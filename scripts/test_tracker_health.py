import copy
import json
import os
import tempfile
import unittest
import contextlib
import io
import runpy
import time
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

import tracker_health as h


def torrent(name="Example", hash="a", **kw):
    return dict(name=name, hash=hash, private=True, progress=1, state="stalledUP",
                tags="IPT, private", ratio=0, seeding_time=0, ratio_limit=-1, seeding_time_limit=-1,
                inactive_seeding_time_limit=-1, **kw)


def tracker(status=4, msg="invalid passkey", url="https://routing.bgp.technology/announce?passkey=secret"):
    return dict(status=status, msg=msg, url=url)


def scan_log(extra="", version="4.13.0", command="tag_tracker_error", phase=True):
    return (f"Version: {version}\n[2026-10-10 10:00:00,000] [INFO] | Starting Run |\n"
            + ("Tagging Torrents with Tracker Errors\n" if phase else "") + extra +
            "\n[2026-10-10 10:00:05,000] [INFO] | Finished Run |\n"
            f"Executed Commands: {command}\n")


class TrackerTests(unittest.TestCase):
    def observe(self, rows, **kw):
        return h.observations([torrent(**kw)], {"a": rows})

    def test_real_torrent_pass_rejection_is_scoped_and_immediate(self):
        groups, healthy, inv, _ = self.observe([tracker(4, "unregistered torrent pass")])
        _, events = h.advance(h.initial_state(), groups, healthy, inv, 1, 100)
        self.assertEqual(len(events), 1)
        self.assertIn("tracker credential rejection", events[0][1])
        self.assertNotIn("account/passkey", events[0][1])

    def test_bare_pass_does_not_mean_account_rejection(self):
        self.assertEqual(h.category("tracker did not pass validation"), "tracker unavailable")
        self.assertEqual(h.category("unregistered torrent"), "torrent registration error")
        self.assertEqual(h.category("invalid passkey"), "account/passkey rejection")

    def test_updating_tracker_is_unknown_not_outage(self):
        groups, _, _, _ = self.observe([tracker(3, "")])
        self.assertIn("IPTorrents: tracker status unknown", groups)

    def test_recovery_does_not_claim_every_mirror_recovered(self):
        groups, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), groups, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        s, _ = h.advance(s, {}, {"a"}, inv, 2, 200)
        _, events = h.advance(s, {}, {"a"}, inv, 3, 300)
        self.assertIn("at least one IPT endpoint", events[0][1])
        self.assertIn("other endpoints may still reject", events[0][1])

    def test_cleaned_up_public_torrent_closes_its_incident(self):
        public = dict(torrent(name="Public"), private=False, tags="issue")
        groups, healthy, inv, _ = h.observations([public], {"a": [tracker(4, "Host not found", "udp://dead.tk:6969")]})
        self.assertIn("public tracker: tracker unavailable", groups)
        s, events = h.advance(h.initial_state(), groups, healthy, inv, 1, 100)
        s, events = h.advance(s, groups, healthy, inv, 2, 200)
        h.acknowledge(s, [e[0] for e in events], 200)
        # qbit_manage removed the torrent after its public seeding rule.
        s, _ = h.advance(s, {}, set(), {}, 3, 300)
        s, events = h.advance(s, {}, set(), {}, 4, 400)
        self.assertEqual([e[0] for e in events], ["recovery:public tracker: tracker unavailable"])
        self.assertIn("cleaned up", events[0][1])

    def test_vanished_private_torrent_does_not_close_its_incident(self):
        groups, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), groups, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        s, _ = h.advance(s, {}, set(), {}, 2, 200)
        s, events = h.advance(s, {}, set(), {}, 3, 300)
        self.assertFalse([e for e in events if e[0].startswith("recovery:")])

    def unknown(self, *hashes):
        return {"IPTorrents: tracker status unknown": {"hashes": list(hashes), "examples": [n.upper() for n in hashes],
                "messages": ["no confirmed working announcement"], "critical": False}}

    def test_torrents_caught_mid_announce_are_not_an_incident(self):
        inv = {"a": "A", "b": "B", "c": "C"}
        s = h.initial_state()
        for scan, mid_announce in enumerate(["a", "b", "c", "a"], 1):
            s, events = h.advance(s, self.unknown(mid_announce), set(inv) - {mid_announce}, inv, scan, scan * 100)
            self.assertEqual(events, [])
        self.assertNotIn("IPTorrents: tracker status unknown", s["groups"])

    def test_torrent_unconfirmed_on_consecutive_runs_still_alerts(self):
        inv = {"a": "A", "b": "B"}
        s = h.initial_state()
        sent = []
        for scan, unconfirmed in enumerate([("a", "b"), ("a",), ("a",)], 1):
            s, events = h.advance(s, self.unknown(*unconfirmed), set(inv) - set(unconfirmed), inv, scan, scan * 100)
            sent += events
        self.assertEqual(len(sent), 1)
        self.assertIn("IPTorrents: tracker status unknown: 1 torrent(s)", sent[0][1])
        self.assertIn("Examples: A", sent[0][1])

    def test_open_unknown_incident_closes_despite_announce_churn(self):
        inv = {"a": "A", "b": "B", "c": "C"}
        s = h.initial_state()
        for scan in (1, 2, 3):
            s, events = h.advance(s, self.unknown("a", "b"), {"c"}, inv, scan, scan * 100)
            h.acknowledge(s, [e[0] for e in events], scan * 100)
        recovered = []
        for scan, mid_announce in enumerate(["c", "b", "a"], 4):
            s, events = h.advance(s, self.unknown(mid_announce), set(inv) - {mid_announce}, inv, scan, scan * 100)
            recovered += [e for e in events if e[0].startswith("recovery:")]
            h.acknowledge(s, [e[0] for e in events], scan * 100)
        self.assertEqual(len(recovered), 1)

    def test_unannounced_reopening_recovers_silently(self):
        inv = {"a": "A", "b": "B"}
        s, hour = h.initial_state(), 3600
        # Alert, then a recovery notice. Brief blips later reopen the closed
        # incident without alerting; their recovery must not post either.
        runs = [(1, "a"), (2, "a"), (3, "a"), (4, ""), (5, "")]
        for start in (20 * hour, 26 * hour):
            runs += [(start, "b"), (start + 900, "b"), (start + 1800, ""), (start + 2700, "")]
        kinds = []
        for scan, (now, unconfirmed) in enumerate(runs, 1):
            s, events = h.advance(s, self.unknown(*unconfirmed), set(inv) - set(unconfirmed), inv, scan, now)
            h.acknowledge(s, [e[0] for e in events], now)
            kinds.append([e[0].split(":")[0] for e in events])
        self.assertEqual(sum(kinds[:5], []), ["group", "recovery"])
        self.assertEqual(sum(kinds[5:], []), [])

    def test_reopened_incident_that_alerts_again_still_recovers_aloud(self):
        inv = {"a": "A"}
        s, hour = h.initial_state(), 3600
        # Alert and recover, then the same outage returns and outlasts the
        # daily reminder window: it alerts again, so its recovery is announced.
        runs = [(1, "a"), (2, "a"), (3, "a"), (4, ""), (5, ""),
                (20 * hour, "a"), (20 * hour + 900, "a"), (20 * hour + 1800, "a"), (25 * hour, "a"),
                (25 * hour + 900, ""), (25 * hour + 1800, "")]
        kinds = []
        for scan, (now, unconfirmed) in enumerate(runs, 1):
            s, events = h.advance(s, self.unknown(*unconfirmed), set(inv) - set(unconfirmed), inv, scan, now)
            h.acknowledge(s, [e[0] for e in events], now)
            kinds.append([e[0].split(":")[0] for e in events])
        self.assertEqual(sum(kinds[5:], []), ["group", "recovery"])

    def test_rejected_stalled_seed_is_immediate(self):
        groups, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), groups, healthy, inv, 1, 100)
        self.assertEqual(len(events), 1)
        self.assertIn("account/passkey", events[0][1])
        self.assertNotIn("secret", events[0][1])

    def test_healthy_without_peers(self):
        groups, healthy, _, errors = self.observe([tracker(2, "")])
        self.assertFalse(groups)
        self.assertEqual(healthy, {"a"})
        self.assertFalse(errors)

    def test_intentional_retirement_is_not_failed_seed_but_unverified_stop_is(self):
        t=torrent();t['state']='stoppedUP'
        self.assertTrue(h.observations([t],{'a':[tracker(2,'')]})[3])
        groups,healthy,inventory,errors=h.observations([t],{'a':[tracker(0,'')]},intentional={'a'})
        self.assertFalse(groups)
        self.assertFalse(healthy)
        self.assertFalse(errors)
        self.assertIn('a',inventory)

    def test_one_working_ipt_mirror_suffices(self):
        self.assertFalse(self.observe([tracker(), tracker(2, "")])[0])

    def test_unrelated_working_tracker_cannot_mask_ipt(self):
        self.assertTrue(self.observe([tracker(), tracker(2, "", "https://unrelated.example/announce")])[0])

    def test_pseudo_trackers_not_success(self):
        self.assertIn("IPTorrents: tracker status unknown", self.observe([tracker(2, "", "** [DHT] **")])[0])

    def test_missing_updating_and_uncontacted_are_unknown(self):
        for rows in [None, [], [tracker(0, "")], [tracker(1, "")]]:
            with self.subTest(rows=rows):
                self.assertIn("IPTorrents: tracker status unknown", self.observe(rows)[0])

    def test_incomplete_torrent_is_monitored(self):
        t = torrent(); t["progress"] = .1
        self.assertTrue(h.observations([t], {"a": [tracker()]})[0])

    def test_temporary_failure_needs_distinct_scans(self):
        g, healthy, inv, _ = self.observe([tracker(4, "timed out")])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        self.assertFalse(events)
        s, events = h.advance(s, g, healthy, inv, 1, 200)
        self.assertFalse(events)
        s, events = h.advance(s, g, healthy, inv, 2, 300)
        self.assertEqual(len(events), 1)

    def test_changes_daily_reminders_and_failed_delivery(self):
        g, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        s, retry = h.advance(s, g, healthy, inv, 1, 101)
        self.assertTrue(retry)  # no acknowledgement means retry
        h.acknowledge(s, [e[0] for e in retry], 101)
        s, events = h.advance(s, g, healthy, inv, 2, 102)
        self.assertFalse(events)
        s, events = h.advance(s, g, healthy, inv, 3, 86502)
        self.assertTrue(events)
        g = copy.deepcopy(g); next(iter(g.values()))["hashes"].append("b")
        h.acknowledge(s, [e[0] for e in events], 86502)
        _, events = h.advance(s, g, healthy, inv, 3, 86503)
        self.assertFalse(events)  # membership changes are included in the daily reminder

    def test_dns_is_debounced_not_authentication(self):
        msg = 'Host not found (non-authoritative), try again later'
        self.assertEqual(h.category(msg), 'tracker unavailable')
        self.assertEqual(h.category('authentication failed'), 'account/passkey rejection')
        self.assertEqual(h.category('account disabled'), 'account/passkey rejection')
        g, healthy, inv, _ = self.observe([tracker(4, msg)])
        _, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        self.assertFalse(events)

    def test_membership_churn_is_one_incident_and_cumulative_history(self):
        s = h.initial_state(); key = 'IPTorrents: tracker credential rejection'
        for scan, names in enumerate([['a','b'], ['b','c'], ['a','b']], 1):
            g = {key:dict(hashes=names, examples=names, messages=['unregistered torrent pass'], critical=True)}
            s, events = h.advance(s, g, set(), dict(a='A',b='B',c='C'), scan, scan*100)
            self.assertEqual(len(events), int(scan == 1))
            h.acknowledge(s, [e[0] for e in events], scan*100)
        self.assertEqual(set(s['groups'][key]['seen_hashes']), {'a','b','c'})
        s, events = h.advance(s, g, set(), s['inventory'], 4, 86500)
        self.assertEqual(len(events), 1)
        h.acknowledge(s, [e[0] for e in events], 86500)
        self.assertEqual(set(s['groups'][key]['notified_hashes']), {'a','b','c'})

    def test_recurrence_survives_restart_without_new_opening_or_recovery_spam(self):
        g, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        s, _ = h.advance(s, {}, {'a'}, inv, 2, 200)
        s, events = h.advance(s, {}, {'a'}, inv, 3, 300)
        h.acknowledge(s, [e[0] for e in events], 300)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'state.json'); h.save_state(path, s); s = h.load_state(path)
        s, events = h.advance(s, g, set(), inv, 4, 400)
        self.assertFalse(events)
        s, _ = h.advance(s, {}, {'a'}, inv, 5, 500)
        s, events = h.advance(s, {}, {'a'}, inv, 6, 600)
        self.assertFalse(events)  # previously delivered recovery is not sent again
        self.assertFalse(s['groups'])
        s, events = h.advance(s, g, set(), inv, 7, 86800)
        self.assertEqual(len(events), 1)  # a new episode after the retention window

    def test_new_noncritical_category_is_aggregated_but_explicit_restriction_escalates(self):
        g, healthy, inv, _ = self.observe([tracker(4,'unregistered torrent pass')])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        outage, _, _, _ = self.observe([tracker(4,'timed out')])
        s, events = h.advance(s, outage, set(), inv, 2, 200)
        s, events = h.advance(s, outage, set(), inv, 3, 300)
        self.assertFalse(events)
        banned, _, _, _ = self.observe([tracker(4,'account disabled')])
        s, events = h.advance(s, banned, set(), inv, 4, 400)
        self.assertEqual(len(events), 1)
        self.assertIn('account/passkey rejection', events[0][1])

    def test_new_members_cannot_mask_disappearance_of_previous_members(self):
        key = 'IPTorrents: tracker credential rejection'
        g = {key:dict(hashes=['a','b'],examples=['A','B'],messages=['unregistered torrent pass'],critical=True)}
        s, events = h.advance(h.initial_state(), g, set(), dict(a='A',b='B'), 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        g[key]['hashes'] = ['b']
        s, _ = h.advance(s, g, set(), dict(b='B'), 2, 200)
        s, _ = h.advance(s, {}, {'b'}, dict(b='B'), 3, 300)
        _, events = h.advance(s, {}, {'b'}, dict(b='B'), 4, 400)
        self.assertFalse(any(k.startswith('recovery:') for k,_ in events))

    def test_account_disabled_escalates_after_passkey_alert(self):
        g, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        g, _, _, _ = self.observe([tracker(4,'account disabled')])
        s, events = h.advance(s, g, set(), inv, 2, 200)
        self.assertEqual(len(events), 1)
        s, events = h.advance(s, g, set(), inv, 2, 201)
        self.assertEqual(len(events), 1)  # failed escalation delivery must retry
        h.acknowledge(s, [e[0] for e in events], 200)
        _, events = h.advance(s, g, set(), inv, 3, 300)
        self.assertFalse(events)

    def test_verified_retirement_is_resolution_not_working_announcement(self):
        g, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        s, _ = h.advance(s, {}, set(), inv, 2, 200, retired={'a'})
        _, events = h.advance(s, {}, set(), inv, 3, 300, retired={'a'})
        self.assertIn('verified intentional', events[0][1])

    def test_dns_incident_migration_preserves_successful_delivery(self):
        g, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        old = 'IPTorrents: account/passkey rejection'
        s['groups'][old]['messages'] = ['Host not found (non-authoritative), try again later']
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d,'state.json'); h.save_state(p,s); loaded=h.load_state(p)
        self.assertNotIn(old, loaded['groups'])
        self.assertEqual(loaded['groups']['IPTorrents: tracker unavailable']['sent'],100)

    def test_recovery_needs_two_working_scans_and_delivery(self):
        g, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        s, events = h.advance(s, {}, {"a"}, inv, 2, 200)
        self.assertFalse(events)
        s, events = h.advance(s, {}, {"a"}, inv, 2, 210)
        self.assertFalse(events)
        s, events = h.advance(s, {}, {"a"}, inv, 3, 300)
        self.assertTrue(events[0][0].startswith("recovery:"))
        self.assertTrue(s["groups"])
        h.acknowledge(s, [e[0] for e in events], 300)
        self.assertFalse(s["groups"])

    def test_disappearance_is_not_recovery(self):
        g, healthy, inv, _ = self.observe([tracker()])
        s, events = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        s, events = h.advance(s, {}, set(), {}, 2, 200)
        self.assertTrue(s["groups"])
        self.assertTrue(any(k.startswith("missing:") for k, _ in events))

    def test_failed_scan_does_not_replace_inventory(self):
        s = h.initial_state(); s["inventory"] = {"a": "Example"}
        new, events = h.advance(s, {}, set(), {}, None, 100, valid=False)
        self.assertEqual(s, new)
        self.assertFalse(events)

    def test_three_examples_max(self):
        ts = [torrent(name=str(n), hash=str(n)) for n in range(10)]
        g, _, _, _ = h.observations(ts, {str(n): [tracker()] for n in range(10)})
        self.assertEqual(len(next(iter(g.values()))["examples"]), 3)

    def test_private_limits_and_stopped_states(self):
        t = torrent(); t["ratio_limit"] = 1
        self.assertTrue(h.observations([t], {"a": [tracker(2, "")]})[3])

    def test_unclassified_torrent_gets_until_qbit_manage_has_run_twice(self):
        now = 1_800_000_000
        fresh = torrent(completion_on=now - 1800); fresh["tags"] = "IPT"
        self.assertFalse(h.observations([fresh], {"a": [tracker(2, "")]}, now=now)[3])
        missed = torrent(completion_on=now - 3 * 3600); missed["tags"] = "IPT"
        self.assertTrue(h.observations([missed], {"a": [tracker(2, "")]}, now=now)[3])

    def test_inherited_limits_require_unlimited_globals(self):
        t = torrent(); t['inactive_seeding_time_limit'] = -2
        self.assertFalse(h.observations([t], {'a':[tracker()]}, {'max_inactive_seeding_time':-1})[3])
        self.assertTrue(h.observations([t], {'a':[tracker()]}, {'max_inactive_seeding_time':60})[3])
        t = torrent(); t["state"] = "queuedUP"
        self.assertTrue(h.observations([t], {"a": [tracker(2, "")]})[3])

    def test_redaction(self):
        s = h.sanitize("token=oops https://site/abc?passkey=xyz password=bad " + "a" * 32)
        for secret in ["oops", "xyz", "bad", "a" * 32]: self.assertNotIn(secret, s)

    def test_completed_scan_proof(self):
        self.assertGreater(h.last_scan(scan_log()), 0)
        for log in [scan_log("[ERROR] failed"), scan_log(version="5.0"),
                    scan_log(command="share_limits"), scan_log(phase=False),
                    scan_log("DRY RUN"), scan_log("[DRYRUN] simulated"), "Finished Run"]:
            with self.subTest(log=log):
                with self.assertRaises(ValueError): h.last_scan(log)

    def test_newest_version_banner_is_not_the_running_version(self):
        def banner(running, newest):
            return ("[2026-10-10 09:59:59,000] [qbit_manage.py:713] [INFO]     |     Version: %s (Docker: Python 3.14.7) (Git: master)   |\n"
                    "[2026-10-10 09:59:59,050] [qbit_manage.py:721] [INFO]     |     Newest Version: %s   |\n" % (running, newest))
        body = scan_log().split("\n", 1)[1]
        self.assertGreater(h.last_scan(banner("4.13.0", "4.14.0") + body), 0)
        with self.assertRaises(ValueError):
            h.last_scan(banner("4.14.0", "4.13.0") + body)

    def test_state_permissions_persistence_and_failed_save(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            with self.assertRaises(FileNotFoundError): h.load_state(path)
            s = h.initial_state(); h.save_state(path, s)
            self.assertEqual(h.load_state(path), s)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with patch("tracker_health.os.replace", side_effect=OSError):
                with self.assertRaises(OSError): h.save_state(path, {**s, "pipeline_sent": 42})
            self.assertEqual(h.load_state(path), s)
            with open(path, "w") as f: f.write("broken")
            with self.assertRaises(ValueError): h.load_state(path)

    def test_existing_ambiguous_incident_is_relabelled_without_losing_delivery_history(self):
        old = "IPTorrents: account/passkey rejection"
        new = "IPTorrents: tracker credential rejection"
        s = h.initial_state()
        g, healthy, inv, _ = self.observe([tracker(4, "unregistered torrent pass")])
        s, events = h.advance(s, g, healthy, inv, 1, 100)
        h.acknowledge(s, [e[0] for e in events], 100)
        s['groups'][old] = s['groups'].pop(new)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'state.json')
            h.save_state(path, s)
            before = Path(path).read_bytes()
            loaded = h.load_state(path)
            self.assertNotIn(old, loaded['groups'])
            self.assertEqual(loaded['groups'][new]['sent'], 100)
            self.assertEqual(loaded['groups'][new]['first_seen'], 100)
            self.assertEqual(loaded['groups'][new]['notified_hashes'], ['a'])
            self.assertEqual(Path(path).read_bytes(), before)

    def test_explicit_passkey_incident_is_not_relabelled(self):
        g, healthy, inv, _ = self.observe([tracker()])
        s, _ = h.advance(h.initial_state(), g, healthy, inv, 1, 100)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'state.json'); h.save_state(path, s)
            self.assertEqual(h.load_state(path), s)

    def test_config_drift(self):
        c = {"commands": dict(tag_tracker_error=True, dry_run=False, skip_cleanup=True,
            rem_unregistered=False, tag_update=True, share_limits=True),
            "settings": dict(private_tag="private", tracker_error_tag="issue"),
            "share_limits": {"private_hold": dict(priority=0, include_all_tags=["private"],
                max_ratio=-1, max_seeding_time=-1, cleanup=False,resume_torrent_after_change=False),
                "public": dict(priority=2, cleanup=True, exclude_any_tags=["private"],resume_torrent_after_change=False)}}
        self.assertFalse(h.config_problems(c))
        for field in ["tag_tracker_error", "skip_cleanup", "share_limits"]:
            bad = copy.deepcopy(c); bad["commands"][field] = False
            self.assertTrue(h.config_problems(bad))
        bad = copy.deepcopy(c); bad["share_limits"]["private_hold"]["cleanup"] = True
        self.assertTrue(h.config_problems(bad))
        bad = copy.deepcopy(c); bad["share_limits"]["public"]["exclude_any_tags"] = []
        self.assertTrue(h.config_problems(bad))

    def test_pipeline_ages_do_not_spam(self):
        self.assertEqual(h.pipeline_signature(["movie stuck 92h"]), h.pipeline_signature(["movie stuck 93h"]))

    def test_canary_report_only_and_delivery_retry(self):
        # Exercise the actual executable, not only policy helpers, with fake APIs.
        import urllib.request
        config = {"commands": dict(tag_tracker_error=True, skip_cleanup=True, tag_update=True, share_limits=True),
            "settings": dict(private_tag="private", tracker_error_tag="issue"),
            "share_limits": {"private_hold": dict(priority=0, include_all_tags=["private"],
                max_ratio=-1, max_seeding_time=-1, cleanup=False,resume_torrent_after_change=False)}}
        class Response(io.BytesIO):
            status = 204
        def response(obj): return Response(json.dumps(obj).encode())
        class Qbit:
            def open(self, request, **kw):
                url = request if isinstance(request, str) else request.full_url
                if url.endswith('/auth/login'): return Response(b'Ok.')
                if '/app/preferences' in url: return response({'max_ratio_act': 0, 'listen_port': 49070})
                if '/torrents/info' in url: return response([torrent()])
                if '/torrents/trackers' in url: return response([tracker()])
                raise AssertionError(url)
        calls = []
        state_path=None
        stopped_live=False
        asynchronous=False
        posts=[]
        fixture=torrent()
        class RetirementQbit(Qbit):
            def open(self,request,**kw):
                nonlocal stopped_live
                url=request if isinstance(request,str) else request.full_url
                if '/torrents/stop' in url:
                    self.assert_persisted_intent()
                    posts.append(request.data)
                    stopped_live=True
                    result=Response(b'');result.status=200
                    return result
                if '/torrents/info' in url:
                    current=dict(fixture)
                    if stopped_live: current['state']='stoppingUP' if asynchronous else 'stoppedUP'
                    return response([current])
                return super().open(request,**kw)
            def assert_persisted_intent(self):
                saved=h.load_state(str(state_path))
                assert saved['retirement']['torrents']['a']['phase']=='pending'
        def urlopen(request, **kw):
            url = request if isinstance(request, str) else request.full_url
            calls.append(url)
            if 'discord.com' in url: raise OSError('simulated delivery failure')
            if '/api/push/' in url: return Response(b'{}')
            if url.endswith('/health'): return response([])
            if '/history?' in url: return response({'records':[{'date':datetime.now().isoformat()}]})
            if '/queue?' in url: return response({'records':[]})
            if '/request?' in url: return response({'results':[]})
            if 'hub.docker.com' in url: return response({'digest':h.QBM_DIGEST,'last_updated':'2026-10-01T00:00:00Z'})
            raise AssertionError(url)
        def command(args, **kw):
            if args[0] == 'df': return b'Avail\n1000000000000\n'
            if '/tmp/gluetun/forwarded_port' in args: return b'49070'
            if tuple(args[0:3]) == ('docker','image','inspect') and '{{.Created}}' in args:
                return datetime.now(timezone.utc).isoformat().encode()
            if tuple(args[0:3]) == ('docker','image','inspect'):
                return json.dumps(['image@'+h.QBM_DIGEST]).encode()
            if tuple(args[0:3]) == ('docker','inspect','plex'): return b'lscr.io/linuxserver/plex:latest sha256:plex'
            if tuple(args[0:3]) == ('docker','inspect','jellyfin'): return b'jellyfin/jellyfin:latest sha256:jellyfin'
            if tuple(args[0:2]) == ('docker','top'): return b'PID\n'
            if args[0] == 'systemctl':
                return ('Result=success\nExecMainExitTimestamp=@%d\n' % time.time()).encode()
            if tuple(args[0:3]) == ('docker','inspect','qbit_manage'): return b'sha256:fixture'
            if 'sed' in args: return b'fixture-key'
            if '/app/config/settings.json' in args: return b'{"main":{"apiKey":"fixture-key"}}'
            if 'node' in args: return b'https://discord.com/api/webhooks/fixture'
            if 'python' in args:
                log = scan_log().replace('2026-10-10 10:00:05', datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
                return json.dumps({'config':config,'log':log,'tz':'UTC'}).encode()
            raise AssertionError(args)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            env = root/'env'; env.write_text('QBITTORRENT_USER=test\nQBITTORRENT_PASS=test\n')
            state = root/'state'; h.save_state(str(state), h.initial_state())
            summary = root/'summary'; summary.touch()
            environ = {'CANARY_ENV_FILE':str(env),'CANARY_TRACKER_STATE':str(state),
                'CANARY_STOPPED_STATE':str(root/'stopped'),'CANARY_SUMMARY_STATE':str(summary)}
            before = state.read_bytes()
            with patch.dict(os.environ,environ), patch('subprocess.check_output',side_effect=command), \
                 patch('urllib.request.build_opener',return_value=Qbit()), patch('urllib.request.urlopen',side_effect=urlopen), \
                 patch('sys.argv',['pipeline-canary.py','--report']), contextlib.redirect_stdout(io.StringIO()):
                runpy.run_path(str(Path(__file__).with_name('pipeline-canary.py')))
            self.assertEqual(state.read_bytes(), before)
            self.assertFalse(any('discord.com' in c or '/api/push/' in c for c in calls))
            self.assertFalse((root/'stopped').exists())
            output = io.StringIO()
            with patch.dict(os.environ,environ), patch('subprocess.check_output',side_effect=command), \
                 patch('urllib.request.build_opener',return_value=Qbit()), patch('urllib.request.urlopen',side_effect=urlopen), \
                 patch('sys.argv',['pipeline-canary.py','--apply']), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit): runpy.run_path(str(Path(__file__).with_name('pipeline-canary.py')))
            saved = h.load_state(str(state))
            self.assertTrue(saved['groups'], output.getvalue())
            self.assertEqual(next(iter(saved['groups'].values()))['sent'], 0)
            self.assertTrue(any('status=down' in c for c in calls))
            # Actual executable stop path: public seeds are finite even while
            # library-linked; report must not POST, apply must persist first.
            from torrent_retirement import initial_retirement
            current=h.initial_state();current['retirement']=initial_retirement()
            current['retirement']['enabled']=True
            h.save_state(str(state),current)
            state_path=state
            fixture=torrent();fixture.update(private=False,tags='public',seeding_time=3*86400,
                added_on=10,completion_on=20)
            with patch.dict(os.environ,environ), patch('subprocess.check_output',side_effect=command), \
                 patch('urllib.request.build_opener',return_value=RetirementQbit()), patch('urllib.request.urlopen',side_effect=urlopen), \
                 patch('sys.argv',['pipeline-canary.py','--report']), contextlib.redirect_stdout(io.StringIO()):
                runpy.run_path(str(Path(__file__).with_name('pipeline-canary.py')))
            self.assertFalse(posts)
            with patch.dict(os.environ,environ), patch('subprocess.check_output',side_effect=command), \
                 patch('urllib.request.build_opener',return_value=RetirementQbit()), patch('urllib.request.urlopen',side_effect=urlopen), \
                 patch('sys.argv',['pipeline-canary.py','--apply']), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit): runpy.run_path(str(Path(__file__).with_name('pipeline-canary.py')))
            self.assertEqual(posts,[b'hashes=a'])
            saved=h.load_state(str(state))
            self.assertEqual(saved['retirement']['torrents']['a']['phase'],'retired')
            self.assertFalse(saved['retirement']['torrents']['a'].get('notified'))

            # Accepted asynchronous stop must NOT turn the real heartbeat down.
            # A stuck transition still fails health after the bounded grace.
            asynchronous=True; stopped_live=False; calls.clear()
            h.save_state(str(state),current)
            def successful_delivery(request,**kw):
                url=request if isinstance(request,str) else request.full_url
                if 'discord.com' in url:
                    calls.append(url)
                    return Response(b'')
                return urlopen(request,**kw)
            def apply_async():
                with patch.dict(os.environ,environ), patch('subprocess.check_output',side_effect=command), \
                     patch('urllib.request.build_opener',return_value=RetirementQbit()), \
                     patch('urllib.request.urlopen',side_effect=successful_delivery), \
                     patch('sys.argv',['pipeline-canary.py','--apply']), contextlib.redirect_stdout(io.StringIO()):
                    runpy.run_path(str(Path(__file__).with_name('pipeline-canary.py')))
            apply_async()
            self.assertTrue(any('status=up' in c for c in calls))
            self.assertFalse(any('status=down' in c for c in calls))
            saved=h.load_state(str(state))
            self.assertEqual(saved['retirement']['torrents']['a']['phase'],'pending')
            saved['retirement']['torrents']['a']['intent_at']-=1801
            h.save_state(str(state),saved); calls.clear()
            apply_async()
            self.assertTrue(any('status=down' in c for c in calls))
            self.assertTrue(any('authorized%20stop%20unconfirmed' in c for c in calls))



class PortForwardTest(unittest.TestCase):
    def test_matching_port_is_healthy(self):
        self.assertIsNone(h.port_forward_problem("49070\n", 49070))
        self.assertIsNone(h.port_forward_problem("49070,49071", 49070))

    def test_missing_forward_is_reported(self):
        for empty in ("", "\n", None):
            self.assertIn("no port", h.port_forward_problem(empty, 49070))

    def test_drifted_listen_port_is_reported(self):
        problem = h.port_forward_problem("28062", 29587)
        self.assertIn("listens on port 29587", problem)
        self.assertIn("forwards 28062", problem)


if __name__ == "__main__": unittest.main()
