"""Tracker monitoring policy; no network or filesystem writes at import time."""
import copy
import hashlib
import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

QBM_VERSION = "4.13.0"
QBM_DIGEST = "sha256:ea04167f627e506b3691304f4c639a52c05584cc9aea4af7ec87d4ed1299e7f5"
IPT_DOMAINS = ("stackoverflow.tech", "empirehost.me", "bgp.technology", "iptorrents.com")
STALE_SECONDS = 90 * 60
CLASSIFY_GRACE_SECONDS = 2 * 60 * 60  # qbit_manage runs hourly (QBT_SCHEDULE=60)


def sanitize(value, limit=180):
    text = re.sub(r"(?:https?|udp|wss?)://\S+", "[URL omitted]", str(value))
    text = re.sub(r"(?i)\b(api.?key|passkey|password|token|torrent_pass)\s*[=:]\s*[^\s,;&]+",
                  r"\1=[redacted]", text)
    text = re.sub(r"\b[0-9a-fA-F]{24,}\b", "[redacted]", text)
    return " ".join(text.split())[:limit]


def last_scan(log, tz="America/New_York"):
    """Require a complete, non-dry-run detection pass with no run errors.

    An arbitrary new logfile write or a Finished Run banner alone is insufficient.
    Parse the last bounded run, including its Executed Commands footer.
    """
    starts = list(re.finditer(r"^.*\|\s+Starting Run\s+\|", log, re.M))
    good = None
    for n, match in enumerate(starts):
        start = match.start()
        block = log[start:starts[n + 1].start() if n + 1 < len(starts) else len(log)]
        if "Finished Run" not in block:
            continue
        # Version is emitted immediately before Starting Run.
        prefix = log[max(0, start - 5000):start]
        # Anchor to the banner so "Newest Version: x" (upstream's latest) is not read as ours.
        versions = re.findall(r"(?:^|\|)\s*Version: ([\d.]+)", prefix, re.M)
        if not versions or versions[-1] != QBM_VERSION:
            continue
        if re.search(r"\[(?:ERROR|CRITICAL)\]|Traceback|Dry.Run:\s*True|DRY[ _-]?RUN", block, re.I):
            continue
        if "Tagging Torrents with Tracker Errors" not in block:
            continue
        commands = re.search(r"Executed Commands:([^\n]+)", block)
        if not commands or "tag_tracker_error" not in commands[1]:
            continue
        end = re.search(r"\[([\d-]+ [\d:]+),\d+\].*\|\s+Finished Run", block)
        if not end:
            continue
        good = datetime.strptime(end[1], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=ZoneInfo(tz)).timestamp()
    if good is None:
        raise ValueError("no supported successful tracker-detection run")
    return good


def config_problems(config):
    def true(x): return str(x).lower() == "true"
    commands = config.get("commands", {})
    issues = []
    if not true(commands.get("tag_tracker_error")) or true(commands.get("dry_run")):
        issues.append("qbit_manage tracker detection is disabled or dry-run")
    if true(commands.get("rem_unregistered")) or true(commands.get("rem_orphaned")):
        issues.append("qbit_manage destructive removal is enabled")
    if not true(commands.get("skip_cleanup")):
        issues.append("recycle-bin preservation is disabled")
    settings = config.get("settings", {})
    if settings.get("private_tag") != "private" or settings.get("tracker_error_tag") != "issue":
        issues.append("qbit_manage monitoring tags have drifted")
    if not true(commands.get("tag_update")) or not true(commands.get("share_limits")):
        issues.append("private classification/share-limit application is disabled")
    groups = config.get("share_limits", {})
    hold = groups.get("private_hold", {})
    if (str(hold.get("priority")) != "0" or hold.get("include_all_tags") != ["private"]
            or str(hold.get("max_ratio")) != "-1" or str(hold.get("max_seeding_time")) != "-1"
            or true(hold.get("cleanup", True))):
        issues.append("private cleanup hold is missing or unsafe")
    for name, group in groups.items():
        if str(group.get('resume_torrent_after_change')).lower() != 'false':
            issues.append('share-limit group can resume intentionally retired torrents')
        if name != "private_hold" and true(group.get("cleanup")):
            if "private" not in group.get("exclude_any_tags", []):
                issues.append("cleanup group does not exclude private torrents")
        if name != "private_hold" and int(group.get("priority", 999)) <= 0:
            issues.append("another share-limit group can override private hold")
    return issues


def is_ipt_url(url):
    from urllib.parse import urlsplit
    host = (urlsplit(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in IPT_DOMAINS)


def private_torrent(t):
    return bool(t.get("private")) or "private" in tags(t) or "IPT" in tags(t)


def tags(t):
    return {s.strip() for s in t.get("tags", "").split(",") if s.strip()}


def category(message):
    m = message.lower()
    # A rejected torrent_pass is real authentication failure at this endpoint,
    # but does not establish an account-wide ban or explain its cause.
    if re.search(r"\bunregistered[ _]+torrent[ _]+pass\b", m):
        return "tracker credential rejection"
    if re.search(r"\b(?:passkey|unauthori[sz]ed|forbidden|banned|disabled|jailed|authentication|authorization|auth)\b", m):
        return "account/passkey rejection"
    if re.search(r"unregistered|not registered|deleted|not found.*torrent", m):
        return "torrent registration error"
    return "tracker unavailable"


def observations(torrents, trackers, preferences=None, intentional=None, now=None):
    """Use qBM tags, with IPT-only status checks to cover its any-tracker rule."""
    groups, healthy, inventory, problems = {}, set(), {}, []
    preferences = preferences or {}
    intentional = intentional or set()
    now = time.time() if now is None else now
    def unlimited(t, field, global_field):
        value = t.get(field, -1)
        return value == -1 or value == -2 and preferences.get(global_field) == -1
    for t in torrents:
        h = t["hash"]
        private = private_torrent(t)
        if private:
            inventory[h] = sanitize(t["name"])
            # qbit_manage classifies new torrents on its hourly run; flag only what it missed twice.
            if t.get("progress") == 1 and now - t.get("completion_on", 0) >= CLASSIFY_GRACE_SECONDS and ("private" not in tags(t)
                    or not unlimited(t, "ratio_limit", "max_ratio")
                    or not unlimited(t, "seeding_time_limit", "max_seeding_time")
                    or not unlimited(t, "inactive_seeding_time_limit", "max_inactive_seeding_time")):
                problems.append("completed private torrent lacks classification/unlimited limits: " + sanitize(t["name"]))
        if h in intentional and t.get('state') in ('stoppedUP','pausedUP'):
            # Persisted stop intent has positive obligation evidence. An idle
            # tracker after authorized retirement is expected, not an outage.
            continue
        rows = trackers.get(h)
        real = [r for r in rows or [] if re.match(r"^(?:https?|udp|wss?)://", r.get("url", ""))]
        ipt = [r for r in real if is_ipt_url(r["url"])]
        expected_ipt = "IPT" in tags(t) or bool(ipt)
        if not private and "issue" not in tags(t):
            continue
        relevant = ipt if expected_ipt else real
        tracker = "IPTorrents" if expected_ipt else "other private tracker" if private else "public tracker"
        if relevant and any(r.get("status") == 2 for r in relevant):
            healthy.add(h)
            if private and t.get("state") in ("queuedUP", "stoppedUP", "pausedUP", "error", "missingFiles"):
                problems.append("private torrent cannot seed in state " + sanitize(t["state"]) + ": " + sanitize(t["name"]))
            continue
        # qBittorrent status 3 is updating, not a completed failure response.
        failures = [r for r in relevant if r.get("status") == 4]
        if failures:
            cats = {category(str(r.get("msg", ""))) for r in failures}
            cat = "account/passkey rejection" if "account/passkey rejection" in cats else sorted(cats)[0]
            messages = sorted({sanitize(r.get("msg") or "tracker returned an error") for r in failures})
        else:
            cat, messages = "tracker status unknown", ["no confirmed working announcement"]
        k = tracker + ": " + cat
        g = groups.setdefault(k, {"hashes": [], "examples": [], "messages": [],
            "critical": cat in ("account/passkey rejection", "tracker credential rejection")})
        g["hashes"].append(h)
        if len(g["examples"]) < 3:
            g["examples"].append(sanitize(t["name"]))
        g["messages"] = sorted(set(g["messages"] + messages))[:3]
    # Widespread protection drift is one incident, not hundreds of Discord lines.
    grouped_problems = {}
    for problem in sorted(set(problems)):
        reason, _, example = problem.partition(": ")
        grouped_problems.setdefault(reason, []).append(example)
    summaries = [f"{reason}: {len(examples)} torrent(s). Examples: " + "; ".join(examples[:3])
                 for reason, examples in grouped_problems.items()]
    return groups, healthy, inventory, summaries


def initial_state():
    return {"version": 1, "groups": {}, "inventory": {}, "incidents": {},
            "tracker_notices": {}, "recently_closed": {}, "pipeline_sent": 0, "pipeline_signature": ""}


def load_state(path):
    with open(path) as f:
        s = json.load(f)
    if s.get("version") != 1 or not all(isinstance(s.get(k), dict) for k in ("groups", "inventory", "incidents")):
        raise ValueError("unsupported monitoring state")
    # Correct the old broad 'pass' classification in memory. Report mode must
    # not write state; normal locked apply persists this alongside observations.
    old_key = "IPTorrents: account/passkey rejection"
    new_key = "IPTorrents: tracker credential rejection"
    old = s['groups'].get(old_key)
    messages = {m.lower() for m in (old or {}).get('messages', [])}
    if ('unregistered torrent pass' in messages and
            messages <= {'unregistered torrent pass', 'tracker returned an error'}):
        old = s['groups'].pop(old_key)
        current = s['groups'].get(new_key)
        if current is None:
            s['groups'][new_key] = old
        else:
            current['first_seen'] = min(current['first_seen'], old['first_seen'])
            current['sent'] = max(current['sent'], old['sent'])
            current['notified_hashes'] = sorted(set(current['notified_hashes']) | set(old['notified_hashes']))
            current['hashes'] = sorted(set(current['hashes']) | set(old['hashes']))
    # Reclassify old false auth incidents (e.g. non-authoritative DNS), without
    # treating the correction as a new incident or losing delivered history.
    for key, group in list(s['groups'].items()):
        if not key.endswith(': account/passkey rejection'):
            continue
        cats = {category(m) for m in group.get('messages', []) if m != 'tracker returned an error'}
        if len(cats) == 1 and 'account/passkey rejection' not in cats:
            target = key.rsplit(': ', 1)[0] + ': ' + cats.pop()
            if target not in s['groups']:
                s['groups'][target] = s['groups'].pop(key)
                s['groups'][target]['critical'] = target.endswith('tracker credential rejection')
    for field in ('tracker_notices', 'recently_closed'):
        if not isinstance(s.setdefault(field, {}), dict):
            raise ValueError('unsupported notification history')
    return s


def save_state(path, state):
    fd, name = tempfile.mkstemp(prefix=".tracker-health-", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)


def explicit_restriction(messages):
    return any(re.search(r'\b(?:banned|disabled|jailed)\b', m, re.I) for m in messages)


def advance(previous, groups, healthy, inventory, scan, now, valid=True, retired=None):
    """Return candidate state + pending events. acknowledge only after delivery.

    Distinct scan identities debounce failures/recovery; failed observations do
    not clear incidents or overwrite inventory. Events survive failed sends.
    """
    s = copy.deepcopy(previous)
    events = []
    if not valid:
        return s, events
    retired = set(retired or ())
    # qBittorrent marks a tracker "updating" for the length of every announce,
    # so any snapshot catches a few torrents mid-announce. A torrent is
    # unconfirmed only if the previous run also found it unconfirmed.
    last = s.get('unconfirmed', {})
    s['unconfirmed'] = {k: sorted(o['hashes']) for k, o in groups.items() if k.endswith(': tracker status unknown')}
    groups = dict(groups)
    for key, hashes in s['unconfirmed'].items():
        kept = sorted(set(hashes) & set(last.get(key, ())))
        if kept:
            names = [inventory[h] for h in kept if h in inventory][:3]
            groups[key] = {**groups[key], 'hashes': kept, 'examples': names or groups[key]['examples']}
        else:
            del groups[key]
    notices = s.setdefault('tracker_notices', {})
    closed = s.setdefault('recently_closed', {})
    legacy_trackers = {k.rsplit(': ', 1)[0] for k in s['groups'] if k.rsplit(': ', 1)[0] not in notices}
    for key, g in list(closed.items()):
        if now >= g['expires_at']:
            del closed[key]
    # Older state has no tracker-level ledger. Seed it from successful delivery
    # timestamps only; merely observing an incident never advances delivery.
    for key, g in list(s['groups'].items()) + list(closed.items()):
        tracker = key.rsplit(': ', 1)[0]
        notice = notices.setdefault(tracker, {'sent': 0, 'account_sent': 0, 'recovery_sent': 0})
        notice['sent'] = max(notice['sent'], g.get('sent', 0))
        if key.endswith(': account/passkey rejection'):
            notice['account_sent'] = max(notice['account_sent'], g.get('sent', 0))
            if explicit_restriction(g.get('messages', [])):
                # Seed only genuinely legacy ledgers, not a newly observed
                # restriction whose group still carries an older alert time.
                if tracker in legacy_trackers and 'restriction_sent' not in notice:
                    notice['restriction_sent'] = g.get('sent', 0)
    for key, obs in groups.items():
        if key not in s['groups'] and key in closed:
            restored = closed.pop(key)
            # Keep the delivery history, but a recovery notice must answer an
            # alert sent since this reopening, not one from the closed episode.
            restored.update(count=0, last_scan=None, recovery_count=0, reopened_at=now)
            s['groups'][key] = restored
        g = s["groups"].setdefault(key, {"first_seen": now, "count": 0, "last_scan": None,
            "sent": 0, "notified_hashes": [], "recovery_count": 0})
        if scan != g["last_scan"]:
            g["count"] += 1
            g["last_scan"] = scan
        seen = set(g.get('seen_hashes', g.get('hashes', []))) | set(obs['hashes']) | set(g.get('notified_hashes', []))
        g.update(obs)
        g['seen_hashes'] = sorted(seen)
        g["recovery_count"] = 0
    planned = set()
    # At most one opening/reminder per tracker; explicit account restriction
    # may escalate immediately once per 24h, independently of membership churn.
    for key in sorted(groups, key=lambda k: (not k.endswith(': account/passkey rejection'), k)):
        obs, g = groups[key], s['groups'][key]
        tracker = key.rsplit(': ', 1)[0]
        notice = notices.setdefault(tracker, {'sent': 0, 'account_sent': 0, 'recovery_sent': 0})
        eligible = obs["critical"] or g["count"] >= 2
        escalation = key.endswith(': account/passkey rejection') and (
            not notice['account_sent'] or now - notice['account_sent'] >= 86400)
        restriction = explicit_restriction(obs['messages']) and key.endswith(': account/passkey rejection')
        escalation = escalation or restriction and (
            not notice.get('restriction_sent') or now - notice['restriction_sent'] >= 86400)
        if eligible and tracker not in planned and (not notice['sent'] or escalation or now - notice['sent'] >= 86400):
            planned.add(tracker)
            related = [o for k, o in groups.items() if k.rsplit(': ', 1)[0] == tracker]
            affected = set().union(*(set(o['hashes']) for o in related))
            first = datetime.fromtimestamp(g["first_seen"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            body = (f"{key}: {len(affected)} torrent(s) affected across current tracker issues; first seen {first}. "
                    + "; ".join(obs["messages"]) + ". Examples: " + "; ".join(obs["examples"]))
            body += ". Membership changes are grouped; unresolved issues remind daily."
            if key.endswith("tracker credential rejection"):
                body += ". Affected announcements were rejected; this alone does not establish an account-wide restriction."
            events.append(("group:" + key, body))
    current = {}
    for k, o in groups.items():
        current.setdefault(k.rsplit(': ', 1)[0], set()).update(o['hashes'])
    for key, g in list(s["groups"].items()):
        if key in groups:
            continue
        # A torrent recovers once it is in no current issue group of its tracker.
        # Public torrents may also have been cleaned up (qbit_manage's rule);
        # private ones must still exist.
        seen = set(g.get('seen_hashes', g['hashes']))
        tracker = key.rsplit(': ', 1)[0]
        if not seen & current.get(tracker, set()) and (
                tracker == 'public tracker' or seen <= healthy | retired | set(inventory)):
            if scan != g["last_scan"]:
                g["recovery_count"] += 1
                g["last_scan"] = scan
        else:
            g["recovery_count"] = 0
            tracker = key.rsplit(': ', 1)[0]
            notice = notices[tracker]
            if g["sent"] and tracker not in planned and now - notice['sent'] >= 86400:
                planned.add(tracker)
                events.append(("group:" + key, key + ": unresolved; affected torrents are absent or still lack verified working announcements."))
    for tracker in sorted({k.rsplit(': ', 1)[0] for k in s['groups']}):
        related = [(k, g) for k, g in s['groups'].items() if k.rsplit(': ', 1)[0] == tracker]
        if related and all(g['recovery_count'] >= 2 for _, g in related):
            notice = notices[tracker]
            if any(g['sent'] and g['sent'] >= g.get('reopened_at', 0) for _, g in related) and (not notice['recovery_sent'] or now - notice['recovery_sent'] >= 86400):
                key = related[0][0]
                working = ("at least one IPT endpoint is working for each affected torrent; other endpoints may still reject announcements"
                           if tracker == 'IPTorrents' else "affected torrents are announcing again or were cleaned up"
                           if tracker == 'public tracker' else "at least one tracker endpoint is working for each affected torrent")
                if any(set(g.get('seen_hashes', g['hashes'])) & retired for _, g in related):
                    working = 'affected torrents have a working tracker endpoint or a verified intentional seeding-policy stop; intentionally stopped torrents are not claimed to be announcing'
                events.append(('recovery:' + key, tracker + ': ' + working + '. Working announcements do not prove credited seed time or H&R clearance; private cleanup stays held.'))
            else:
                for key, g in related:
                    closed[key] = {**g, 'expires_at': now + 86400}
                    del s['groups'][key]
    for h in previous["inventory"].keys() - inventory.keys():
        s["incidents"].setdefault(h, {"name": previous["inventory"][h], "sent": 0})
    s["inventory"] = inventory
    missing = [(h, i) for h, i in s["incidents"].items()
               if not i["sent"] or now - i["sent"] >= 86400]
    if missing:
        events.append(("missing:" + ",".join(h for h, _ in missing),
            f"{len(missing)} private torrent(s) disappeared; investigate removal. Examples: "
            + "; ".join(i["name"] for _, i in missing[:3])))
    return s, events


def acknowledge(state, event_ids, now):
    for event in event_ids:
        kind, key = event.split(":", 1)
        if kind == "group":
            tracker = key.rsplit(': ', 1)[0]
            notice = state.setdefault('tracker_notices', {}).setdefault(tracker, {'sent': 0, 'account_sent': 0, 'recovery_sent': 0})
            notice['sent'] = now
            if key.endswith(': account/passkey rejection'):
                notice['account_sent'] = now
                if explicit_restriction(state['groups'][key].get('messages', [])):
                    notice['restriction_sent'] = now
            for k, g in state['groups'].items():
                if k.rsplit(': ', 1)[0] == tracker:
                    g['sent'] = now
                    g['notified_hashes'] = sorted(set(g.get('notified_hashes', [])) | set(g.get('seen_hashes', g['hashes'])))
        elif kind == "recovery":
            tracker = key.rsplit(': ', 1)[0]
            state['tracker_notices'][tracker]['recovery_sent'] = now
            for k, g in list(state['groups'].items()):
                if k.rsplit(': ', 1)[0] == tracker and g['recovery_count'] >= 2:
                    state.setdefault('recently_closed', {})[k] = {**g, 'expires_at': now + 86400}
                    del state['groups'][k]
        elif kind == "missing":
            for h in key.split(","):
                state["incidents"][h]["sent"] = now


def pipeline_signature(findings):
    # Age text changes every run and must not defeat notification suppression.
    normalized = [re.sub(r"\b\d+(?:\.\d+)?\s*(?:h|hours?|days?)\b", "[age]", sanitize(x)) for x in findings]
    return hashlib.sha256(json.dumps(sorted(set(normalized))).encode()).hexdigest()


def port_forward_problem(forwarded, listen_port):
    """Why peers cannot connect in through the VPN, or None.

    gluetun writes PIA's forwarded port to a file and qBittorrent must listen on
    it. In 2026-09 they drifted apart, then the forward failed outright, and
    seeding starved for a month with every service green.
    """
    port = (forwarded or "").strip().split(",")[0]
    if not port.isdigit():
        return "VPN port forwarding has no port: peers cannot connect in, so seeding starves"
    if int(port) != listen_port:
        return ("qBittorrent listens on port %s but the VPN forwards %s: peers cannot connect in, "
                "so seeding starves" % (listen_port, port))
    return None
