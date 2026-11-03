#!/usr/bin/env python3
"""
pipeline-canary.py — detect a request pipeline that is silently doing nothing.

Liveness checks cannot catch "every service is green but no media is arriving",
which is exactly how a stale download-client address went unnoticed for seven
weeks. This inspects the pipeline end to end and reports only when something is
actually wrong. Silent when healthy. The same applies to torrent cleanup, whose
own heartbeat stays green even when it has stopped deleting anything.

  --report   print findings and exit (no Discord message)
  --apply    post to Discord if there are findings
"""
import http.cookiejar, json, sqlite3, subprocess, sys, time, urllib.request, urllib.parse
import fcntl, hashlib, os, tempfile
from tracker_health import (QBM_DIGEST, STALE_SECONDS, acknowledge, advance,
    config_problems, initial_state, last_scan, load_state, observations,
    pipeline_signature, port_forward_problem, private_torrent, sanitize, save_state)
from datetime import datetime, timezone
from host_checks import (PROGRAM_DIRS, backup_problem, backup_running, foreign_process, plex_update_problem,
    release_update_problem)
from ipt_credit import (CreditUnavailable, fetch_required, with_stored_credentials,
    identity_map, advance_credit, fetch_account_ratio)
from torrent_retirement import (advance_retirement, initial_retirement, intentional_stops, pending_stop_errors,
    retirement_paused, waiver_applies, incarnation, STOPPED)

REPORT_ONLY   = "--apply" not in sys.argv
TRACKER_STATE = os.environ.get("CANARY_TRACKER_STATE", "/home/twoplustwoone/.canary-tracker-health.json")
if not REPORT_ONLY:
    _lock = open(TRACKER_STATE + ".lock", "a")
    try:
        fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another canary run is active")
        sys.exit(0)
state_error = None
try:
    monitor_state = load_state(TRACKER_STATE)
except (OSError, ValueError, TypeError):
    monitor_state = initial_state()
    if "--initialize-state" not in sys.argv:
        state_error = "tracker monitoring state missing/corrupt; history cannot be verified"
tracker_events = []
retirement_events = []
monitor_errors = []
STUCK_REQ_DAYS = 3     # approved but still not available
STUCK_QUEUE_HRS = 24   # sat in the download queue this long
NO_GRAB_DAYS   = 21    # nothing successfully grabbed at all
MIN_FREE_GB    = 250

# Torrent cleanup. These mirror qbit_manage/config/config.yml; keep them in step.
QBIT = "http://127.0.0.1:8080"
ENV_FILE = os.environ.get("CANARY_ENV_FILE", "/home/twoplustwoone/yggdrasil/.env")
PUBLIC_DAYS = 3
HNR_DAYS = 14          # IPTorrents: 1:1 or 14 days, per torrent
CLEANUP_GRACE_DAYS = 1 # qbit_manage runs hourly; a day late means it has stalled
STOPPED_STATE = os.environ.get("CANARY_STOPPED_STATE", "/home/twoplustwoone/.canary-stopped-released.json")

# Dead-man switch: an Uptime Kuma push monitor, pinged on EVERY completed run
# whether healthy or not. It proves the canary itself is alive. Kuma raises the
# alarm when the heartbeat stops - the one failure this script cannot report
# about itself.
PUSH_URL = "http://127.0.0.1:3001/api/push/16EK9URVJDqa7NhX"
SUMMARY_STATE = os.environ.get("CANARY_SUMMARY_STATE", "/home/twoplustwoone/.canary-last-summary")
SUMMARY_EVERY_DAYS = 7

def sh(*a): return subprocess.check_output(a, stderr=subprocess.DEVNULL).decode().strip()
_arr_key_cache = {}
def arr_key(svc):
    if svc not in _arr_key_cache:
        _arr_key_cache[svc] = sh("docker","exec",svc,"sed","-n",
                  r"s#.*<ApiKey>\(.*\)</ApiKey>.*#\1#p","/config/config.xml")
    return _arr_key_cache[svc]
def get(url, key, hdr="X-Api-Key"):
    r = urllib.request.Request(url, headers={hdr: key})
    with urllib.request.urlopen(r, timeout=30) as resp:
        return json.load(resp)

def radarr_release_pending(movie_id):
    """True if Radarr shows this movie as not yet released (nothing to deliver)."""
    try:
        m = get("http://127.0.0.1:7878/api/v3/movie/%d" % movie_id, arr_key("radarr"))
        return m.get("status") != "released"
    except Exception:
        return False  # fail open: never suppress a real finding on a lookup error

def sonarr_season_unaired(series_id, season_numbers):
    """True if every requested season hasn't aired yet (nothing to deliver)."""
    try:
        s = get("http://127.0.0.1:8989/api/v3/series/%d" % series_id, arr_key("sonarr"))
        if s.get("status") == "upcoming":
            return True
        seasons = {se.get("seasonNumber"): se for se in s.get("seasons", [])}
        for num in season_numbers:
            se = seasons.get(num)
            if not se:
                continue
            stats = se.get("statistics", {}) or {}
            if stats.get("nextAiring") and stats.get("episodeFileCount", 0) == 0:
                continue  # this season still pending airing
            return False  # at least one requested season is airing/aired, not just pending
        return True
    except Exception:
        return False  # fail open

def age_days(ts):
    if not ts: return None
    ts = ts.replace("Z", "+00:00")
    try: d = datetime.fromisoformat(ts)
    except ValueError: return None
    if d.tzinfo is None: d = d.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - d).total_seconds() / 86400

def backup_unit():
    """(Result, last exit, ActiveState, current run's start) of the nightly backup; times unix."""
    unit = dict(l.split("=", 1) for l in sh("systemctl", "show", "plex-config-backup.service", "-p", "Result",
                "-p", "ExecMainExitTimestamp", "-p", "ActiveState", "-p", "ExecMainStartTimestamp",
                "--timestamp=unix").splitlines() if "=" in l)
    stamp = lambda k: int(unit[k].lstrip("@")) if unit.get(k, "").lstrip("@").isdigit() else None
    return unit.get("Result"), stamp("ExecMainExitTimestamp"), unit.get("ActiveState"), stamp("ExecMainStartTimestamp")

# The nightly backup stops Plex and Kuma for a few minutes; a run then reports its
# own failed checks and cannot reach Kuma or Discord. Skip it unless the backup is stuck.
try:
    _, _, state, started = backup_unit()
    if backup_running(state, started, time.time()):
        print("nightly backup in progress; skipping this run")
        sys.exit(0)
except subprocess.CalledProcessError:
    pass  # the backup check below reports an unreadable unit

findings = []

# 1. health errors reported by the apps themselves
for svc, port, ver in (("radarr",7878,"v3"), ("sonarr",8989,"v3"), ("prowlarr",9696,"v1")):
    try:
        for h in get("http://127.0.0.1:%d/api/%s/health" % (port, ver), arr_key(svc)):
            if h.get("type") == "error":
                findings.append("%s health: %s" % (svc, h.get("message","")[:110]))
    except Exception as e:
        findings.append("%s unreachable: %s" % (svc, type(e).__name__))

# 2. nothing grabbed recently, and 3. queue items stuck
for svc, port in (("radarr",7878), ("sonarr",8989)):
    try:
        k = arr_key(svc)
        # eventType=1 is "grabbed". Filtering server-side matters: a burst of
        # imports can push every grab off the first page of unfiltered history.
        h = get("http://127.0.0.1:%d/api/v3/history?eventType=1&pageSize=5&sortKey=date&sortDirection=descending" % port, k)
        grabs = h.get("records", [])
        if grabs:
            d = age_days(grabs[0].get("date"))
            if d and d > NO_GRAB_DAYS:
                findings.append("%s: no successful grab in %d days" % (svc, d))
        else:
            findings.append("%s: no grabs in recent history at all" % svc)

        q = get("http://127.0.0.1:%d/api/v3/queue?pageSize=100" % port, k)
        for r in q.get("records", []):
            if r.get("errorMessage"):
                findings.append("%s queue: %s -- %s" % (svc, (r.get("title") or "?")[:44], r["errorMessage"][:60]))
            d = age_days(r.get("added"))
            if d and d * 24 > STUCK_QUEUE_HRS:
                findings.append("%s queue: '%s' stuck %.0fh" % (svc, (r.get("title") or "?")[:44], d*24))
    except Exception as e:
        findings.append("%s history/queue check failed: %s" % (svc, type(e).__name__))

# 4. Overseerr requests approved but never delivered -- the user-visible failure
try:
    okey = json.loads(sh("docker","exec","seerr","cat","/app/config/settings.json"))["main"]["apiKey"]
    reqs = get("http://127.0.0.1:5055/api/v1/request?take=100&sort=added", okey)
    for r in reqs.get("results", []):
        media = r.get("media") or {}
        if r.get("status") == 2 and media.get("status") in (2, 3):   # approved, still pending/processing
            d = age_days(r.get("createdAt"))
            if d and d > STUCK_REQ_DAYS:
                media_type = r.get("type")
                ext_id = media.get("externalServiceId")
                if media_type == "movie" and ext_id and radarr_release_pending(ext_id):
                    continue
                if media_type == "tv" and ext_id:
                    season_nums = [s.get("seasonNumber") for s in r.get("seasons", [])]
                    if sonarr_season_unaired(ext_id, season_nums):
                        continue
                who = (r.get("requestedBy") or {}).get("displayName", "?")
                findings.append("overseerr: request #%s (%s, by %s) approved but not available after %.0f days"
                                % (r.get("id"), r.get("type"), who, d))
except Exception as e:
    findings.append("overseerr request check failed: %s" % type(e).__name__)

# 5. disk headroom
try:
    out = sh("df","-B1","--output=avail","/mnt/library").splitlines()[-1]
    free_gb = int(out) / 1e9
    if free_gb < MIN_FREE_GB:
        findings.append("library free space low: %.0f GB" % free_gb)
except Exception:
    pass

# 9-11. intrusion tells (see host_checks.py). A check that cannot run fails the
# heartbeat rather than passing silently.
WATCHED = ("plex", "jellyfin", "seerr", "radarr", "sonarr", "prowlarr", "tautulli", "qbittorrent")
def foreign_processes():
    found = {}
    for name in WATCHED:
        for pid in sh("docker", "top", name, "-o", "pid").split()[1:]:
            try:
                uid = os.stat("/proc/" + pid).st_uid
                with open("/proc/%s/comm" % pid) as f: comm = f.read().strip()
            except OSError:
                continue  # exited between listing and reading
            try: exe = os.readlink("/proc/%s/exe" % pid)
            except OSError: exe = None
            digest = None
            if exe and not exe.startswith(PROGRAM_DIRS):
                try:  # the binary actually running, even if the file was since replaced
                    with open("/proc/%s/exe" % pid, "rb") as f: digest = hashlib.sha256(f.read()).hexdigest()
                except OSError:
                    pass
            why = foreign_process(exe, uid, comm, digest)
            if why: found[(name, pid)] = "%s %s" % (name, why)
    return found
try:
    suspects = foreign_processes()
    if suspects:
        time.sleep(30)  # healthchecks and updates are brief; planted programs persist
        again = foreign_processes()
        for key in sorted(set(suspects) & set(again)):
            findings.append("possible intrusion: " + again[key])
except Exception as e:
    monitor_errors.append("process check failed: %s" % type(e).__name__)
try:
    ref, image = sh("docker", "inspect", "plex", "--format", "{{.Config.Image}} {{.Image}}").split()
    problem = plex_update_problem(ref, sh("docker", "image", "inspect", image, "--format", "{{.Created}}"),
                                  datetime.now(timezone.utc))
    if problem: findings.append(problem)
except Exception as e:
    monitor_errors.append("Plex update check failed: %s" % type(e).__name__)
try:
    ref, image = sh("docker", "inspect", "jellyfin", "--format", "{{.Config.Image}} {{.Image}}").split()
    local = json.loads(sh("docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"))
    with urllib.request.urlopen("https://hub.docker.com/v2/repositories/jellyfin/jellyfin/tags/latest", timeout=30) as r:
        latest = json.load(r)
    problem = release_update_problem("Jellyfin", ref, local, latest["digest"], latest["last_updated"],
                                     datetime.now(timezone.utc))
    if problem: findings.append(problem)
except Exception as e:
    monitor_errors.append("Jellyfin update check failed: %s" % type(e).__name__)
try:
    result, finished, state, started = backup_unit()
    problem = backup_problem(result, finished, time.time(), state, started)
    if problem: findings.append(problem)
except Exception as e:
    monitor_errors.append("backup check failed: %s" % type(e).__name__)

# 6-8. torrents: seeding owed to IPTorrents is being earned, cleanup keeps pace,
# and the qBittorrent settings both depend on are still in place.
def qbit_opener():
    with open(ENV_FILE) as f:
        env = dict(l.strip().split("=", 1) for l in f if "=" in l and not l.startswith("#"))
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    form = urllib.parse.urlencode({"username": env["QBITTORRENT_USER"].strip('"'),
                                   "password": env["QBITTORRENT_PASS"].strip('"')}).encode()
    req = urllib.request.Request(QBIT + "/api/v2/auth/login", data=form, headers={"Referer": QBIT})
    if op.open(req, timeout=30).read() != b"Ok.":
        raise RuntimeError("qBittorrent login refused")
    return op

def cleanup_due(t, slack_days=0):
    """qbit_manage's rule for a released torrent, optionally `slack_days` past it."""
    days = t["seeding_time"] / 86400 - slack_days
    if private_torrent(t):
        return False  # Private cleanup is held regardless of local counters.
    return days >= PUBLIC_DAYS

try:
    op = qbit_opener()
    qget = lambda path: json.load(op.open(QBIT + path, timeout=30))
    # With qBittorrent < 5.2 its global action overrides qbit_manage's "Stop":
    # "remove with files" deletes outside the recycle bin and min-seed check.
    preferences = qget("/api/v2/app/preferences")
    act = preferences.get("max_ratio_act")
    if act != 0:
        findings.append("qBittorrent share-limit action is %s, not 0 (Stop): cleanup bypasses the recycle bin" % act)
    # Peers reach qBittorrent only through the VPN's forwarded port. gluetun
    # empties the port file while it reconnects, so recheck once before reporting.
    def forwarded_port():
        try:
            return sh("docker", "exec", "gluetun", "cat", "/tmp/gluetun/forwarded_port")
        except subprocess.CalledProcessError:
            return ""
    problem = port_forward_problem(forwarded_port(), preferences.get("listen_port"))
    if problem:
        time.sleep(60)
        problem = port_forward_problem(forwarded_port(), qget("/api/v2/app/preferences").get("listen_port"))
    if problem:
        findings.append(problem)
    torrents = qget("/api/v2/torrents/info")
    tags = {t["hash"]: {x.strip() for x in t["tags"].split(",")} for t in torrents}
    stopped = {"stoppedUP", "pausedUP"}
    credit = None
    credit_identities = {}

    # Account credit is independent of tracker liveness. Existing Prowlarr
    # authentication stays in memory; a logged-out 200 response is not success.
    if any("IPT" in tags[t["hash"]] for t in torrents):
        try:
            indexers=with_stored_credentials(get("http://127.0.0.1:9696/api/v1/indexer", arr_key("prowlarr")))
            credit = fetch_required(indexers)
            print("IPT account credit readable: %d explicit records; absence alone is not completion."
                  % len(credit["records"]))
            if len(credit['account_user_ids'])!=1:
                raise CreditUnavailable('IPT account identity ambiguous; retirement held')
            account_ratio=fetch_account_ratio(indexers,credit['account_user_ids'][0])
            if account_ratio['below_minimum']:
                findings.append('IPT overall account ratio is below 1.0; per-torrent seed-time completion does not fix the account ratio')
            history=[]
            for svc,port in (("radarr",7878),("sonarr",8989)):
                page=1
                while page<=20:
                    chunk=get("http://127.0.0.1:%d/api/v3/history?eventType=1&page=%d&pageSize=1000&sortKey=date&sortDirection=descending"
                              % (port,page),arr_key(svc))
                    history.extend(chunk.get("records",[]))
                    if page*1000>=chunk.get("totalRecords",0): break
                    page+=1
                else:
                    raise CreditUnavailable("IPT identity history exceeds validated bound; retirement held")
            credit_identities=identity_map(history)
        except CreditUnavailable as e:
            monitor_errors.append(str(e))  # fixed safe categories, never raw bodies
        except Exception:
            monitor_errors.append("IPT account connection lookup failed; retirement held")

    # Read only safe configuration fields and bounded logs; never expose env secrets.
    # qbit_manage rotates its log to qbit_manage.1.log at 10 MB, even mid-run, so
    # the last complete run can straddle the two files.
    probe = '''import json,pathlib,os
from ruamel.yaml import YAML
logs=[pathlib.Path('/config/logs/qbit_manage.1.log'),pathlib.Path('/config/logs/qbit_manage.log')]
c=YAML(typ='base').load(pathlib.Path('/config/config.yml').read_text())
print(json.dumps({'config':{k:c.get(k,{}) for k in ['commands','settings','share_limits']},
'log':'\\n'.join(''.join(p.read_text() for p in logs if p.exists()).splitlines()[-20000:]),
'tz':os.environ.get('TZ','UTC')}))'''
    metadata = json.loads(sh("docker", "exec", "qbit_manage", "python", "-c", probe))
    monitor_errors.extend(config_problems(metadata["config"]))
    recent_run = metadata["log"].rsplit("Starting Run", 1)[-1]
    if "[ERROR]" in recent_run or "[CRITICAL]" in recent_run or "Traceback" in recent_run:
        monitor_errors.append("latest qbit_manage run contains errors")
    image_id = sh("docker", "inspect", "qbit_manage", "--format", "{{.Image}}")
    digests = json.loads(sh("docker", "image", "inspect", image_id, "--format", "{{json .RepoDigests}}"))
    if not any(x.endswith("@" + QBM_DIGEST) for x in digests or []):
        monitor_errors.append("qbit_manage image differs from validated digest")
    scan = None
    try:
        scan = last_scan(metadata["log"], metadata["tz"])
        if time.time() - scan > STALE_SECONDS:
            monitor_errors.append("qbit_manage successful tracker scan is over 90 minutes old")
    except (ValueError, KeyError):
        monitor_errors.append("qbit_manage has no supported successful tracker scan")
    tracker_rows = {}
    for t in torrents:
        if private_torrent(t) or "issue" in tags[t["hash"]]:
            try:
                tracker_rows[t["hash"]] = qget("/api/v2/torrents/trackers?hash=" + t["hash"])
            except Exception:
                monitor_errors.append("tracker API read failed; recovery/credit cannot be verified")
    retirement_previous=monitor_state.get('retirement') or initial_retirement()
    paused=retirement_paused(retirement_previous)
    authorized=intentional_stops(retirement_previous,torrents)
    waived={t['hash'] for t in torrents if waiver_applies(retirement_previous,t)}
    groups, healthy, inventory, protection_errors = observations(torrents, tracker_rows, preferences,authorized)
    if credit is not None:
        credit_state,credit_findings=advance_credit(monitor_state.get("ipt_credit"),credit["records"],
            credit_identities,torrents,
            healthy if scan is not None and time.time()-scan<=STALE_SECONDS else set(),time.time(),
            satisfied=waived|authorized)
        monitor_state["ipt_credit"]=credit_state
        if paused:
            # Credit evidence gates only retirement stops, and none happen while paused.
            for f in credit_findings: print("retirement paused, not a failure: " + f)
        else:
            monitor_errors.extend(credit_findings)
    monitor_errors.extend(protection_errors)
    if state_error:
        monitor_errors.append(state_error)
    if paused:
        print('Finite seeding retirement is paused; no torrents will be stopped.')
    elif not retirement_previous.get('enabled'):
        monitor_errors.append('finite seeding policy disabled/uninitialized; retirement held')
    retirement,stop_actions,retirement_errors=advance_retirement(retirement_previous,torrents,
        credit['records'] if credit else {},credit_identities,healthy,scan,time.time(),
        valid=not monitor_errors and scan is not None and time.time()-scan<=STALE_SECONDS
            and (credit is not None or not any('IPT' in ts for ts in tags.values())))
    monitor_errors.extend(retirement_errors)
    monitor_state['retirement']=retirement
    if stop_actions and not REPORT_ONLY:
        # Commit proof and intent before the side effect. A crash immediately
        # after POST is distinguishable from an unverified/manual private stop.
        save_state(TRACKER_STATE,monitor_state)
        latest={t['hash']:t for t in qget('/api/v2/torrents/info')}
        if any(h not in latest or incarnation(latest[h])!=retirement['torrents'][h]['incarnation']
               or latest[h].get('progress')!=1 for h in stop_actions):
            raise RuntimeError('retirement candidates changed; stopping held')
        form=urllib.parse.urlencode({'hashes':'|'.join(stop_actions)}).encode()
        request=urllib.request.Request(QBIT+'/api/v2/torrents/stop',data=form,headers={'Referer':QBIT})
        with op.open(request,timeout=30) as response:
            if response.status!=200: raise RuntimeError('retirement stop request refused')
            response.read()
        verified=qget('/api/v2/torrents/info')
        retirement,_,_=advance_retirement(retirement,[t for t in verified if t['hash'] in stop_actions],credit['records'] if credit else {},
            credit_identities,healthy,scan,time.time(),valid=False)
        monitor_state['retirement']=retirement
    # HTTP 200 precedes qBittorrent's asynchronous stopped-state transition.
    # Check all persisted intents, including those no longer eligible for retry.
    monitor_errors.extend(pending_stop_errors(retirement,time.time()))
    retired_pending=[t for t in torrents if retirement['torrents'].get(t['hash'],{}).get('phase')=='retired'
        and not retirement['torrents'][t['hash']].get('notified')]
    if retired_pending:
        retirement_events.append(('retirement:'+','.join(t['hash'] for t in retired_pending),
            '%d torrent(s) stopped after verified seeding policy; files retained. Examples: '%len(retired_pending)
            +'; '.join(sanitize(t['name']) for t in retired_pending[:3])))
    phases=[r['phase'] for r in retirement['torrents'].values() if r.get('proof')]
    print('Finite seeding: %d waived; %d buffering; %d pending stop; %d retired.'%
          (len(waived),phases.count('buffer'),phases.count('pending'),phases.count('retired')))
    # Invalid scans cannot advance debounce, clear incidents, or replace inventory.
    monitor_state, tracker_events = advance(monitor_state, groups, healthy, inventory,
        scan, time.time(), valid=scan is not None and time.time() - scan <= STALE_SECONDS,
        retired=intentional_stops(retirement, torrents) & {t['hash'] for t in torrents if t['state'] in STOPPED})

    queued = [t for t in torrents if t["state"] == "queuedUP"]
    if queued:
        findings.append("qBittorrent: %d torrents queued instead of seeding (queue limits back?)" % len(queued))
    # Queued, stopped or errored torrents don't announce, so owed seeding time stalls.
    owing = [t for t in torrents if t.get("private") and t["progress"] == 1
             and t["ratio"] < 1 and t["seeding_time"] < HNR_DAYS * 86400
             and t["state"] not in ("uploading", "stalledUP", "forcedUP", "queuedUP")
             and t['hash'] not in authorized]
    if owing:
        findings.append("%d private torrents still owe seeding but aren't seeding (e.g. %s: %s)"
                        % (len(owing), owing[0]["name"][:40], owing[0]["state"]))

    # A released torrent that qBittorrent stopped at its limit should be gone by
    # qbit_manage's next hourly run. Stopped torrents stop accruing seeding time,
    # so track when each was first seen stopped.
    now = time.time()
    try:
        with open(STOPPED_STATE) as f:
            first_seen = json.load(f)
    except (OSError, ValueError):
        first_seen = {}
    first_seen = {t["hash"]: first_seen.get(t["hash"], now) for t in torrents
                  if "released" in tags[t["hash"]] and t["state"] in stopped}
    if not REPORT_ONLY:
        with open(STOPPED_STATE, "w") as f:
            json.dump(first_seen, f)
    overdue = [t for t in torrents if not private_torrent(t) and "released" in tags[t["hash"]] and (
        now - first_seen.get(t["hash"], now) > CLEANUP_GRACE_DAYS * 86400
        or (t["state"] not in stopped and cleanup_due(t, CLEANUP_GRACE_DAYS)))]
    if overdue:
        findings.append("torrent cleanup stalled: %d released torrents past their seeding rule (e.g. %s)"
                        % (len(overdue), overdue[0]["name"][:50]))
except Exception as e:
    monitor_errors.append("torrent monitoring failed: %s" % type(e).__name__)

findings.extend(sorted(set(monitor_errors)))
# A season pack is one queue record per episode, each producing the same line.
findings = list(dict.fromkeys(findings))

def heartbeat(msg, status="up"):
    """Tell Kuma the canary ran. A failure here must never mask the real result."""
    if REPORT_ONLY:
        return
    try:
        urllib.request.urlopen(
            PUSH_URL + "?status=" + status + "&msg=" + urllib.parse.quote(msg[:60]), timeout=15).read()
        print("heartbeat sent")
    except Exception as e:
        print("heartbeat FAILED: %s" % type(e).__name__)

def discord(msg):
    # Read live SQLite (including WAL) inside Kuma; copying only its DB can be stale.
    js = """const sqlite=require('@louislam/sqlite3');
const db=new sqlite.Database('/app/data/kuma.db',sqlite.OPEN_READONLY);
db.get('SELECT config FROM notification WHERE id=1',(e,r)=>{
if(e){process.exitCode=1;}else{process.stdout.write(JSON.parse(r.config).discordWebhookUrl);}db.close();});"""
    hook = sh("docker", "exec", "uptime-kuma", "node", "-e", js)
    if not hook.startswith("https://discord.com/api/webhooks/"):
        raise ValueError("Discord webhook missing")
    req = urllib.request.Request(hook, data=json.dumps({"content": msg, "allowed_mentions": {"parse": []}}).encode(),
        headers={"Content-Type":"application/json","User-Agent":"pipeline-canary"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status

def maybe_weekly_summary(ok):
    """Periodic proof of life. Covers BOTH this script and Kuma failing at once -
    a human notices the weekly message stopped arriving."""
    if REPORT_ONLY:
        return True
    import os, time
    try:
        last = os.path.getmtime(SUMMARY_STATE)
    except OSError:
        last = 0
    if (time.time() - last) < SUMMARY_EVERY_DAYS * 86400:
        return True
    try:
        discord("Weekly check-in: pipeline canary is running. " +
                ("No issues found." if ok else "Issues reported separately."))
        with open(SUMMARY_STATE, "w") as f:
            f.write(str(time.time()))
        print("weekly summary sent")
        return True
    except Exception as e:
        print("weekly summary failed: %s" % type(e).__name__)
        return False

now = time.time()
signature = pipeline_signature(findings)
pipeline_due = (signature != monitor_state.get("pipeline_signature") or
    findings and now - monitor_state.get("pipeline_sent", 0) >= 86400)
lines = [(event_id, sanitize(body, 1400)) for event_id, body in tracker_events]
lines.extend(retirement_events)
if findings:
    print("Pipeline findings:\n" + "\n".join("- " + sanitize(f) for f in findings))
    if pipeline_due:
        lines.extend(("pipeline", sanitize(f)) for f in findings)
elif monitor_state.get("pipeline_signature") and signature != monitor_state["pipeline_signature"]:
    lines.append(("pipeline", "Previous pipeline findings cleared."))
if tracker_events:
    print("Tracker findings:\n" + "\n".join("- " + sanitize(b, 1400) for _, b in tracker_events))
if not findings and not tracker_events:
    print("No new alerts. Tracker credit/H&R clearance remains unverified; private cleanup held.")

if not REPORT_ONLY:
    delivered = True
    # Bound messages without truncating away incidents; acknowledge each delivered batch.
    batches, batch, length = [], [], 0
    for event in lines:
        if length + len(event[1]) + 3 > 1700 and batch:
            batches.append(batch); batch, length = [], 0
        batch.append(event); length += len(event[1]) + 3
    if batch: batches.append(batch)
    for batch in batches:
        try:
            discord("**Plex / tracker monitoring**\n" + "\n".join("- " + body for _, body in batch))
            acknowledge(monitor_state, [k for k, _ in batch if k != "pipeline"], now)
            for event_id,_ in batch:
                if event_id.startswith('retirement:'):
                    for h in event_id.removeprefix('retirement:').split(','):
                        monitor_state['retirement']['torrents'][h]['notified']=now
        except Exception as e:
            print("Discord delivery FAILED: " + type(e).__name__)
            delivered = False
            break
    if delivered and pipeline_due:
        monitor_state["pipeline_signature"], monitor_state["pipeline_sent"] = signature, now
    if not maybe_weekly_summary(not findings and not monitor_state["groups"]):
        delivered = False
    try:
        # Missing/corrupt history must stay visible until explicitly initialized.
        if not state_error:
            save_state(TRACKER_STATE, monitor_state)
    except Exception as e:
        print("Monitoring state write FAILED: " + type(e).__name__)
        delivered = False
    heartbeat(("notification/state persistence failed" if not delivered else
              "monitoring failed: " + sanitize(monitor_errors[0],180)) if monitor_errors or not delivered else
              "%d pipeline finding(s), %d tracker group(s)" % (len(findings), len(monitor_state["groups"])),
              "down" if monitor_errors or not delivered else "up")
    _lock.close()
    if not delivered: sys.exit(1)
