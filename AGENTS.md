# Agent Instructions

## The host

The stack runs on **`yggdrasil`** — an HP ProDesk 600 G6 Desktop Mini, Ubuntu
x86_64, Intel i5-10500T, 14 GiB RAM, root on NVMe.

```
ssh twoplustwoone@192.168.1.246
```

It is **not** a Raspberry Pi any more, and the SSH user is not `pi`. Older
documents under `docs/` and `OPS-GUIDE.md` describe the retired Pi at
`192.168.1.188`; they are kept as history and their addresses and paths are
wrong. Treat this file as the authority on where things are.

The checkout is `~/yggdrasil`, which is also the Compose project name
(pinned by `name:` in `docker-compose.yml`; it was `pi4-ultimate-plex-stack`
until October 2026).

Media lives on `/mnt/library` (mounted by UUID). Container configs are at
`/home/pi/docker-configs` — a legacy path that is real and in use; do not
"correct" it without relocating the data.

## Privileges

There is **no passwordless sudo**, and `sudo` cannot prompt over a
non-interactive SSH session (`sudo: a terminal is required to authenticate`).
Anything needing root — mounts, `/etc/fstab`, systemd units, `smartctl`,
partitioning — must be handed to the user.

The pattern that works: write a **guarded script**, have the user run it once
with `sudo`, and make it refuse to act on the wrong target. See
`scripts/prep-new-disk.sh` for the shape — it verifies the disk serial and
aborts if the device backs the live library. One password prompt beats ten
round-trips.

Everything else needs no elevation: the user is in the `docker` group, and the
service APIs are reachable over HTTP on localhost.

## Container topology — three things that cause real bugs

1. **qBittorrent joins gluetun's network namespace.** `docker start qbittorrent
   gluetun` fails, because Docker does not order the arguments — start gluetun
   first. Restarting gluetun also silently breaks qBittorrent's networking;
   restart qBittorrent afterwards. The symptom is `wget: bad address` inside the
   container. qBittorrent's listen port belongs to gluetun: each time PIA
   forwards a port, `scripts/gluetun-qbt-port.sh` logs in and sets it. Do not set
   it by hand, and keep "bypass authentication on localhost" off. qBittorrent
   bans an IP after five failed logins, and the ban lasts until it restarts.
2. **Plex uses host networking; most services use the bridge.** Inside a
   bridged container, `127.0.0.1` is that container — not Plex. Reach Plex at
   `192.168.1.246:32400`. Tautulli was misconfigured this way and recorded
   nothing for months.
3. **Restart policies are `unless-stopped`.** An explicit `docker stop` marks a
   container intentionally stopped and it will **not** come back after a reboot.
   Before an OS upgrade, let the reboot stop them; do not stop them by hand.

## Remote access and Plex updates

Plex was compromised through Plex2Shell in October 2026 while pinned to a
ten-month-old build with port 32400 forwarded. Two rules follow:

- **Plex is never pinned and never forwarded.** It tracks `:latest` and, with
  `jellyfin` and `tailscale`, is one of the three containers Watchtower updates;
  everything else is monitor-only. `scripts/pin-images.sh` skips all three.
  Remote access in Plex stays off; `plex-upnp-port.timer` is disabled and must
  stay that way.
- **Remote clients come in over Tailscale** (container `tailscale`, node
  `yggdrasil`, `100.110.236.10`). plex.tv's Cloudflare edge rejects any device
  update listing a `100.64/10` address, so do not set Plex's custom connection
  URL to the tailnet IP — it breaks Plex's publishing with 403s. Instead the
  node advertises the route `192.168.1.246/32`, and clients use the
  `192-168-1-246.<hash>.plex.direct` connection plex.tv already lists.

Jellyfin is replacing Plex, under the same two rules
(`docs/jellyfin-migration.md`). Clients use `http://192.168.1.246:8096` at home
and over the same route. It has no plex.tv-style limit, so the tailnet IP works
too. Its UPnP stays off.

## Talking to the services

Radarr, Sonarr and Prowlarr keep their API key in `config.xml`:

```bash
key=$(docker exec radarr sed -n 's#.*<ApiKey>\(.*\)</ApiKey>.*#\1#p' /config/config.xml)
curl -s -H "X-Api-Key: $key" http://127.0.0.1:7878/api/v3/health
```

Ports: radarr 7878, sonarr 8989, prowlarr 9696 (`/api/v1`), seerr 5055,
qBittorrent via gluetun 8080, Plex 32400, Jellyfin 8096, Tautulli 8181,
Uptime Kuma 3001. Jellyfin's API key is `JELLYFIN_API_KEY` in `.env`, sent as
`Authorization: MediaBrowser Token="<key>"`; its admin login is
`JELLYFIN_ADMIN_USER`/`_PASS`.
Seerr (Overseerr's successor; the container is `seerr`, still reachable as
`overseerr` on the Docker network) keeps its key in `/app/config/settings.json`
under `main.apiKey`. qBittorrent's credentials are `QBITTORRENT_USER`/`_PASS`
in `.env`.

Torrent cleanup is qbit_manage (`qbit_manage/config/config.yml`): a torrent is
removed only once its library copy is gone *and* its tracker's seeding rule is
met. qBittorrent's `seeding_time` counts only active seeding, not time queued.
qBittorrent below 5.2 ignores qbit_manage's per-torrent `share_limit_action`
and applies its **global** action instead, so that global action must stay
**Stop** (`max_ratio_act=0`). Set to "remove with files", qBittorrent deletes a
torrent outright as soon as its limits are set, skipping qbit_manage's recycle
bin and its minimum-seeding-time check. Deleting a torrent also leaves behind
anything unpackerr extracted beside it (e.g. a `.iso` from a RAR'd disc release).

Never print tokens, API keys or passwords. Use them inside a script or shell
variable. **Beware that redaction can disguise absence** — an empty value passed
through a masking regex prints as `<REDACTED>` and looks populated. Check length,
not appearance.

## Monitoring

Failures are routed to Discord via a webhook shared by Uptime Kuma and the arr
apps. `scripts/pipeline-canary.py` runs every 15 minutes and reports what liveness
checks structurally cannot: everything green while nothing is delivered. It
heartbeats an Uptime Kuma push monitor on every run, so its own death is
detectable.

The service runs **copies** in the home folder (`/home/twoplustwoone/pipeline-canary.py`
and the modules it imports), not the checkout, so `git pull` alone deploys nothing.
After pulling, copy each changed script over its home copy, e.g.
`install -m 644 ~/yggdrasil/scripts/host_checks.py ~/host_checks.py`.

The canary also looks for intrusion tells (`scripts/host_checks.py`). It flags:

- any process in the exposed containers running from outside a root-owned program folder
- Plex pinned to a digest, or on an image more than 21 days old
- a failed or missing nightly config backup

The Plex2Shell implants ran from `/config` and `/tmp`, so a program legitimately
added to a container must come from its image.

If you add a check, make its *absence* detectable too. A monitor that fails
silently reproduces the bug it was built to catch.

## Re-arming a dormant job

**Repairing a broken scheduled task deploys its behaviour for the first time.**
A config backup that had failed silently for five weeks was fixed, and its first
real run stopped Plex mid-film — behaviour that had always been in the script but
had never actually executed. Read any long-broken job for side effects before
enabling it, and prefer running it manually once at a harmless moment.

Note the host clock is **UTC** while the site is `America/New_York`. Name the
zone explicitly in systemd timers or a "3am" job runs at 11pm local.

## Local Operational Artifacts

Keep local-only operational artifacts under `.local/`. This includes incident
history, media inventories, deletion-candidate lists, diagnostic captures, and
other machine-specific working data. The directory is ignored by git; do not
commit files from it.

## Operations Log

When diagnosing or fixing issues on the Plex stack, keep a running local incident
log in `.local/pi-issue-history.md`.

For each issue, append a dated entry with:

- observed symptoms and user-reported problem
- commands or checks run, summarized without secrets
- root cause or best current theory
- actions taken
- follow-up work or hardware checks needed

Record the *misleading* findings too — a check that measured the wrong thing, a
metric that moved the wrong way — not just the conclusion. Several hours were
lost this way to `dd iflag=direct`, which bypasses readahead and understated disk
throughput fourfold.

The log is intentionally local-only. Do not include tokens, passwords, private
keys, or full `.env` contents in it.
