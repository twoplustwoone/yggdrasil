"""Cheap intrusion tells for the canary. Pure decisions; the canary collects facts.

The 2026-10 Plex2Shell compromise ran a miner, an SSH server and a tunnel from
Plex's config folder and /tmp, sat on a ten-month-old pinned Plex build, and left
an unreadable folder that failed the nightly backup three nights running. Each
check here would have flagged one of those within a day.
"""
from datetime import datetime

# Folders the containers' own user cannot write (verified 2026-10-28). A program
# running from anywhere else (/config, /tmp, /share) was put there at runtime.
# Limit: the arr apps own the files inside their bin folders (for self-update),
# so overwriting an existing file there would go unnoticed; adding one cannot.
PROGRAM_DIRS = ("/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/bin/", "/sbin/", "/package/", "/command/",
                "/usr/lib/plexmediaserver/", "/app/radarr/bin/", "/app/sonarr/bin/", "/app/prowlarr/bin/",
                "/jellyfin/", "/usr/lib/jellyfin-ffmpeg/")
# Root processes cannot be read by the canary's user, so they are judged by name:
# the s6 supervision tree, shells, and the healthchecks docker runs as root.
ROOT_COMMANDS = {"s6-svscan", "s6-supervise", "s6-linux-init-s", "s6-ipcserverd", "s6-rc", "s6-log",
                 "bash", "sh", "sleep", "busybox", "docker-init", "curl", "wget"}
# Programs Plex downloads into /config at runtime, matched by content so a file
# planted at the same path still alerts. Each was verified against downloads.plex.tv:
# the zip's sha256 against plex.tv's codec manifest, then the binary inside it.
VERIFIED_BINARIES = {
    "104c46812636118342920c9612c6d6d5bc76c5fd322cb95141ac8c1f800f385c":
        "Plex EasyAudioEncoder 6a4213e165f8ac3d108a346e linux-x86_64 (verified 2026-11-02)",
}
PLEX_MAX_IMAGE_DAYS = 21   # linuxserver rebuilds the image weekly
# Jellyfin's image changes only on a release, with gaps of up to six months, so its
# age says nothing. Compare with the registry instead; Watchtower pulls daily.
RELEASE_GRACE_DAYS = 3
BACKUP_MAX_AGE_HOURS = 36  # nightly job, plus slack
BACKUP_MAX_RUN_HOURS = 2   # runs take 1-18 minutes


def foreign_process(exe, uid, comm, digest=None):
    """Why a container process looks planted, or None. `exe` is None when unreadable;
    `digest` is the sha256 of the running binary, when the canary could read it."""
    if exe is not None:
        if exe.endswith(" (deleted)"):
            return "runs a deleted program %s" % exe[:-len(" (deleted)")]
        if exe.startswith(PROGRAM_DIRS) or digest in VERIFIED_BINARIES:
            return None
        return "runs %s (sha256 %s)" % (exe, digest) if digest else "runs %s" % exe
    if uid == 0:
        return None if comm in ROOT_COMMANDS else "runs root process %r" % comm
    return "runs an unreadable process %r as uid %s" % (comm, uid)


def plex_update_problem(image_ref, created, now):
    """Why Plex is no longer taking updates, or None. `created` is the image's ISO time."""
    if "@sha256:" in image_ref:
        return "Plex is pinned to an image digest, so it cannot take security fixes"
    age = (now - datetime.fromisoformat(created.replace("Z", "+00:00"))).total_seconds() / 86400
    if age > PLEX_MAX_IMAGE_DAYS:
        return "Plex image is %d days old: automatic updates have stopped" % age
    return None


def release_update_problem(name, image_ref, local_digests, latest_digest, latest_published, now):
    """Why a container is not on its registry's latest release, or None.

    `local_digests` are the running image's RepoDigests; `latest_*` describe the
    registry's current tag."""
    if "@sha256:" in image_ref:
        return "%s is pinned to an image digest, so it cannot take security fixes" % name
    if any(d.endswith("@" + latest_digest) for d in local_digests):
        return None
    age = (now - datetime.fromisoformat(latest_published.replace("Z", "+00:00"))).total_seconds() / 86400
    if age > RELEASE_GRACE_DAYS:
        return "%s has not taken a release published %d days ago: automatic updates have stopped" % (name, age)
    return None


def backup_running(state, started, now):
    """Whether the nightly backup is mid-run and not overdue. It stops Plex and Kuma
    for a few minutes, so other checks run in that window fail by themselves."""
    return state == "activating" and started is not None and now - started < BACKUP_MAX_RUN_HOURS * 3600


def backup_problem(result, finished, now, state="inactive", started=None):
    """Why the nightly config backup cannot be trusted, or None. Times are unix;
    `state` and `started` are the unit's ActiveState and current run's start."""
    if state == "activating":
        # systemd blanks the last exit time while a run is in progress.
        if backup_running(state, started, now):
            return None
        return "nightly config backup has been running since %s" % (
            "?" if started is None else datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M"))
    when = "never" if finished is None else datetime.fromtimestamp(finished).strftime("%Y-%m-%d %H:%M")
    if finished is None or now - finished > BACKUP_MAX_AGE_HOURS * 3600:
        return "nightly config backup has not finished since %s" % when
    if result != "success":
        return "nightly config backup failed (%s, %s)" % (result, when)
    return None
