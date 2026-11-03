import unittest
from datetime import datetime, timedelta, timezone

import host_checks as hc


class ForeignProcessTest(unittest.TestCase):
    def test_programs_from_writable_places_are_flagged(self):
        # The 2026-10 implants: miner in Plex's cache, dropbear in /config, curl copies in /tmp.
        for exe in ("/config/Library/Application Support/Plex Media Server/Cache/PlexMediaScanner",
                    "/config/plugins/x", "/cache/transcodes/x",
                    "/config/.db/db", "/tmp/.pxb/curl", "/app/evil", "/share/movies/x"):
            self.assertIn(exe, hc.foreign_process(exe, 1000, "x"))

    def test_stock_programs_pass(self):
        for exe in ("/usr/lib/plexmediaserver/Plex Media Server", "/usr/lib/plexmediaserver/Plex Transcoder",
                    "/app/radarr/bin/Radarr", "/usr/local/bin/node", "/usr/bin/qbittorrent-nox",
                    "/jellyfin/jellyfin", "/usr/lib/jellyfin-ffmpeg/ffmpeg"):
            self.assertIsNone(hc.foreign_process(exe, 1000, "x"))

    def test_deleted_binary_is_flagged_even_in_a_system_dir(self):
        self.assertIn("deleted", hc.foreign_process("/usr/bin/top (deleted)", 1000, "top"))

    def test_root_processes_judged_by_name(self):
        self.assertIsNone(hc.foreign_process(None, 0, "s6-supervise"))
        self.assertIsNone(hc.foreign_process(None, 0, "curl"))  # docker healthcheck
        self.assertIn("xmrig", hc.foreign_process(None, 0, "xmrig"))

    def test_unreadable_non_root_process_is_flagged(self):
        self.assertIn("uid 911", hc.foreign_process(None, 911, "db"))

    def test_verified_plex_download_passes_by_content(self):
        eae = "/config/Library/Application Support/Plex Media Server/Codecs/EasyAudioEncoder-x/EasyAudioEncoder"
        good = "104c46812636118342920c9612c6d6d5bc76c5fd322cb95141ac8c1f800f385c"
        self.assertIsNone(hc.foreign_process(eae, 1000, "EasyAudioEncoder", good))
        # A planted file at the same path is still flagged, with its digest to check.
        self.assertIn("sha256 deadbeef", hc.foreign_process(eae, 1000, "EasyAudioEncoder", "deadbeef" * 8))


class PlexUpdateTest(unittest.TestCase):
    now = datetime(2026, 10, 28, tzinfo=timezone.utc)

    def test_fresh_image_passes(self):
        self.assertIsNone(hc.plex_update_problem("lscr.io/linuxserver/plex:latest", "2026-10-26T13:17:28.8Z", self.now))

    def test_stale_image_is_flagged(self):
        created = (self.now - timedelta(days=30)).isoformat()
        self.assertIn("30 days old", hc.plex_update_problem("lscr.io/linuxserver/plex:latest", created, self.now))

    def test_digest_pin_is_flagged_even_when_fresh(self):
        # How 1.42.2 stayed in place for ten months.
        self.assertIn("pinned", hc.plex_update_problem("lscr.io/linuxserver/plex@sha256:1720efa8", "2026-10-26T00:00:00Z", self.now))


class ReleaseUpdateTest(unittest.TestCase):
    now = datetime(2026, 10, 29, tzinfo=timezone.utc)
    ref = "jellyfin/jellyfin:latest"
    running = ["jellyfin/jellyfin@sha256:aaaa"]

    def check(self, latest_digest, published, ref=ref):
        return hc.release_update_problem("Jellyfin", ref, self.running, latest_digest, published, self.now)

    def test_running_the_latest_release_passes_however_old(self):
        self.assertIsNone(self.check("sha256:aaaa", "2026-04-05T00:00:00Z"))

    def test_new_release_within_grace_passes(self):
        self.assertIsNone(self.check("sha256:bbbb", "2026-10-27T12:00:00Z"))

    def test_release_not_taken_after_grace_is_flagged(self):
        self.assertIn("5 days ago", self.check("sha256:bbbb", "2026-10-23T12:00:00.123456Z"))

    def test_digest_pin_is_flagged_even_when_current(self):
        self.assertIn("pinned", self.check("sha256:aaaa", "2026-10-28T00:00:00Z", ref="jellyfin/jellyfin@sha256:aaaa"))


class BackupTest(unittest.TestCase):
    now = 1_800_000_000

    def test_recent_success_passes(self):
        self.assertIsNone(hc.backup_problem("success", self.now - 3600, self.now))

    def test_failed_run_is_flagged(self):
        self.assertIn("failed (exit-code", hc.backup_problem("exit-code", self.now - 3600, self.now))

    def test_stopped_schedule_is_flagged_even_after_a_success(self):
        self.assertIn("has not finished since", hc.backup_problem("success", self.now - 40 * 3600, self.now))
        self.assertIn("never", hc.backup_problem("success", None, self.now))

    def test_run_in_progress_passes_though_systemd_blanks_its_exit_time(self):
        # 2026-10-28..11-02: every run caught mid-backup read "not finished since never".
        self.assertIsNone(hc.backup_problem("success", None, self.now, "activating", self.now - 600))
        self.assertTrue(hc.backup_running("activating", self.now - 600, self.now))

    def test_run_past_its_window_is_flagged_as_stuck(self):
        self.assertIn("running since", hc.backup_problem("success", None, self.now, "activating", self.now - 3 * 3600))
        self.assertFalse(hc.backup_running("activating", self.now - 3 * 3600, self.now))
        self.assertFalse(hc.backup_running("inactive", self.now - 600, self.now))


if __name__ == "__main__": unittest.main()
