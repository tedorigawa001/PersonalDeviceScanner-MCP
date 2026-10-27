"""Engine release lookup: opt-in, a warning only, bounded network use, and a cache that cannot be turned against the owner."""
import asyncio
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler

from pc_scanner import dashboard, history, updates
from pc_scanner.core import Scanner, ScannerError, result


def release(tag, day, prerelease=False, draft=False):
    # Shaped like GitHub's answer, which also carries notes and assets.
    return {"tag_name": tag, "published_at": f"{day}T17:00:00Z", "prerelease": prerelease, "draft": draft,
            "body": "Release notes", "assets": []}


# Modelled on the real lists of 2026-10-18.
OSQUERY = [release("5.24.0", "2026-10-09", prerelease=True), release("5.23.1", "2026-06-24"),
           release("5.23.0", "2026-04-25"), release("5.22.1", "2026-02-25")]
CLAMAV = [release("clamav-1.5.4", "2026-08-07"), release("clamav-1.4.6", "2026-08-07"),
          release("clamav-1.5.3", "2026-07-01"), release("clamav-1.4.5", "2026-07-01"),
          release("clamav-1.5.2", "2026-03-04"), release("clamav-1.4.4", "2026-03-04"),
          release("clamav-1.5.1", "2025-10-16"), release("clamav-1.5.0", "2025-10-07"),
          release("clamav-1.5.0-rc", "2025-08-20", prerelease=True), release("clamav-1.4.3", "2025-06-18")]
SDK = """<?xml version='1.0' encoding='utf-8'?>
<sdk:sdk-repository xmlns:sdk="http://schemas.android.com/sdk/android/repo/repository2/03"
    xmlns:generic="http://schemas.android.com/repository/android/generic/02"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <channel id="channel-0">stable</channel>
  <channel id="channel-1">beta</channel>
  <remotePackage path="platform-tools">
    <type-details xsi:type="generic:genericDetailsType"/>
    <revision><major>37</major><minor>0</minor><micro>1</micro></revision>
    <display-name>Android SDK Platform-Tools</display-name>
    <channelRef ref="channel-0"/>
  </remotePackage>
  <remotePackage path="platform-tools">
    <revision><major>38</major><minor>0</minor><micro>0</micro></revision>
    <channelRef ref="channel-1"/>
  </remotePackage>
  <remotePackage path="build-tools;40.0.0">
    <revision><major>40</major><minor>0</minor><micro>0</micro></revision>
    <channelRef ref="channel-0"/>
  </remotePackage>
</sdk:sdk-repository>"""
BODIES = {"osquery": json.dumps(OSQUERY).encode(), "clamav": json.dumps(CLAMAV).encode(), "adb": SDK.encode()}
OUTPUTS = {"osquery": "osqueryd version 5.22.1\n",
           "clamav": "ClamAV 1.4.5/27800/Sat Oct 17 09:30:00 2026\n",
           "adb": "Android Debug Bridge version 1.0.41\nVersion 37.0.1-14181417\n"
                  "Installed as /Users/owner/Library/Android/sdk/platform-tools/adb\nRunning on Darwin 25.6.0 (arm64)\n"}


class Network:
    """Stands in for the release lists; records what was asked for."""

    def __init__(self, bodies=None, error=None):
        self.bodies = BODIES if bodies is None else bodies
        self.error = error
        self.urls = []

    def __call__(self, url, cancel):
        self.urls.append(url)
        if self.error is not None:
            raise self.error
        engine = next(engine for engine, address in updates.RELEASES.items() if address == url)
        return self.bodies[engine]


class UpdateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.cache = history.releases_file(self.folder / "history.jsonl")
        self.outputs = dict(OUTPUTS)
        self.versions = self.enterContext(patch("pc_scanner.updates.run_bounded", side_effect=self.engine_output))

    def engine_output(self, argv, timeout, limit, cancel=None):
        self.assertLessEqual(timeout, updates.VERSION_SECONDS)
        engine = {"-S": "osquery", "--version": "clamav", "version": "adb"}[argv[1]]
        return 0, self.outputs[engine], ""

    def scanner(self, lookup=True, **sections):
        config = {"local": {"osquery_binary": sys.executable, "clamav_binary": sys.executable},
                  "android": {"adb_binary": sys.executable}, "android_devices": {"phone": "SERIAL1"},
                  "scan_roots": {"test": str(self.folder)},
                  # The cache sits beside the history, so tests never touch the owner's own.
                  "history": {"file": str(self.folder / "history.jsonl")}, **sections}
        if lookup is not None:
            config["updates"] = {"lookup": lookup}
        return Scanner(config)

    def check(self, scanner, operation="inventory", network=None, cancel=None):
        report = result("osquery", "completed", data={})
        with patch("pc_scanner.updates.https", network or Network()):
            updates.check(scanner, operation, report, cancel)
        return report

    def write_cache(self, **entries):
        self.cache.write_text(json.dumps({"version": 1, **entries}))

    def ago(self, **delta):
        return (datetime.now(timezone.utc) - timedelta(**delta)).isoformat(timespec="seconds")

    # --- Off by default ---------------------------------------------------------------------

    def test_off_by_default_nothing_is_run_or_looked_up(self):
        for scanner in (self.scanner(lookup=None), self.scanner(lookup=False)):
            network = Network()
            with patch("pc_scanner.updates.https", network), \
                    patch("pc_scanner.core.run_bounded", return_value=(0, '[{"name":"OS"}]', "")):
                report = scanner.invoke("inventory", query_id="os_version")
            self.assertEqual(report["status"], "completed")
            self.assertNotIn("engine_update", report["data"])
            self.assertEqual(network.urls, [])
            self.versions.assert_not_called()
            self.assertFalse(scanner.invoke("status")["data"]["update_lookup"])
        self.assertFalse(self.cache.exists())

    def test_setting_must_be_true_or_false_and_misspellings_are_warned(self):
        with self.assertRaises(ScannerError):
            self.scanner(lookup="yes")
        with self.assertRaises(ScannerError):
            Scanner({"updates": "on"})
        scanner = self.scanner(lookup=None, updates={"lookups": True})
        self.assertIn("did you mean 'updates.lookup'?", " ".join(scanner.config_warnings))
        self.assertTrue(self.scanner().invoke("status")["data"]["update_lookup"])

    # --- Each scan compares its own engine ---------------------------------------------------

    def test_each_scan_compares_its_engine_and_keeps_its_status(self):
        cases = {"inventory": ("inventory", "osquery", ["-S", "--version"], {"query_id": "os_version"}),
                 "malware": ("malware", "clamav", ["--version"], {"root_alias": "test"}),
                 "android": ("android_collect", "adb", ["version"], {"device_alias": "phone", "query_id": "device"}),
                 "android_check": ("android_check", "adb", ["version"], {"device_alias": "phone"})}
        for operation, (method, engine, tail, arguments) in cases.items():
            with self.subTest(operation=operation):
                self.versions.reset_mock()
                self.cache.unlink(missing_ok=True)
                network = Network()
                with patch.object(Scanner, method, return_value=result("x", "completed", data={})), \
                        patch("pc_scanner.updates.https", network):
                    report = self.scanner().invoke(operation, **arguments)
                self.assertEqual(report["status"], "completed")
                self.assertEqual(self.versions.call_args.args[0][1:], tail)
                info = report["data"]["engine_update"]
                self.assertEqual((info["engine"], info["status"]), (engine, "outdated" if engine != "adb" else "current"))
                self.assertEqual(network.urls, [updates.RELEASES[engine]])
                if engine != "adb":
                    self.assertTrue(any(updates.UPDATE_FROM[engine] in w for w in report["warnings"]))

    def test_wazuh_router_and_status_are_not_compared(self):
        scanner = self.scanner()
        network = Network()
        with patch("pc_scanner.updates.https", network):
            scanner.invoke("status")
            with patch.object(Scanner, "vulnerabilities", return_value=result("wazuh", "completed", data={})):
                report = scanner.invoke("vulnerabilities")
        self.assertNotIn("engine_update", report["data"])
        self.assertEqual(network.urls, [])

    def test_failed_scans_are_not_compared(self):
        network = Network()
        with patch("pc_scanner.updates.https", network), patch("pc_scanner.core.run_bounded", return_value=(1, "", "")):
            report = self.scanner().invoke("inventory", query_id="os_version")
        self.assertEqual(report["status"], "error")
        self.assertEqual(network.urls, [])
        self.versions.assert_not_called()

    def test_outdated_osquery_is_a_warning_with_where_to_update(self):
        with patch("pc_scanner.core.run_bounded", return_value=(0, '[{"name":"OS"}]', "")), \
                patch("pc_scanner.updates.https", Network()):
            report = self.scanner().invoke("inventory", query_id="os_version")
        self.assertEqual(report["status"], "completed")
        self.assertIn("osquery 5.22.1 is older than the latest release, 5.23.1; update it from "
                      "https://osquery.io/downloads/", report["warnings"])
        info = report["data"]["engine_update"]
        self.assertEqual({key: info[key] for key in ("installed", "latest", "status", "source")},
                         {"installed": "5.22.1", "latest": "5.23.1", "status": "outdated",
                          "source": "GitHub releases of osquery/osquery"})
        self.assertIsNotNone(datetime.fromisoformat(info["checked_at"]).tzinfo)

    def test_current_and_newer_engines_get_no_warning(self):
        for output, status in (("osqueryi version 5.23.1", "current"), ("osqueryd version 5.24.0", "newer")):
            with self.subTest(output=output):
                self.outputs["osquery"] = output
                report = self.check(self.scanner())
                self.assertEqual(report["data"]["engine_update"]["status"], status)
                self.assertEqual(report["warnings"], [])

    def test_unreadable_version_is_said_and_nothing_is_looked_up(self):
        for output in ("", "osquery 5.23.1 (no marker)", "osqueryi version five"):
            with self.subTest(output=output):
                self.outputs["osquery"] = output
                network = Network()
                report = self.check(self.scanner(), network=network)
                self.assertEqual(report["data"]["engine_update"]["status"], "unknown")
                self.assertEqual(network.urls, [])
                self.assertIn("The osquery version could not be read; it was not compared with the latest release",
                              report["warnings"])

    def test_version_command_failure_is_a_warning(self):
        self.versions.side_effect = ScannerError("Engine timed out")
        report = self.check(self.scanner())
        self.assertEqual(report["data"]["engine_update"]["status"], "unknown")
        self.assertIn("could not be read", report["warnings"][0])

    def test_adb_output_path_never_reaches_the_report(self):
        report = self.check(self.scanner(), "android")
        self.assertEqual(report["data"]["engine_update"]["installed"], "37.0.1")
        self.assertNotIn("/Users/owner", json.dumps(report))

    # --- What counts as the latest ------------------------------------------------------------

    def test_pre_releases_drafts_and_list_order_do_not_decide_the_latest(self):
        listed = [release("5.22.1", "2026-02-25"), release("5.25.0", "2026-10-10", draft=True),
                  release("5.24.0", "2026-10-09", prerelease=True), release("5.23.1", "2026-06-24")]
        with patch("pc_scanner.updates.https", Network(bodies={"osquery": json.dumps(listed).encode()})):
            self.assertEqual(updates.lookup("osquery", None), {"latest": "5.23.1"})

    def test_hostile_or_odd_tags_are_ignored(self):
        listed = [release("5.99.0‮", "2026-10-10"), release("5.98.0 <img src=x>", "2026-10-10"),
                  {"tag_name": 5, "published_at": "2026-10-10T00:00:00Z", "draft": False, "prerelease": False},
                  {"tag_name": "5.97.0", "published_at": "2026-10-10T00:00:00", "draft": False, "prerelease": False},
                  {"tag_name": "5.96.0", "published_at": "yesterday", "draft": False, "prerelease": False},
                  {"tag_name": "5.95.0", "published_at": "2026-10-10T00:00:00Z"},
                  release("clamav-1.5.4", "2026-08-07"), "text", release("5.23.1", "2026-06-24")]
        found = updates.github_releases(json.dumps(listed).encode(), "osquery")
        self.assertEqual([updates.shown(parts) for parts, _ in found], ["5.23.1"])
        for body in (b"{}", b"not json", b"[" * 100000, json.dumps(listed[:6]).encode()):
            with self.subTest(body=body[:10]), self.assertRaises(updates.Unavailable):
                updates.github_releases(body, "osquery")

    def test_clamav_lines_and_the_latest_release_round(self):
        found = updates.github_releases(BODIES["clamav"], "clamav")
        self.assertEqual(updates.clamav_lines(found), {
            "newest": "1.5.4", "lines": {"1.5": "1.5.4", "1.4": "1.4.6"}, "updated_lines": ["1.5", "1.4"],
            "round": "2026-08-07"})

    def test_clamav_is_compared_within_its_line(self):
        entry = {"checked_at": self.ago(hours=1), **updates.clamav_lines(updates.github_releases(BODIES["clamav"], "clamav"))}
        cases = [((1, 4, 5), "", "outdated", "ClamAV 1.4.5 is older than 1.4.6, the latest release of ClamAV 1.4"),
                 ((1, 4, 6), "", "current", None), ((1, 5, 4), "", "current", None),
                 ((1, 5, 4), "-rc", "outdated", "ClamAV 1.5.4-rc is older than 1.5.4"),
                 ((1, 0, 9), "", "outdated", "ClamAV 1.0 has no release among the latest ten (the newest is 1.5.4); "
                                             "it may no longer be supported"),
                 ((1, 6, 0), "", "newer", None)]
        for current, test_release, status, warning in cases:
            with self.subTest(current=current, test_release=test_release):
                info, warnings = updates.compare("clamav", current, test_release, entry)
                self.assertEqual(info["status"], status)
                if warning:
                    self.assertTrue(warnings and warnings[0].startswith(warning), warnings)
                else:
                    self.assertEqual(warnings, [])
        self.assertIsNone(updates.compare("clamav", (1, 6, 0), "", entry)[0]["line_updated"])
        self.assertTrue(updates.compare("clamav", (1, 4, 6), "", entry)[0]["line_updated"])

    def test_a_line_left_out_of_the_latest_round_is_warned_about(self):
        listed = [release("clamav-1.5.4", "2026-08-07"), release("clamav-1.4.6", "2026-08-08"),
                  release("clamav-1.3.9", "2026-07-01"), release("clamav-1.5.3", "2026-07-01")]
        entry = {"checked_at": self.ago(hours=1),
                 **updates.clamav_lines(updates.github_releases(json.dumps(listed).encode(), "clamav"))}
        # A day apart (time zones) is still one round.
        self.assertEqual((entry["updated_lines"], entry["round"]), (["1.5", "1.4"], "2026-08-08"))
        info, warnings = updates.compare("clamav", (1, 3, 9), "", entry)
        self.assertEqual((info["status"], info["line_updated"]), ("outdated", False))
        self.assertEqual(warnings, ["ClamAV 1.3 was not updated in the latest release round (2026-08-08, for 1.5, "
                                    "1.4); it may no longer be supported. The newest release is 1.5.4"])

    def test_the_newest_line_counts_as_updated_without_a_patch_in_the_round(self):
        # 1.6 already had the fix, so only the older lines were patched.
        listed = [release("clamav-1.5.4", "2026-08-07"), release("clamav-1.4.6", "2026-08-07"),
                  release("clamav-1.6.0", "2026-07-01")]
        lines = updates.clamav_lines(updates.github_releases(json.dumps(listed).encode(), "clamav"))
        self.assertEqual((lines["newest"], lines["updated_lines"]), ("1.6.0", ["1.6", "1.5", "1.4"]))

    def test_a_clamav_test_release_is_older_than_its_release(self):
        self.outputs["clamav"] = "ClamAV 1.4.6-rc/27800/Sat Oct 17 09:30:00 2026\n"
        report = self.check(self.scanner(), "malware")
        info = report["data"]["engine_update"]
        self.assertEqual((info["installed"], info["status"]), ("1.4.6-rc", "outdated"))
        self.assertTrue(report["warnings"][0].startswith("ClamAV 1.4.6-rc is older than 1.4.6"))
        # Only ClamAV marks test releases this way; osquery's text after the number is not one.
        self.outputs["osquery"] = "osqueryi version 5.23.1-rc"
        self.assertEqual(self.check(self.scanner())["data"]["engine_update"]["installed"], "5.23.1")

    def test_without_a_shared_round_nothing_is_said_about_lines(self):
        listed = [release("clamav-1.5.4", "2026-08-07"), release("clamav-1.5.3", "2026-07-01"),
                  release("clamav-1.4.6", "2026-05-01")]
        entry = {"checked_at": self.ago(hours=1),
                 **updates.clamav_lines(updates.github_releases(json.dumps(listed).encode(), "clamav"))}
        self.assertEqual((entry["updated_lines"], entry["round"]), (None, None))
        info, warnings = updates.compare("clamav", (1, 4, 6), "", entry)
        self.assertEqual((info["status"], info["line_updated"], warnings), ("current", None, []))

    def test_platform_tools_is_the_stable_revision(self):
        self.assertEqual(updates.platform_tools(BODIES["adb"]), "37.0.1")
        beta_only = SDK.replace('<channelRef ref="channel-0"/>\n  </remotePackage>\n  <remotePackage path="platform',
                                '<channelRef ref="channel-2"/>\n  </remotePackage>\n  <remotePackage path="platform')
        doctype = SDK.replace("<sdk:sdk-repository", '<!DOCTYPE x [<!ENTITY a "b">]>\n<sdk:sdk-repository', 1)
        odd = SDK.replace("<micro>1</micro>", "<micro>1a</micro>")
        for body in (beta_only, doctype, odd, "<x/>", "not xml"):
            with self.subTest(body=body[:40]), self.assertRaises(updates.Unavailable):
                updates.platform_tools(body.encode())

    # --- Requests --------------------------------------------------------------------------

    def test_requests_go_only_to_the_fixed_sources_without_proxy_or_redirect(self):
        seen = []

        def fetch(opener, handler, request, budget, limit, cancel, service):
            seen.append((request, opener, budget, limit, service))
            return b""

        # A proxy set for other programs is not used: the requests go straight to the source.
        with patch("pc_scanner.updates.fetch_bounded", side_effect=fetch), \
                patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy.invalid:1", "https_proxy": "http://proxy.invalid:1"}):
            for engine in updates.RELEASES:
                updates.https(updates.RELEASES[engine], None)
        self.assertEqual([r.full_url for r, *_ in seen], list(updates.RELEASES.values()))
        for request, opener, budget, limit, service in seen:
            self.assertTrue(request.full_url.startswith(("https://api.github.com/repos/", "https://dl.google.com/")))
            self.assertEqual(request.get_header("User-agent"), "personal-device-scanner-mcp")
            self.assertEqual((budget, limit), (updates.LOOKUP_SECONDS, updates.MAX_RESPONSE_BYTES))
            self.assertFalse([h for h in opener.handlers if isinstance(h, ProxyHandler)])
            self.assertTrue(any(type(h).__name__ == "NoRedirect" for h in opener.handlers))
            github = service == "GitHub"
            self.assertEqual(request.get_header("Accept") == "application/vnd.github+json", github)
        self.assertEqual([s for *_, s in seen], ["GitHub", "GitHub", "Google"])

    def test_failures_are_named_in_fixed_words(self):
        cases = [(HTTPError("https://api.github.com/", 403, "rate limit <b>", {}, None), "HTTP 403"),
                 (ScannerError("GitHub did not finish answering within 15 seconds"), "no complete answer"),
                 (URLError("dns"), "connection failed"), (http.client.IncompleteRead(b"x"), "connection failed"),
                 (ConnectionResetError(), "connection failed")]
        for error, reason in cases:
            with self.subTest(reason=reason):
                self.cache.unlink(missing_ok=True)
                report = self.check(self.scanner(), network=Network(error=error))
                self.assertIn(f"The latest osquery release could not be checked ({reason}); the installed version "
                              "5.22.1 was not compared", report["warnings"])
                self.assertEqual(report["data"]["engine_update"]["status"], "unknown")
        self.cache.unlink()
        report = self.check(self.scanner(), network=Network(bodies={"osquery": b"<html>"}))
        self.assertIn("The latest osquery release could not be checked (unexpected answer); the installed version "
                      "5.22.1 was not compared", report["warnings"])

    def test_a_cancel_adds_nothing_and_is_not_remembered_as_a_failure(self):
        cancel = threading.Event()
        cancel.set()
        report = self.check(self.scanner(), network=Network(error=ScannerError("Scan cancelled")), cancel=cancel)
        self.assertNotIn("engine_update", report["data"])
        self.assertEqual(report["warnings"], [])
        self.assertNotIn("failed_at", self.cache.read_text() if self.cache.exists() else "")

    def test_an_unexpected_failure_keeps_the_scan(self):
        with patch("pc_scanner.updates.check", side_effect=KeyError("boom")), \
                patch("pc_scanner.core.run_bounded", return_value=(0, '[{"name":"OS"}]', "")):
            report = self.scanner().invoke("inventory", query_id="os_version")
        self.assertEqual(report["status"], "completed")
        self.assertIn("The engine version could not be compared with the latest release; the scan itself is "
                      "unaffected", report["warnings"])

    # --- Found in the vulnerability check of 2026-10-19 ------------------------------------

    def test_a_release_list_far_longer_than_asked_for_is_refused_quickly(self):
        # Finding the ClamAV release round took time growing with the square of the list's length.
        listed = [release(f"clamav-1.{n}.0", "2026-01-01") for n in range(updates.MAX_RELEASES + 1)]
        started = time.perf_counter()
        with self.assertRaises(updates.Unavailable):
            updates.github_releases(json.dumps(listed).encode(), "clamav")
        self.assertLess(time.perf_counter() - started, 1)
        self.assertEqual(len(updates.github_releases(json.dumps(listed[:updates.MAX_RELEASES]).encode(), "clamav")),
                         updates.MAX_RELEASES)

    def test_dates_far_from_now_are_skipped_and_the_failure_is_remembered(self):
        # A year-1 date escaped as OverflowError, so no failure was saved and every scan asked again.
        for published in ("0001-01-01T00:00:00+01:00", "0001-01-01T00:00:00+00:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(published=published):
                self.cache.unlink(missing_ok=True)
                body = json.dumps([{**release("clamav-1.5.4", "2026-08-07"), "published_at": published}]).encode()
                network = Network(bodies={"clamav": body})
                for _ in range(3):
                    report = self.check(self.scanner(), "malware", network=network)
                self.assertEqual(len(network.urls), 1)
                self.assertIn("(an earlier attempt failed; it is retried an hour later)", report["warnings"][0])

    def test_an_answer_that_cannot_be_kept_is_a_failure(self):
        # 21 ClamAV lines parse, but the saved form allows 20: it was saved anyway and asked for on every scan.
        listed = [release(f"clamav-1.{n}.0", "2026-08-07") for n in range(21)]
        network = Network(bodies={"clamav": json.dumps(listed).encode()})
        reports = [self.check(self.scanner(), "malware", network=network) for _ in range(3)]
        self.assertEqual(len(network.urls), 1)
        self.assertIn("could not be checked (unexpected answer)", reports[0]["warnings"][0])
        self.assertNotIn("checked_at", json.loads(self.cache.read_text())["clamav"])

    def test_saved_times_and_versions_are_written_out_again_or_refused(self):
        # A saved time is any text that still parses; it reached the AI as written, bidi controls included.
        # strftime gets only ASCII: on Windows, Python 3.11 encodes its format in the system code page.
        now = datetime.now(timezone.utc)
        weird = now.strftime("%Y-%m-%d") + "\u202e" + now.strftime("%H:%M:%S") + "." + "9" * 5000 + "+00:00"
        self.write_cache(osquery={"checked_at": weird, "latest": "5.23.1"})
        network = Network()
        info = self.check(self.scanner(), network=network)["data"]["engine_update"]
        self.assertEqual(network.urls, [])
        self.assertNotIn("\u202e", info["checked_at"])
        self.assertEqual(len(info["checked_at"]), len("2026-10-19T00:00:00+00:00"))
        # Digits of other scripts are not version numbers.
        self.assertFalse(updates.usable("osquery", {"checked_at": self.ago(hours=1), "latest": "\u0665.\u0662.\u0661"}))
        self.outputs["osquery"] = "osqueryi version \u0665.\u0662\u0663.\u0661"
        self.assertIn("could not be read", self.check(self.scanner())["warnings"][0])

    def test_a_clamav_development_build_comes_before_its_release(self):
        self.outputs["clamav"] = "ClamAV 1.5.4-devel-20261001/28157/Sun Oct 18 15:24:14 2026\n"
        report = self.check(self.scanner(), "malware")
        info = report["data"]["engine_update"]
        self.assertEqual((info["installed"], info["status"]), ("1.5.4-devel-20261001", "outdated"))
        self.assertTrue(report["warnings"][0].startswith("ClamAV 1.5.4-devel-20261001 is older than 1.5.4"))
        self.outputs["clamav"] = "ClamAV 1.6.0-devel-20261001/28157/x\n"
        self.assertEqual(self.check(self.scanner(), "malware")["data"]["engine_update"]["status"], "newer")

    def test_with_the_history_off_nothing_is_written(self):
        scanner = self.scanner(history={"file": str(self.folder / "history.jsonl"), "enabled": False})
        network = Network()
        for _ in range(2):
            report = self.check(scanner, network=network)
        self.assertEqual(report["data"]["engine_update"]["status"], "outdated")
        self.assertEqual(len(network.urls), 1)  # this process remembers
        self.assertEqual(list(self.folder.iterdir()), [])

    # --- Kept for a day --------------------------------------------------------------------

    def test_found_releases_are_kept_for_a_day(self):
        network = Network()
        self.check(self.scanner(), network=network)
        self.check(self.scanner(), network=network)
        self.assertEqual(len(network.urls), 1)
        saved = json.loads(self.cache.read_text())
        self.assertEqual((saved["version"], saved["osquery"]["latest"]), (1, "5.23.1"))
        if os.name != "nt":
            self.assertEqual(self.cache.stat().st_mode & 0o777, 0o600)
        # Each engine keeps its own entry.
        self.check(self.scanner(), "malware", network=network)
        self.assertEqual(set(json.loads(self.cache.read_text())) - {"version"}, {"osquery", "clamav"})
        self.write_cache(osquery={"checked_at": self.ago(hours=25), "latest": "5.23.1"})
        self.check(self.scanner(), network=network)
        self.assertEqual(len(network.urls), 3)

    def test_the_cache_never_takes_the_place_of_the_history(self):
        # Found in review: a history file named like the cache lost a scan to it and was left with a damaged line.
        for name in ("engine-releases.json", "history.jsonl.releases", "history", "scans.html"):
            with self.subTest(name=name):
                path = self.folder / name
                scanner = self.scanner(history={"file": str(path)})
                scanner.via = "cli"
                with patch("pc_scanner.core.run_bounded", return_value=(0, '[{"name":"OS"}]', "")), \
                        patch("pc_scanner.updates.https", Network()):
                    for _ in range(2):
                        scanner.invoke("inventory", query_id="os_version")
                entries, skipped = history.read(path, 100)
                self.assertEqual((len(entries), skipped), (2, 0))
                cache = updates.cache_file(scanner)
                self.assertNotIn(cache, {path, history.older(path), history.lock_file(path),
                                         history.details_folder(path), dashboard.page_file(path)})
                self.assertEqual(json.loads(cache.read_text())["osquery"]["latest"], "5.23.1")

    def test_a_failure_is_retried_an_hour_later(self):
        failing = Network(error=URLError("down"))
        self.check(self.scanner(), network=failing)
        report = self.check(self.scanner(), network=failing)
        self.assertEqual(len(failing.urls), 1)
        self.assertIn("(an earlier attempt failed; it is retried an hour later)", report["warnings"][0])
        self.write_cache(osquery={"failed_at": self.ago(minutes=61)})
        network = Network()
        report = self.check(self.scanner(), network=network)
        self.assertEqual((len(network.urls), report["data"]["engine_update"]["status"]), (1, "outdated"))
        self.assertNotIn("failed_at", json.loads(self.cache.read_text())["osquery"])

    def test_older_information_is_used_with_its_date_when_a_lookup_fails(self):
        checked = self.ago(days=3)
        self.write_cache(osquery={"checked_at": checked, "latest": "5.23.1"})
        report = self.check(self.scanner(), network=Network(error=URLError("down")))
        self.assertEqual(report["data"]["engine_update"]["status"], "outdated")
        self.assertIn(f"The latest osquery release could not be checked again (connection failed); compared with "
                      f"the information from {checked[:10]}", report["warnings"])
        self.assertIn("osquery 5.22.1 is older than the latest release", " ".join(report["warnings"]))
        # Kept for the next time, with when it failed.
        self.assertEqual(set(json.loads(self.cache.read_text())["osquery"]), {"checked_at", "latest", "failed_at"})

    def test_information_older_than_a_month_is_not_used(self):
        self.write_cache(osquery={"checked_at": self.ago(days=31), "latest": "5.23.1"})
        report = self.check(self.scanner(), network=Network(error=URLError("down")))
        self.assertEqual(report["data"]["engine_update"]["status"], "unknown")

    def test_times_in_the_future_or_damaged_entries_are_looked_up_again(self):
        future = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        damaged = [{"checked_at": future, "latest": "5.23.1"}, {"checked_at": self.ago(hours=1), "latest": "5.23.1<b>"},
                   {"checked_at": self.ago(hours=1), "latest": 5}, {"checked_at": "soon", "latest": "5.23.1"},
                   {"checked_at": self.ago(hours=1)[:19], "latest": "5.23.1"}, "text", None]
        for entry in damaged:
            with self.subTest(entry=entry):
                self.write_cache(osquery=entry)
                network = Network()
                report = self.check(self.scanner(), network=network)
                self.assertEqual(len(network.urls), 1)
                self.assertEqual(report["data"]["engine_update"]["latest"], "5.23.1")

    def test_damaged_clamav_entries_are_looked_up_again(self):
        good = {"checked_at": self.ago(hours=1), "newest": "1.5.4", "lines": {"1.5": "1.5.4", "1.4": "1.4.6"},
                "updated_lines": ["1.5", "1.4"], "round": "2026-08-07"}
        self.assertTrue(updates.usable("clamav", good))
        damaged = [{"lines": {"1.5": "1.4.6", "1.4": "1.4.6"}}, {"lines": {"1.5‮": "1.5.4"}}, {"lines": {}},
                   {"lines": {f"1.{n}": f"1.{n}.0" for n in range(21)}}, {"updated_lines": ["2.0"]},
                   {"updated_lines": None}, {"round": "08/07/2026"}, {"newest": "latest"}, {"lines": ["1.5"]}]
        for change in damaged:
            with self.subTest(change=change):
                self.assertFalse(updates.usable("clamav", {**good, **change}))

    def test_a_damaged_or_foreign_cache_file_is_ignored(self):
        for text in ("not json", json.dumps({"version": 2, "osquery": {"checked_at": self.ago(hours=1),
                                                                         "latest": "5.23.1"}}), "[1]", "x" * 70000):
            with self.subTest(text=text[:20]):
                self.cache.write_text(text)
                network = Network()
                self.check(self.scanner(), network=network)
                self.assertEqual(len(network.urls), 1)

    @unittest.skipIf(os.name == "nt", "POSIX hard links and owners")
    def test_a_hard_link_is_not_read_or_written_through(self):
        other = self.folder / "profile"
        other.write_text(json.dumps({"version": 1, "osquery": {"checked_at": self.ago(hours=1), "latest": "1.0.0"}}))
        os.link(other, self.cache)
        before = other.read_text()
        network = Network()
        report = self.check(self.scanner(), network=network)
        # Not taken as the owner's cache, and replaced rather than written through.
        self.assertEqual((len(network.urls), report["data"]["engine_update"]["latest"]), (1, "5.23.1"))
        self.assertEqual(other.read_text(), before)
        self.assertEqual(self.cache.stat().st_nlink, 1)

    def test_an_unwritable_cache_is_said_and_this_process_remembers(self):
        self.cache.mkdir()
        scanner = self.scanner()
        network = Network()
        report = self.check(scanner, network=network)
        self.assertIn("The latest-release information could not be saved; it is looked up again on the next scan",
                      report["warnings"])
        self.assertEqual(report["data"]["engine_update"]["status"], "outdated")
        self.check(scanner, network=network)
        self.assertEqual(len(network.urls), 1)
        self.assertEqual([p.name for p in self.folder.iterdir() if p.name.endswith(".tmp")], [])

    def test_without_a_home_folder_the_lookup_still_works(self):
        scanner = self.scanner(history={})
        network = Network()
        with patch.object(Scanner, "history_path", side_effect=ScannerError("Cannot find the home folder")):
            report = self.check(scanner, network=network)
            self.check(scanner, network=network)
        self.assertEqual(report["data"]["engine_update"]["status"], "outdated")
        self.assertEqual(len(network.urls), 1)

    # --- The AI client is told -------------------------------------------------------------

    def test_engine_tools_are_open_world_only_with_the_lookup(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server

        engines = {"collect_inventory", "scan_malware", "collect_android", "check_android_monitoring_apps", "rescan_malware_targets"}

        async def hints(scanner):
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                return {t.name: t.annotations.openWorldHint for t in (await session.list_tools()).tools}

        on, off = asyncio.run(hints(self.scanner())), asyncio.run(hints(self.scanner(lookup=False)))
        self.assertEqual({name for name, hint in on.items() if hint}, engines | {"get_vulnerabilities"})
        self.assertEqual({name for name, hint in off.items() if hint}, {"get_vulnerabilities"})


if __name__ == "__main__":
    unittest.main()
