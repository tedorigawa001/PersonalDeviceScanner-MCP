"""Kept details and the dashboard page: opt-in, private, bounded, and safe to open in a browser."""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pc_scanner import cli, dashboard, history
from pc_scanner.core import Scanner, ScannerError, encode_cursor, result

HOSTILE = "<img src=x onerror=alert(1)>"
SORT = [9.8, "CVE-2026-1000", "openssl", "3.0.2", "amd64", "deb", ""]


class DetailsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.file = self.root / "state" / "history.jsonl"
        self.folder = history.details_folder(self.file)

    def scanner(self, **settings):
        scanner = Scanner({"scan_roots": {"downloads": str(self.root)},
                           "history": {"file": str(self.file), **settings}})
        scanner.via = "cli"
        return scanner

    def scan(self, scanner, report, relative_path="."):
        with patch.object(scanner, "malware", return_value=report):
            return scanner.invoke("malware", root_alias="downloads", relative_path=relative_path)

    def kept(self):
        return sorted(self.folder.iterdir()) if self.folder.exists() else []

    def test_details_are_kept_only_when_turned_on(self):
        report = result("clamav", "partial", findings=[{"kind": "malware", "severity": "high", "path": "a.exe",
                                                        "signature": "Win.Test.EICAR"}])
        self.scan(self.scanner(), report)
        self.assertEqual(self.kept(), [])
        self.assertIsNone(history.read(self.file, 5)[0][0]["details"])
        returned = self.scan(self.scanner(details=True), report)
        [kept] = self.kept()
        entry = history.read(self.file, 5)[0][-1]
        self.assertTrue(history.DETAILS_ID.fullmatch(entry["details"]))
        self.assertEqual(kept.name, entry["details"] + ".json")
        self.assertEqual(json.loads(kept.read_text()), returned)
        self.assertEqual(history.load_details(self.file, entry["details"]), (returned, ""))
        self.assertNotIn("a.exe", self.file.read_text())
        if os.name != "nt":
            self.assertEqual(kept.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.folder.stat().st_mode & 0o777, 0o700)

    def test_text_that_cannot_be_encoded_is_still_kept(self):
        report = result("clamav", "completed", data={"name": "\ud800 ‮"})
        self.scan(self.scanner(details=True), report)
        [kept] = self.kept()
        self.assertEqual(json.loads(kept.read_text())["data"], {"name": "\ud800 ‮"})

    def test_oldest_details_go_first_and_the_newest_always_stays(self):
        ids = []
        for n in range(6):
            history.append(self.file, {"n": n}, {"data": "x" * 200}, 700)
            ids.append(json.loads(self.file.read_text().splitlines()[-1])["details"])
        names = [path.stem for path in self.kept()]
        self.assertEqual(names, ids[-len(names):])
        self.assertLessEqual(sum(path.stat().st_size for path in self.kept()), 700)
        self.assertEqual(history.load_details(self.file, ids[0]), (None, "removed"))
        # One result larger than the limit is still kept, alone.
        history.append(self.file, {"n": 6}, {"data": "x" * 2000}, 700)
        self.assertEqual(len(self.kept()), 1)
        # Other files in the folder are never removed.
        (self.folder / "notes.txt").write_text("mine")
        history.append(self.file, {"n": 7}, {"data": "x" * 2000}, 700)
        self.assertTrue((self.folder / "notes.txt").exists())

    def test_the_details_folder_is_private_and_a_link_is_refused(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions and links")
        self.file.parent.mkdir()
        self.folder.mkdir(mode=0o755)
        self.folder.chmod(0o755)
        self.scan(self.scanner(details=True), result("clamav", "completed"))
        self.assertEqual(self.folder.stat().st_mode & 0o777, 0o700)
        for child in self.kept():
            child.unlink()
        self.folder.rmdir()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        self.folder.symlink_to(elsewhere)
        report = self.scan(self.scanner(details=True), result("clamav", "completed"))
        self.assertIn("Scan history could not be written; the scan itself is unaffected", report["warnings"])
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_failed_write_leaves_no_partial_file(self):
        with patch.object(history, "open", create=True, side_effect=OSError("disk full")):
            report = self.scan(self.scanner(details=True), result("clamav", "completed"))
        self.assertIn("Scan history could not be written; the scan itself is unaffected", report["warnings"])
        self.assertEqual(self.kept(), [])

    def test_damaged_or_missing_details_are_reported_not_raised(self):
        self.folder.mkdir(parents=True)
        names = {"20261016T000000.000000Z-0000000a": "{not json", "20261016T000000.000000Z-0000000b": "[1, 2]",
                 "20261016T000000.000000Z-0000000c": "[" * 100000}
        for name, text in names.items():
            (self.folder / f"{name}.json").write_text(text)
        for name in names:
            self.assertEqual(history.load_details(self.file, name), (None, "unreadable"))
        self.assertEqual(history.load_details(self.file, "../../etc/passwd"), (None, "unreadable"))
        self.assertEqual(history.load_details(self.file, "20261016T000000.000000Z-0000000d"), (None, "removed"))
        self.assertEqual(history.load_details(self.file, None), (None, "off"))
        with patch.object(history, "MAX_DETAILS_BYTES", 10):
            (self.folder / "20261016T000000.000000Z-0000000e.json").write_text('{"data": "' + "x" * 20 + '"}')
            self.assertEqual(history.load_details(self.file, "20261016T000000.000000Z-0000000e"), (None, "unreadable"))
            # Refused by its size, even though its start alone would read as a result.
            (self.folder / "20261016T000000.000000Z-00000011.json").write_text('{"a": 1}' + " " * 100)
            self.assertEqual(history.load_details(self.file, "20261016T000000.000000Z-00000011"), (None, "unreadable"))
        if os.name != "nt":
            os.mkfifo(self.folder / "20261016T000000.000000Z-0000000f.json")
            self.assertEqual(history.load_details(self.file, "20261016T000000.000000Z-0000000f"), (None, "unreadable"))
            # A link in place of a kept result is not followed into another file.
            other = self.root / "other.json"
            other.write_text('{"data": "not a result"}')
            (self.folder / "20261016T000000.000000Z-00000010.json").symlink_to(other)
            self.assertEqual(history.load_details(self.file, "20261016T000000.000000Z-00000010"), (None, "unreadable"))

    def test_an_edited_details_reference_is_ignored(self):
        self.file.parent.mkdir()
        line = {"version": 1, "started_at": "2026-10-16T00:00:00+00:00", "seconds": 1, "via": "cli",
                "operation": "malware", "target": {}, "status": "completed", "findings": {}, "warnings": 0}
        self.file.write_text("\n".join(json.dumps({**line, "details": value})
                                       for value in ("../secret", 3, "20261016T000000.000000Z-0000000a")) + "\n")
        entries, skipped = history.read(self.file, 5)
        self.assertEqual(skipped, 0)
        self.assertEqual([entry["details"] for entry in entries], [None, None, "20261016T000000.000000Z-0000000a"])

    def test_settings_are_checked(self):
        for bad in ({"details": "yes"}, {"details_max_mb": 0}, {"details_max_mb": 1025}, {"details_max_mb": 1.5},
                    {"details_max_mb": True}):
            with self.subTest(bad=bad), self.assertRaises(ScannerError):
                Scanner({"history": bad})
        scanner = Scanner({"history": {"details": True, "details_max_mb": 1}})
        self.assertEqual((scanner.history_details, scanner.history_details_mb, scanner.config_warnings), (True, 1, []))
        self.assertIn("history.details has no effect while history.enabled = false",
                      Scanner({"history": {"enabled": False, "details": True}}).config_warnings)
        self.assertFalse(Scanner({}).history_details)

    def test_the_size_limit_setting_reaches_the_pruning(self):
        scanner = self.scanner(details=True, details_max_mb=3)
        with patch.object(history, "save_details", wraps=history.save_details) as save:
            self.scan(scanner, result("clamav", "completed"))
        self.assertEqual(save.call_args.args[2], 3 * 1024 * 1024)


class DashboardTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.file = self.root / "state" / "history.jsonl"
        self.scanner = Scanner({"scan_roots": {"downloads": str(self.root)}, "android_devices": {"phone": "R58"},
                                "history": {"file": str(self.file), "details": True}})
        self.scanner.via = "mcp"

    def run_scan(self, operation, method, report, **arguments):
        with patch.object(self.scanner, method, return_value=report):
            return self.scanner.invoke(operation, **arguments)

    def build(self, limit=100):
        page, _ = dashboard.build(self.file, limit, True, True, 50)
        return page, page.read_text(encoding="utf-8")

    def test_the_page_shows_details_safely_and_privately(self):
        self.run_scan("malware", "malware", result("clamav", "partial", findings=[
            {"kind": "malware", "severity": "high", "path": "請求書‮exe.pdf", "signature": HOSTILE},
            {"kind": "scan_limit", "severity": "<b>", "path": None, "extra": {"nested": [1, "</td>"]}}],
            warnings=[HOSTILE], data={"text": "line‮<script>"}), root_alias="downloads", relative_path=HOSTILE)
        self.run_scan("android_check", "android_check", result("adb", "completed"), device_alias="phone")
        page, text = self.build()
        self.assertEqual(page, self.file.with_suffix(".html"))
        if os.name != "nt":
            self.assertEqual(page.stat().st_mode & 0o777, 0o600)
        # Nothing from a result becomes markup, and nothing can run or load.
        self.assertNotIn("<img", text)
        self.assertNotIn("<script", text)
        self.assertNotIn("<b>", text.split("</style>", 1)[1].replace("<b>partial</b>", "").replace("<b>error</b>", ""))
        self.assertNotIn("</td>\"", text)
        self.assertNotIn("‮", text)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", text)
        self.assertIn("請求書\\u202eexe.pdf", text)
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', text).group(1)
        style = base64.b64encode(hashlib.sha256(dashboard.STYLE.encode()).digest()).decode()
        self.assertEqual(csp, f"default-src 'none'; style-src 'sha256-{style}'; base-uri 'none'; form-action 'none'")
        self.assertIn(f"<style>{dashboard.STYLE}</style>", text)
        self.assertEqual(len(re.findall(r"<(?:script|link|iframe|object|embed|img|form)\b", text)), 0)
        # A severity outside the known names is shown as text, never as a class.
        self.assertIn('<span class="badge other">&lt;b&gt;</span>', text)
        self.assertIn("No findings in this result.", text)

    def test_scans_without_kept_details_say_why(self):
        self.scanner.history_details = False
        self.run_scan("malware", "malware", result("clamav", "completed"), root_alias="downloads")
        self.scanner.history_details = True
        self.run_scan("malware", "malware", result("clamav", "completed"), root_alias="downloads")
        [kept] = history.details_folder(self.file).iterdir()
        kept.unlink()
        self.run_scan("malware", "malware", result("clamav", "completed"), root_alias="downloads")
        [kept] = history.details_folder(self.file).iterdir()
        kept.write_text("{damaged")
        _, text = self.build()
        for reason in dashboard.REASONS.values():
            self.assertEqual(text.count(reason), 1, reason)

    def wazuh(self, page, findings=0, more=False, status="partial", cursor=None):
        """A Wazuh page; a cursor that names no page stands for a history line from 0.3.0."""
        if cursor is None:
            cursor = "" if page == 1 else encode_cursor(page, SORT)
        report = result("wazuh", status, findings=[{"kind": "vulnerability", "severity": "high"}] * findings,
                        data={"next_cursor": "next" if more else None})
        return self.run_scan("vulnerabilities", "vulnerabilities", report, cursor=cursor)

    def inventory(self, offset, status="partial", next_offset=None, query_id="applications"):
        report = result("osquery", status, data={"next_offset": next_offset} if status != "error" else None)
        if status == "error":
            report = result("osquery", "error", error="timed out")
        return self.run_scan("inventory", "inventory", report, query_id=query_id, offset=offset)

    def latest(self, limit=100):
        return [(dashboard.run_label(run[0][1]), len(run), dashboard.combined(run))
                for run in dashboard.latest_runs(history.read(self.file, limit)[0])]

    def test_findings_on_earlier_pages_still_count_after_a_later_page(self):
        self.wazuh(1, findings=3, more=True)
        self.wazuh(2, findings=0, more=True)
        self.assertEqual(self.latest(), [("configured agent", 2, {"findings": {"high": 3}, "status": "partial"})])
        _, text = self.build()
        row = re.search(r"<tr><td class=\"op\">vulnerabilities</td>.*?</tr>", text).group()
        self.assertIn('href="#scan-0"', row)
        self.assertIn("2 pages", row)
        self.assertIn("more pages remain", row)
        self.assertIn('<span class="badge high">high</span> 3', row)
        # The last page says no page follows.
        self.wazuh(3, findings=1)
        self.assertEqual(self.latest()[0][1:], (3, {"findings": {"high": 4}, "status": "partial"}))
        self.assertNotIn("more pages remain", self.build()[1])

    def test_a_new_first_page_starts_a_new_run(self):
        self.wazuh(1, findings=3, more=True)
        self.wazuh(2, findings=2)
        self.wazuh(1, findings=1)
        self.assertEqual(self.latest(), [("configured agent", 1, {"findings": {"high": 1}, "status": "partial"})])

    def test_a_wazuh_page_fetched_again_replaces_the_earlier_fetch(self):
        # The reported case: 3 on the first page, 1 on the next, the next fetched again.
        self.wazuh(1, findings=3, more=True)
        self.wazuh(2, findings=1)
        self.wazuh(2, findings=1)
        self.assertEqual(self.latest(), [("configured agent", 2, {"findings": {"high": 4}, "status": "partial"})])
        # An earlier page fetched again later still counts once.
        self.wazuh(1, findings=3, more=True)
        self.wazuh(2, findings=1, more=True)
        self.wazuh(3, findings=2)
        self.wazuh(2, findings=1, more=True)
        self.assertEqual(self.latest(), [("configured agent", 3, {"findings": {"high": 6}, "status": "partial"})])
        # Page 3 was the last one, even though page 2 was fetched after it.
        self.assertNotIn("more pages remain", self.build()[1])

    def test_a_wazuh_page_retried_after_an_error_replaces_it(self):
        self.wazuh(1, findings=2, more=True)
        self.wazuh(2, status="error")
        self.assertEqual(self.latest(), [("configured agent", 2, {"findings": {"high": 2}, "status": "error"})])
        self.wazuh(2, findings=1)
        self.assertEqual(self.latest(), [("configured agent", 2, {"findings": {"high": 3}, "status": "partial"})])

    def test_history_lines_from_0_3_0_without_page_numbers(self):
        self.wazuh(1, findings=2, more=True)
        self.wazuh(None, status="error", cursor="old-cursor")
        self.wazuh(None, findings=1, cursor="old-cursor")
        self.assertEqual(self.latest(), [("configured agent", 2, {"findings": {"high": 3}, "status": "partial"})])
        # A failed first page is not replaced: the page after it was not that page again.
        self.wazuh(1, status="error")
        self.wazuh(None, findings=1, cursor="old-cursor")
        self.assertEqual(self.latest(), [("configured agent", 2, {"findings": {"high": 1}, "status": "error"})])

    def test_a_page_fetched_again_replaces_the_failed_attempt_and_the_worst_status_shows(self):
        self.inventory(0, next_offset=500)
        self.inventory(500, status="error")
        self.assertEqual(self.latest(), [("applications", 2, {"findings": {}, "status": "error"})])
        self.inventory(500)
        self.assertEqual(self.latest(), [("applications", 2, {"findings": {}, "status": "partial"})])
        # A page that succeeded, fetched again, still counts once.
        self.inventory(500)
        self.assertEqual(self.latest(), [("applications", 2, {"findings": {}, "status": "partial"})])
        self.inventory(0, status="completed", query_id="os_version")
        self.assertEqual([label for label, _, _ in self.latest()], ["applications", "os_version"])
        # A failed first page stays the worst, even when a later page was fetched after it.
        self.inventory(0, status="error")
        self.inventory(500)
        self.assertEqual(self.latest()[0], ("applications", 2, {"findings": {}, "status": "error"}))

    def test_later_pages_without_their_first_page_are_marked(self):
        self.wazuh(1, findings=3, more=True)
        self.wazuh(2, findings=1)
        self.assertEqual(self.latest(limit=1), [("configured agent", 1, {"findings": {"high": 1}, "status": "partial"})])
        _, text = self.build(limit=1)
        self.assertIn("first page not in the shown history", text)
        _, text = self.build()
        self.assertNotIn("first page not in the shown history", text)

    def test_other_scans_show_their_newest_result(self):
        for findings in (2, 0):
            self.run_scan("malware", "malware", result("clamav", "completed", findings=[
                {"kind": "malware", "severity": "high"}] * findings), root_alias="downloads")
        self.assertEqual(self.latest(), [("downloads", 1, {"findings": {}, "status": "completed"})])
        _, text = self.build()
        self.assertEqual(text.count('<details class="scan panel"'), 2)
        _, text = self.build(limit=1)
        self.assertEqual(text.count('<details class="scan panel"'), 1)

    def test_whether_another_page_follows_is_recorded(self):
        self.wazuh(1, more=True)
        self.wazuh(2)
        self.inventory(0, next_offset=500)
        self.inventory(500, status="error")
        self.run_scan("malware", "malware", result("clamav", "completed"), root_alias="downloads")
        self.assertEqual([entry["more"] for entry in history.read(self.file, 10)[0]], [True, False, True, None, None])
        for kept in (encode_cursor(2, SORT), "CVE-2026-1000", "openssl"):
            self.assertNotIn(kept, self.file.read_text())
        lines = [json.loads(line) for line in self.file.read_text().splitlines()]
        self.assertNotIn("more", lines[-1])
        self.file.write_text(json.dumps({**lines[0], "more": "yes"}) + "\n")
        self.assertIsNone(history.read(self.file, 10)[0][0]["more"])

    def test_large_data_is_cut_and_line_breaks_inside_values_stay_escaped(self):
        self.run_scan("malware", "malware", result("clamav", "completed", data={"a": "x\ny", "b": "z" * 150000}),
                      root_alias="downloads")
        _, text = self.build()
        self.assertIn("&quot;a&quot;: &quot;x\\ny&quot;", text)
        self.assertIn("Cut at 50,000 characters.", text)
        self.assertLess(len(text), 80000)

    def test_an_empty_history_still_gives_a_page(self):
        page, text = self.build()
        self.assertIn("No scans recorded yet.", text)
        self.assertTrue(page.parent.is_dir())

    def test_the_page_name_never_replaces_the_history(self):
        self.assertEqual(dashboard.page_file(Path("/x/history.jsonl")), Path("/x/history.html"))
        self.assertEqual(dashboard.page_file(Path("/x/history")), Path("/x/history.html"))
        self.assertEqual(dashboard.page_file(Path("/x/scans.html")), Path("/x/scans.html.html"))

    def test_the_command_writes_the_page_and_opens_it(self):
        self.run_scan("malware", "malware", result("clamav", "completed"), root_alias="downloads")
        with patch("pc_scanner.cli.webbrowser.open", return_value=True) as opened, \
                patch("sys.stdout") as stdout:
            cli.write_dashboard(self.scanner, 10, True)
        page = self.file.with_suffix(".html")
        opened.assert_called_once_with(page.as_uri())
        self.assertIn(str(page), "".join(call.args[0] for call in stdout.write.call_args_list))
        with patch("pc_scanner.cli.webbrowser.open") as opened, patch("sys.stdout"):
            cli.write_dashboard(self.scanner, 10, False)
        opened.assert_not_called()
        with self.assertRaises(ScannerError):
            cli.write_dashboard(self.scanner, 0, False)

    def test_the_cli_command(self):
        config = self.root / "scanner.toml"
        config.write_text(f"[history]\nfile = {json.dumps(str(self.file))}\n")
        run = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "dashboard",
                              "--no-open"], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), f"Dashboard written to {self.file.with_suffix('.html')}")
        refused = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "dashboard",
                                  "--no-open", "--limit", "1001"], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(refused.returncode, 2)
        self.assertIn("--limit must be 1..1000", json.loads(refused.stdout)["error"])


if __name__ == "__main__":
    unittest.main()
