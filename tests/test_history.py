"""Scan history: summaries only, kept on this PC, read with the history command."""
import asyncio
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pc_scanner import history
from pc_scanner.core import Scanner, ScannerError, encode_cursor, result


ROOT = Path(__file__).resolve().parents[1]
HOLD_LOCK = """
import pathlib, sys
from pc_scanner import history
with history.locked(pathlib.Path(sys.argv[1])):
    print("held", flush=True)
    sys.stdin.readline()
"""


def toml_path(path):
    return json.dumps(str(path))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.file = self.root / "state" / "history.jsonl"

    def scanner(self, via="cli", **settings):
        scanner = Scanner({"scan_roots": {"downloads": str(self.root)}, "android_devices": {"phone": "R58TEST"},
                           "history": {"file": str(self.file), **settings}})
        scanner.via = via
        return scanner

    def records(self):
        return [json.loads(line) for line in self.file.read_text(encoding="utf-8").splitlines()]

    def cli(self, *args, config=None):
        if config is None:
            config = self.root / "scanner.toml"
            config.write_text(f"[scan_roots]\ndownloads = {toml_path(self.root)}\n"
                              f"[history]\nfile = {toml_path(self.file)}\n")
        return subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), *args],
                              capture_output=True, text=True, encoding="utf-8")

    def test_a_scan_is_kept_as_a_summary_without_its_findings(self):
        scanner = self.scanner()
        report = result("clamav", "partial", findings=[
            {"kind": "malware", "severity": "high", "path": "private/plan.exe", "signature": "Win.Test.EICAR"},
            {"kind": "scan_limit", "severity": "unknown", "path": "large.zip", "signature": "Heuristics.Limits"},
            {"kind": "malware", "severity": "odd", "path": "other.bin", "signature": "X"}], warnings=["w1", "w2"])
        with patch.object(scanner, "malware", return_value=report):
            returned = scanner.invoke("malware", root_alias="downloads", relative_path="private")
        self.assertIs(returned, report)
        [record] = self.records()
        self.assertEqual(record["via"], "cli")
        self.assertEqual(record["operation"], "malware")
        self.assertEqual(record["target"], {"root_alias": "downloads", "relative_path": "private"})
        self.assertEqual(record["status"], "partial")
        self.assertEqual(record["findings"], {"high": 1, "unknown": 2})
        self.assertEqual(record["warnings"], 2)
        self.assertNotIn("error", record)
        self.assertLess(abs(datetime.fromisoformat(record["started_at"]) - datetime.now(timezone.utc)).total_seconds(),
                        60)
        text = self.file.read_text(encoding="utf-8")
        for detail in ("plan.exe", "EICAR", "large.zip", "other.bin", "w1"):
            self.assertNotIn(detail, text)

    def test_each_scan_records_what_identifies_its_target(self):
        scanner = self.scanner()
        cursor = encode_cursor(3, [9.8, "CVE-2026-1000", "openssl", "3.0.2", "amd64", "deb", ""])
        calls = {"inventory": {"query_id": "applications", "offset": 500},
                 "vulnerabilities": {"cursor": cursor},
                 "android": {"device_alias": "phone", "query_id": "apps"},
                 "android_check": {"device_alias": "phone"}}
        methods = {"inventory": "inventory", "vulnerabilities": "vulnerabilities", "android": "android_collect",
                   "android_check": "android_check"}
        for operation, arguments in calls.items():
            with patch.object(scanner, methods[operation], return_value=result("x", "completed")):
                scanner.invoke(operation, **arguments, cancel=threading.Event())
        self.assertEqual([record["target"] for record in self.records()], [
            {"query_id": "applications", "offset": 500},
            {"continued": True, "page": 3,
             "after": history.cursor_fingerprint([9.8, "CVE-2026-1000", "openssl", "3.0.2", "amd64", "deb", ""])},
            {"device_alias": "phone", "query_id": "apps"}, {"device_alias": "phone"}])
        # Neither the cursor nor what it names is kept: only the page it leads to.
        for kept in (cursor, "CVE-2026-1000", "openssl"):
            self.assertNotIn(kept, self.file.read_text(encoding="utf-8"))
        with patch.object(scanner, "vulnerabilities", return_value=result("x", "completed")):
            scanner.invoke("vulnerabilities", cursor="")
            scanner.invoke("vulnerabilities", cursor="not a cursor")
        self.assertEqual([record["target"] for record in self.records()[-2:]],
                         [{"continued": False, "page": 1}, {"continued": True}])
        self.assertEqual([history.describe_target(entry) for entry in history.read(self.file, 10)[0]
                          if entry["operation"] == "vulnerabilities"], ["page 3", "first page", "next page"])

    def test_failed_scans_are_kept_with_their_error(self):
        self.scanner().invoke("malware", root_alias="missing")
        [record] = self.records()
        self.assertEqual(record["status"], "error")
        self.assertEqual(record["error"], "Scan root alias is not authorized")
        self.assertEqual(record["target"], {"root_alias": "missing"})

    def test_status_library_use_and_turning_it_off_record_nothing(self):
        self.scanner().invoke("status")
        self.scanner(via=None).invoke("malware", root_alias="missing")
        report = self.scanner(enabled=False).invoke("malware", root_alias="missing")
        self.assertFalse(self.file.exists())
        self.assertFalse(any("history" in warning for warning in report["warnings"]))

    def test_names_from_the_ai_are_cleaned_and_bounded(self):
        self.scanner().invoke("malware", root_alias="a‮b\n", relative_path="x" * 5000)
        [record] = self.records()
        self.assertEqual(record["target"]["root_alias"], "a\\u202eb\\u000a")
        self.assertLess(len(record["target"]["relative_path"]), 1100)

    def test_the_file_is_private_and_a_link_is_refused(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions and links")
        self.scanner().invoke("malware", root_alias="missing")
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.file.parent.stat().st_mode & 0o077, 0)
        target = self.root / "other.txt"
        target.write_text("keep")
        self.file.unlink()
        self.file.symlink_to(target)
        report = self.scanner().invoke("malware", root_alias="missing")
        self.assertEqual(target.read_text(), "keep")
        self.assertIn("Scan history could not be written; the scan itself is unaffected", report["warnings"])

    def test_a_file_that_others_can_read_is_made_private_before_writing(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions")
        self.file.parent.mkdir()
        self.file.write_text("")
        self.file.chmod(0o644)
        self.scanner().invoke("malware", root_alias="missing")
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.records()), 1)
        # A new file is private from the start, so no reader can open it before it is checked.
        created = self.root / "new" / "history.jsonl"
        with patch.object(history, "private"):
            history.append(created, {"n": 1})
        self.assertEqual(created.stat().st_mode & 0o777, 0o600)
        # A FIFO in place of the files is refused at once, with or without a reader, and gets nothing.
        fifo = self.root / "fifo" / "history.jsonl"
        fifo.parent.mkdir()
        os.mkfifo(fifo)
        with self.assertRaises(OSError):
            history.make_private(fifo)
        with self.assertRaises(OSError):
            history.append(fifo, {"n": 1})
        reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
        try:
            with self.assertRaises(OSError):
                history.append(fifo, {"n": 1})
            try:
                received = os.read(reader, 100)
            except BlockingIOError:
                received = b""
            self.assertEqual(received, b"")
        finally:
            os.close(reader)

    def test_a_hard_link_or_another_users_file_is_never_written(self):
        if os.name == "nt":
            self.skipTest("POSIX links and owners")
        # In a folder other users can write to, a hard link could aim the history at the owner's shell profile.
        profile = self.root / "profile.sh"
        profile.write_text("echo hi\n")
        profile.chmod(0o644)
        self.file.parent.mkdir()
        os.link(profile, self.file)
        report = self.scanner().invoke("malware", root_alias="$(id)")
        self.assertIn("Scan history could not be written; the scan itself is unaffected", report["warnings"])
        self.assertEqual((profile.read_text(), profile.stat().st_mode & 0o777), ("echo hi\n", 0o644))
        self.file.unlink()
        fd = os.open(profile, os.O_RDONLY)
        try:
            with self.assertRaisesRegex(OSError, "hard links"):
                os.link(profile, self.root / "second-name")
                history.private(fd)
            with patch.object(history.os, "geteuid", return_value=os.geteuid() + 1), \
                    self.assertRaisesRegex(OSError, "another user"):
                os.unlink(self.root / "second-name")
                history.private(fd)
        finally:
            os.close(fd)

    def test_another_users_lock_file_or_details_folder_is_refused(self):
        if os.name == "nt":
            self.skipTest("POSIX owners")
        self.file.parent.mkdir()
        with patch.object(history.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(OSError, "lock file"):
                with history.locked(self.file):
                    pass
            history.details_folder(self.file).mkdir()
            with self.assertRaisesRegex(OSError, "details folder"):
                history.save_details(self.file, {"data": 1}, 1000)

    def test_reading_follows_no_link_and_never_waits_on_a_fifo(self):
        if os.name == "nt":
            self.skipTest("POSIX links and FIFOs")
        self.file.parent.mkdir()
        elsewhere = self.root / "elsewhere.jsonl"
        elsewhere.write_text("")
        self.file.symlink_to(elsewhere)
        with self.assertRaises(OSError):
            history.read(self.file, 5)
        self.file.unlink()
        os.mkfifo(self.file)
        started = time.monotonic()
        with self.assertRaises(OSError):
            history.read(self.file, 5)
        self.assertLess(time.monotonic() - started, 5)

    def test_a_time_that_cannot_be_shown_is_a_damaged_line(self):
        self.file.parent.mkdir()
        line = {"version": 1, "started_at": "0001-01-01T00:00:00+14:00", "seconds": 1, "via": "cli",
                "operation": "malware", "target": {}, "status": "completed", "findings": {}, "warnings": 0}
        self.file.write_text(json.dumps(line) + "\n")
        self.assertEqual(history.read(self.file, 5), ([], 1))

    def test_rotated_and_older_files_are_made_private_too(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions")
        self.file.parent.mkdir()
        full = "".join(json.dumps({"n": n}) + "\n" for n in range(20))
        self.file.write_text(full)
        history.older(self.file).write_text("previous\n")
        for name in (self.file, history.older(self.file)):
            name.chmod(0o644)
        with patch.object(history, "FILE_BYTES", 100):
            history.append(self.file, {"n": 20})
        # The full file became the older one, and both are private.
        self.assertEqual(history.older(self.file).read_text(), full)
        for name in (self.file, history.older(self.file)):
            self.assertEqual(name.stat().st_mode & 0o777, 0o600, name.name)
        # An older file that others can read is fixed even when nothing rotates.
        history.older(self.file).chmod(0o604)
        history.append(self.file, {"n": 21})
        self.assertEqual(history.older(self.file).stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.file.read_text().splitlines()), 2)

    def test_processes_take_turns_to_check_rotate_and_write(self):
        self.file.parent.mkdir()
        full = "".join(json.dumps({"n": n}) + "\n" for n in range(20))
        self.file.write_text(full)
        holder = subprocess.Popen([sys.executable, "-c", HOLD_LOCK, str(self.file)], cwd=ROOT, text=True,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            with patch.object(history, "FILE_BYTES", 100), patch.object(history, "LOCK_ATTEMPTS", 3):
                with self.assertRaises(OSError):
                    history.append(self.file, {"n": 20})
                # Neither rotated nor written while the other process holds the lock.
                self.assertFalse(history.older(self.file).exists())
                self.assertEqual(self.file.read_text(), full)
                report = self.scanner().invoke("malware", root_alias="missing")
                self.assertIn("Scan history could not be written; the scan itself is unaffected", report["warnings"])
                # Reading does not need the lock.
                self.assertEqual(history.read(self.file, 5), ([], 20))
        finally:
            holder.communicate("\n", timeout=30)
        self.assertEqual(holder.returncode, 0)
        with patch.object(history, "FILE_BYTES", 100):
            history.append(self.file, {"n": 21})
        self.assertEqual(history.older(self.file).read_text(), full)
        self.assertEqual(self.file.read_text(), json.dumps({"n": 21}) + "\n")

    def test_reading_holds_the_lock_so_no_rotation_falls_between_the_files(self):
        self.scanner().invoke("malware", root_alias="missing")
        held = []
        original = history.locked

        def spy(path):
            held.append(path)
            return original(path)

        with patch.object(history, "locked", spy):
            self.assertEqual(len(history.read(self.file, 5)[0]), 1)
        self.assertEqual(held, [self.file])
        # No folder yet: nothing to read, and nothing is created.
        missing = self.root / "none" / "history.jsonl"
        self.assertEqual(history.read(missing, 5), ([], 0))
        self.assertFalse(missing.parent.exists())

    def test_a_history_that_cannot_be_written_only_adds_a_warning(self):
        (self.root / "state").write_text("not a folder")
        report = self.scanner().invoke("malware", root_alias="missing")
        self.assertEqual(report["error"], "Scan root alias is not authorized")
        self.assertIn("Scan history could not be written; the scan itself is unaffected", report["warnings"])
        with patch("pc_scanner.history.entry", side_effect=KeyError("status")):
            report = self.scanner().invoke("malware", root_alias="missing")
        self.assertEqual(report["status"], "error")
        self.assertIn("Scan history could not be written; the scan itself is unaffected", report["warnings"])

    def test_old_scans_rotate_into_one_older_file(self):
        scanner = self.scanner()
        with patch.object(history, "FILE_BYTES", 600), \
                patch.object(scanner, "inventory", return_value=result("osquery", "completed")):
            for offset in range(30):
                scanner.invoke("inventory", query_id="os_version", offset=offset)
        self.assertTrue(history.older(self.file).exists())
        self.assertLessEqual(self.file.stat().st_size, 600 + 300)
        entries, skipped = history.read(self.file, history.MAX_LIMIT)
        offsets = [entry["target"]["offset"] for entry in entries]
        self.assertEqual(skipped, 0)
        # Both files are read, the older one first.
        self.assertGreater(len(offsets), len(self.file.read_text(encoding="utf-8").splitlines()))
        self.assertEqual(offsets, list(range(30 - len(offsets), 30)))
        self.assertLess(len(offsets), 30)
        self.assertEqual([entry["target"]["offset"] for entry in history.read(self.file, 3)[0]], [27, 28, 29])

    def test_damaged_or_edited_lines_are_skipped_and_shown_safely(self):
        good = {"version": 1, "started_at": "2026-10-15T01:02:03+00:00", "seconds": 1.5, "via": "mcp",
                "operation": "malware", "target": {"root_alias": "downloads", "relative_path": "‮exe.txt"},
                "status": "completed", "findings": {"high": 2}, "warnings": 1}
        bad = [{**good, "started_at": "2026-10-15T01:02:03"}, {**good, "seconds": -1}, {**good, "seconds": "1"},
               {**good, "findings": {"high": -1}}, {**good, "findings": []}, {**good, "via": 3},
               {**good, "warnings": 1.5}, [good], "text"]
        self.file.parent.mkdir()
        self.file.write_text("\n".join([json.dumps(good), "{not json", "[" * 100000, *map(json.dumps, bad),
                                        "", json.dumps({**good, "error": "e\u001b[31m"})]) + "\n",
                             encoding="utf-8")
        entries, skipped = history.read(self.file, 100)
        self.assertEqual(len(entries), 2)
        self.assertEqual(skipped, 2 + len(bad))
        self.assertEqual(entries[0]["target"]["relative_path"], "\\u202eexe.txt")
        self.assertEqual(entries[1]["error"], "e\\u001b[31m")
        shown = history.table(entries)
        self.assertNotIn("‮", shown)
        self.assertNotIn("\u001b", shown)
        self.assertIn("2 (high 2)", shown)
        self.assertIn("downloads/\\u202eexe.txt", shown)

    def test_the_history_command_shows_a_table_or_json(self):
        empty = self.cli("history")
        self.assertEqual(empty.returncode, 0, empty.stderr)
        self.assertIn("No scans recorded yet", empty.stdout)
        self.assertEqual(self.cli("malware", "missing").returncode, 2)
        self.assertEqual(self.cli("malware", "downloads", "sub").returncode, 2)
        shown = self.cli("history")
        self.assertEqual(shown.returncode, 0, shown.stderr)
        lines = shown.stdout.splitlines()
        self.assertEqual(lines[0].split(),
                         ["TIME", "VIA", "OPERATION", "SOURCE", "STATUS", "FINDINGS", "SECONDS", "TARGET"])
        self.assertEqual(lines[1].split()[2:6], ["cli", "malware", "ClamAV", "error"])
        self.assertTrue(lines[1].endswith("missing"))
        self.assertEqual(lines[2].strip(), "error: Scan root alias is not authorized")
        self.assertEqual(lines[1].split()[6], "-")
        self.assertTrue(lines[3].endswith("downloads/sub"))
        latest = self.cli("history", "--limit", "1", "--json")
        self.assertEqual(latest.returncode, 0, latest.stderr)
        report = json.loads(latest.stdout)
        self.assertEqual(report["status"], "completed")
        self.assertEqual([entry["target"] for entry in report["data"]["entries"]],
                         [{"root_alias": "downloads", "relative_path": "sub"}])
        self.assertEqual([entry["source"] for entry in report["data"]["entries"]], ["ClamAV"])
        self.assertEqual(report["data"]["file"], str(self.file))
        self.assertTrue(report["data"]["recording"])
        for limit in ("0", "1001"):
            refused = self.cli("history", "--limit", limit)
            self.assertEqual(refused.returncode, 2)
            self.assertIn("--limit must be 1..1000", json.loads(refused.stdout)["error"])

    def test_numbers_no_scan_could_produce_make_a_damaged_line(self):
        # Found in the vulnerability check of 2026-10-19: counts of over 4,300 digits stopped the dashboard.
        good = {"version": 1, "started_at": "2026-10-19T08:00:00+09:00", "seconds": 1.0, "via": "cli",
                "operation": "malware", "target": {"root_alias": "downloads"}, "status": "completed",
                "findings": {"high": history.NUMBER_LIMIT}, "warnings": 0}
        huge = int("9" * 4300)
        bad = [{**good, "findings": {"high": huge}}, {**good, "findings": {"high": history.NUMBER_LIMIT + 1}},
               {**good, "warnings": huge}, {**good, "operation": "inventory", "target": {"query_id": "x", "offset": huge}}]
        self.file.parent.mkdir()
        other = {**good, "target": {"root_alias": "documents"}}  # another target, so the dashboard adds both up
        self.file.write_text("\n".join(json.dumps(line) for line in [good, other, *bad]) + "\n", encoding="utf-8")
        entries, skipped = history.read(self.file, 100)
        self.assertEqual((len(entries), skipped), (2, len(bad)))
        self.assertIn(f"{history.NUMBER_LIMIT} (high {history.NUMBER_LIMIT})", history.table(entries))
        from pc_scanner import dashboard
        page, _ = dashboard.build(self.file, 100, True, False, 50)
        self.assertIn(f"high {2 * history.NUMBER_LIMIT}", page.read_text(encoding="utf-8"))

    def test_each_operation_shows_the_scan_that_ran_and_the_columns_stay_aligned(self):
        base = {"version": 1, "started_at": "2026-10-19T08:00:00+09:00", "seconds": 1.5, "via": "cli",
                "status": "completed", "findings": {}, "warnings": 0, "error": None}
        targets = {"inventory": {"query_id": "os_version", "offset": 0}, "malware": {"root_alias": "downloads"},
                   "vulnerabilities": {"continued": False}, "android": {"device_alias": "phone", "query_id": "apps"},
                   "android_check": {"device_alias": "phone"}, "router_check": {"router_alias": "home"}}
        entries = [{**base, "operation": operation, "target": target} for operation, target in targets.items()]
        lines = history.table(entries).splitlines()
        start, end = lines[0].index("SOURCE"), lines[0].index("STATUS")
        shown = {line.split()[3]: line[start:end].strip() for line in lines[1:]}
        self.assertEqual(shown, {"inventory": "osquery", "malware": "ClamAV", "vulnerabilities": "Wazuh",
                                 "android": "Android (adb)", "android_check": "Android (adb)",
                                 "router_check": "Router check (JVN, KEV, settings)"})
        # SECONDS is right-aligned under its heading, after a source with spaces in it.
        seconds_end = lines[0].index("SECONDS") + len("SECONDS")
        self.assertTrue(all(line[:seconds_end].endswith("1.5") for line in lines[1:]))
        self.assertEqual(set(history.SOURCES), history.OPERATIONS)

    def test_the_source_is_shown_but_never_recorded(self):
        self.scanner().invoke("malware", root_alias="missing")
        self.assertNotIn("source", self.file.read_text(encoding="utf-8"))
        report = json.loads(self.cli("history", "--json").stdout)
        self.assertEqual(report["data"]["entries"][0]["source"], "ClamAV")

    def test_the_history_command_still_reads_after_recording_is_turned_off(self):
        self.scanner().invoke("malware", root_alias="missing")
        config = self.root / "off.toml"
        config.write_text(f"[history]\nenabled = false\nfile = {toml_path(self.file)}\n")
        shown = self.cli("history", config=config)
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn("missing", shown.stdout)
        self.assertIn("Recording is turned off", shown.stderr)
        self.assertEqual(self.cli("malware", "missing", config=config).returncode, 2)
        self.assertEqual(len(self.records()), 1)

    def test_settings_are_checked(self):
        for bad in ({"enabled": "yes"}, {"enabled": 1}, {"file": "history.jsonl"}, {"file": 3}):
            with self.subTest(bad=bad), self.assertRaises(ScannerError):
                Scanner({"history": bad})
        with self.assertRaises(ScannerError):
            Scanner({"history": "on"})
        self.assertEqual(Scanner({"history": {"enabled": True, "file": str(self.file)}}).config_warnings, [])
        self.assertTrue(any("did you mean 'history.enabled'?" in warning
                            for warning in Scanner({"history": {"enable": False}}).config_warnings))

    def test_the_default_file_is_in_each_os_state_folder(self):
        home = self.root / "home"
        name = Path(history.FOLDER) / "history.jsonl"
        self.assertEqual(history.default_file({}, "Darwin", home), home / "Library" / "Application Support" / name)
        self.assertEqual(history.default_file({}, "Linux", home), home / ".local" / "state" / name)
        self.assertEqual(history.default_file({"XDG_STATE_HOME": str(self.root / "s")}, "Linux", home),
                         self.root / "s" / name)
        self.assertEqual(history.default_file({"XDG_STATE_HOME": "relative"}, "Linux", home),
                         home / ".local" / "state" / name)
        self.assertEqual(history.default_file({"LOCALAPPDATA": str(self.root / "Local")}, "Windows", home),
                         self.root / "Local" / name)
        self.assertEqual(history.default_file({}, "Windows", home), home / "AppData" / "Local" / name)
        with patch("pc_scanner.history.default_file", side_effect=RuntimeError):
            scanner = Scanner({})
            scanner.via = "cli"
            report = scanner.invoke("malware", root_alias="missing")
        self.assertIn("Scan history could not be written; the scan itself is unaffected", report["warnings"])

    def test_the_mcp_server_marks_its_scans(self):
        from pc_scanner import server
        scanner = self.scanner(via=None)
        with patch.object(server, "create_server") as create:
            server.serve(scanner)
        create.return_value.run.assert_called_once_with(transport="stdio")
        self.assertEqual(scanner.via, "mcp")

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_scans_requested_over_mcp_are_recorded_as_mcp(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        scanner = self.scanner(via="mcp")

        async def exercise():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                await session.call_tool("scanner_status", {})
                await session.call_tool("scan_malware", {"root_alias": "missing"})

        asyncio.run(exercise())
        [record] = self.records()
        self.assertEqual((record["via"], record["operation"], record["status"]), ("mcp", "malware", "error"))
        self.assertEqual(record["target"], {"root_alias": "missing", "relative_path": "."})


if __name__ == "__main__":
    unittest.main()
