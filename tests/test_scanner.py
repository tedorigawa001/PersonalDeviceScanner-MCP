import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pc_scanner.core import NoRedirect, Scanner, ScannerError, clamav_signatures, is_link, run_bounded


def signatures(age=timedelta(hours=3)):
    built_at = None if age is None else datetime.now(timezone.utc) - age
    return {"engine": "1.5.4", "version": None if age is None else 27800, "built_at": built_at}


def wait_for(condition, seconds):
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def process_running(pid):
    if os.name == "nt":
        # os.kill(pid, 0) would terminate the process on Windows, so ask the OS instead.
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 0x102  # WAIT_TIMEOUT: still running
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def as_standard_user(func):
    """Call func with the file access a standard user would have.

    GitHub's Windows runners enable SeBackupPrivilege, which bypasses ACL deny
    entries, so on Windows func runs on this thread with a restricted token:
    all privileges removed and Administrators deny-only. Elsewhere it is a plain call.
    """
    if os.name != "nt":
        return func()
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    advapi32.ImpersonateSelf.argtypes = [ctypes.c_int]
    advapi32.OpenThreadToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL,
                                         ctypes.POINTER(wintypes.HANDLE)]
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SID_AND_ATTRIBUTES),
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.SetThreadToken.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.HANDLE]
    kernel32.GetCurrentThread.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    def check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    security_impersonation, token_all_access, disable_max_privilege = 2, 0xF01FF, 0x1
    check(advapi32.ImpersonateSelf(security_impersonation))
    try:
        own = wintypes.HANDLE()
        check(advapi32.OpenThreadToken(kernel32.GetCurrentThread(), token_all_access, True, ctypes.byref(own)))
        administrators = ctypes.c_void_p()
        check(advapi32.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(administrators)))
        restricted = wintypes.HANDLE()
        try:
            deny_only = SID_AND_ATTRIBUTES(administrators, 0)
            check(advapi32.CreateRestrictedToken(own, disable_max_privilege, 1, ctypes.byref(deny_only),
                                                 0, None, 0, None, ctypes.byref(restricted)))
        finally:
            kernel32.LocalFree(administrators)
            kernel32.CloseHandle(own)
        try:
            check(advapi32.SetThreadToken(None, restricted))
            return func()
        finally:
            kernel32.CloseHandle(restricted)
    finally:
        advapi32.RevertToSelf()


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "sample.txt").write_text("ordinary test file")
        self.scanner = Scanner({"local": {"clamav_binary": sys.executable,
                                          "osquery_binary": sys.executable},
                                "scan_roots": {"test": str(self.root)}})
        # Scans see fresh signatures unless a test says otherwise.
        self.signature_check = self.enterContext(
            patch("pc_scanner.core.clamav_signatures", side_effect=lambda *args, **kwargs: signatures()))

    def test_no_engines_is_error_not_safe(self):
        report = Scanner({}).invoke("inventory", query_id="os_version")
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["source"], "osquery")

    def test_arbitrary_sql_is_rejected(self):
        with patch("pc_scanner.core.run_bounded") as run:
            report = self.scanner.invoke("inventory", query_id="SELECT * FROM users;")
        self.assertEqual(report["status"], "error")
        run.assert_not_called()

    def test_inventory_is_not_finding(self):
        with patch("pc_scanner.core.run_bounded", return_value=(0, '[{"name":"OS"}]', "")):
            report = self.scanner.invoke("inventory", query_id="os_version")
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["findings"], [])

    def test_inventory_cap_empty_and_bad_json(self):
        for output, expected in [("[]", "partial"), ("broken", "error"),
                                 (json.dumps([{}] * 501), "partial")]:
            with self.subTest(output=output[:20]), patch("pc_scanner.core.run_bounded", return_value=(0, output, "")):
                self.assertEqual(self.scanner.invoke("inventory", query_id="os_version")["status"], expected)

    def test_linux_inventory_query(self):
        with patch("pc_scanner.core.platform.system", return_value="Linux"), patch(
                "pc_scanner.core.run_bounded", return_value=(0, '[{"name":"app"}]', "")) as run:
            self.scanner.invoke("inventory", query_id="applications")
        self.assertIn("deb_packages UNION ALL", run.call_args.args[0][-1])

    def test_inventory_pages(self):
        with patch("pc_scanner.core.run_bounded", return_value=(0, json.dumps([{}] * 501), "")) as run:
            first = self.scanner.invoke("inventory", query_id="os_version")
        self.assertEqual(first["data"]["next_offset"], 500)
        self.assertEqual(len(first["data"]["rows"]), 500)
        self.assertTrue(run.call_args.args[0][-1].endswith("LIMIT 501 OFFSET 0;"))
        with patch("pc_scanner.core.run_bounded", return_value=(0, '[{"name":"last"}]', "")) as run:
            last = self.scanner.invoke("inventory", query_id="os_version", offset=500)
        self.assertTrue(run.call_args.args[0][-1].endswith("LIMIT 501 OFFSET 500;"))
        self.assertIsNone(last["data"]["next_offset"])
        self.assertEqual(last["status"], "partial")

    def test_invalid_offset_rejected(self):
        for offset in (-1, 9501, "0; DROP TABLE users", True):
            with self.subTest(offset=offset), patch("pc_scanner.core.run_bounded") as run:
                report = self.scanner.invoke("inventory", query_id="os_version", offset=offset)
                self.assertEqual(report["status"], "error")
                run.assert_not_called()

    def test_listening_ports_show_address_and_process(self):
        with patch("pc_scanner.core.run_bounded", return_value=(0, '[{"port":"22"}]', "")) as run:
            report = self.scanner.invoke("inventory", query_id="listening_ports")
        query = run.call_args.args[0][-1]
        self.assertIn("lp.address", query)
        self.assertIn("JOIN processes", query)
        self.assertTrue(any("Standard-user" in warning for warning in report["warnings"]))

    def test_path_escape_and_absolute_rejected(self):
        for target in ("../secret", str(self.root / "sample.txt")):
            with self.subTest(target=target), patch("pc_scanner.core.run_bounded") as run:
                self.assertEqual(self.scanner.invoke("malware", root_alias="test", relative_path=target)["status"], "error")
                run.assert_not_called()

    def test_symlink_escape_rejected(self):
        outside = self.root.parent / "outside"
        try:
            (self.root / "link").symlink_to(self.root.parent, target_is_directory=True)
        except OSError:
            self.skipTest("Symlinks unavailable")
        with patch("pc_scanner.core.run_bounded") as run:
            report = self.scanner.invoke("malware", root_alias="test", relative_path="link")
        self.assertEqual(report["status"], "error")
        run.assert_not_called()

    def test_unknown_scan_alias_rejected(self):
        self.assertEqual(self.scanner.invoke("malware", root_alias="other")["status"], "error")

    def test_clamav_exit_codes_and_limits(self):
        cases = [(0, "Scanned files: 1\n", "", "completed", 0),
                 (1, "C:\\file.txt: Test.Signature FOUND\nScanned files: 1\n", "", "completed", 1),
                 (2, "", "database missing", "partial", 0),
                 (0, "Scanned files: 0\n", "", "partial", 0),
                 (1, "file: Heuristics.Limits.Exceeded.MaxFileSize FOUND\nScanned files: 1\n", "", "partial", 1)]
        for code, output, diagnostic, status, count in cases:
            with self.subTest(code=code, output=output), patch("pc_scanner.core.run_bounded", return_value=(code, output, diagnostic)) as run:
                report = self.scanner.invoke("malware", root_alias="test", relative_path="sample.txt")
                self.assertEqual(report["status"], status)
                self.assertEqual(len(report["findings"]), count)
                argv = run.call_args.args[0]
                self.assertNotIn("--remove", argv)
                self.assertIn("--follow-dir-symlinks=0", argv)

    def test_unknown_settings_are_warned_with_suggestions(self):
        cases = [({"scan_root": {"docs": str(self.root)}}, "'scan_root'", "'scan_roots'"),  # missing s
                 ({"local": {"timeout_second": 60}}, "'local.timeout_second'", "'local.timeout_seconds'"),
                 ({"timeout_seconds": 60}, "'timeout_seconds'", "'local.timeout_seconds'"),  # outside its section
                 ({"wazuh": {"agentid": "001"}}, "'wazuh.agentid'", "'wazuh.agent_id'"),
                 ({"wazuh": {"timeout": 5}}, "'wazuh.timeout'", None),  # the shared section prefix is no match
                 ({"extras": {}}, "'extras'", None)]
        for config, name, suggestion in cases:
            with self.subTest(config=config):
                warnings = Scanner(config).config_warnings
                self.assertEqual(len(warnings), 1)
                self.assertIn(f"Unknown setting {name} is ignored", warnings[0])
                if suggestion:
                    self.assertIn(f"did you mean {suggestion}?", warnings[0])
                else:
                    self.assertNotIn("did you mean", warnings[0])

    def test_credentials_in_config_point_to_environment(self):
        for key in ("password", "user", "username"):
            with self.subTest(key=key):
                warning = Scanner({"wazuh": {key: "x"}}).config_warnings[0]
                self.assertIn("PC_SCANNER_WAZUH_USER", warning)
                self.assertNotIn("did you mean", warning)

    def test_known_settings_and_any_alias_are_accepted(self):
        with open("scanner.example.toml", "rb") as f:
            self.assertEqual(Scanner(tomllib.load(f)).config_warnings, [])
        scanner = Scanner({"local": {"timeout_seconds": 60, "max_output_bytes": 2048, "max_signature_age_days": 3},
                           "scan_roots": {"any-alias_1": str(self.root)},
                           "wazuh": {"url": "", "agent_id": "", "ca_file": "", "agent_name": ""}})
        self.assertEqual(scanner.config_warnings, [])

    def test_unknown_settings_reach_every_result(self):
        scanner = Scanner({"local": {"clamav_binary": sys.executable}, "scan_root": {"docs": str(self.root)}})
        for operation, kwargs in (("status", {}), ("malware", {"root_alias": "docs"})):
            with self.subTest(operation=operation):
                report = scanner.invoke(operation, **kwargs)
                self.assertIn("did you mean 'scan_roots'?", report["warnings"][0])
        self.assertEqual(scanner.invoke("malware", root_alias="docs")["status"], "error")  # the typo has an effect

    def test_config_rejects_http_and_relative_binary(self):
        for config in ({"wazuh": {"url": "http://localhost:9200", "agent_id": "001"}},
                       {"wazuh": {"url": "https://user:pass@localhost:9200", "agent_id": "001"}},
                       {"local": {"osquery_binary": "osqueryi"}},
                       {"local": {"timeout_seconds": 0}},
                       {"local": {"max_signature_age_days": 0}},
                       {"local": {"max_signature_age_days": "7"}}):
            with self.subTest(config=config), self.assertRaises(ScannerError):
                Scanner(config)

    def test_batch_wrappers_rejected(self):
        batch = self.root / "engine.cmd"
        batch.write_text("echo test")
        scanner = Scanner({"local": {"clamav_binary": str(batch)}})
        with self.assertRaises(ScannerError):
            scanner.binary("clamav_binary")

    def test_batch_wrappers_rejected_through_symlinks(self):
        for suffix in (".cmd", ".BAT"):
            with self.subTest(suffix=suffix):
                batch = self.root / ("engine" + suffix)
                batch.write_text("echo test")
                alias = self.root / ("alias" + suffix + ".exe")
                try:
                    alias.symlink_to(batch)
                except OSError:
                    self.skipTest("Symlinks unavailable")
                scanner = Scanner({"local": {"clamav_binary": str(alias)},
                                   "scan_roots": {"test": str(self.root)}})
                with patch("pc_scanner.core.run_bounded") as run:
                    report = scanner.invoke("malware", root_alias="test")
                self.assertEqual(report["status"], "error")
                run.assert_not_called()

    def test_directory_depth_boundary(self):
        # ClamAV counts the scan target itself as directory level 1.
        directory = self.root
        for level in range(2, 18):
            directory /= "d"
            directory.mkdir()
            (directory / "sample.txt").write_text("test")
            with self.subTest(level=level), patch(
                    "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")) as run:
                report = self.scanner.invoke("malware", root_alias="test")
                self.assertEqual(report["status"], "partial" if level > 16 else "completed")
                self.assertIn("--max-dir-recursion=16", run.call_args.args[0])
                if level > 16:
                    self.assertTrue(any("directory" in warning.lower() for warning in report["warnings"]))

    def test_deep_scan_preserves_malware_findings(self):
        directory = self.root.joinpath(*(["d"] * 16))
        directory.mkdir(parents=True)
        output = f"{self.root / 'sample.txt'}: Test.Signature FOUND\nScanned files: 1\n"
        with patch("pc_scanner.core.run_bounded", return_value=(1, output, "")):
            report = self.scanner.invoke("malware", root_alias="test")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["findings"][0]["kind"], "malware")

    def test_direct_scan_of_deep_file_is_complete(self):
        file = self.root.joinpath(*(["d"] * 16), "sample.txt")
        file.parent.mkdir(parents=True)
        file.write_text("test")
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")):
            report = self.scanner.invoke("malware", root_alias="test", relative_path=str(file.relative_to(self.root)))
        self.assertEqual(report["status"], "completed")

    def test_depth_check_excludes_directory_symlinks(self):
        directory = self.root.joinpath(*(["d"] * 15))
        directory.mkdir(parents=True)
        try:
            (directory / "link").symlink_to(self.root, target_is_directory=True)
        except OSError:
            self.skipTest("Symlinks unavailable")
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")):
            report = self.scanner.invoke("malware", root_alias="test")
        self.assertEqual(report["status"], "completed")

    @unittest.skipUnless(os.name == "nt", "Legacy profile junctions exist only on Windows")
    def test_legacy_profile_junction_does_not_block_scan(self):
        music = self.root / "Music"
        music.mkdir()
        junction = self.root / "My Music"
        subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(music)],
                       check=True, capture_output=True)
        self.addCleanup(os.rmdir, junction)
        self.deny_listing(junction, junction=True)
        self.assertTrue(as_standard_user(lambda: is_link(junction)))
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")):
            report = as_standard_user(lambda: self.scanner.invoke("malware", root_alias="test"))
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["data"]["unreadable_directories"], [])

    @unittest.skipUnless(os.name == "nt", "Real junctions exist only on Windows")
    def test_real_windows_junction_is_not_followed(self):
        directory = self.root.joinpath(*(["d"] * 15))
        directory.mkdir(parents=True)
        junction = directory / "junction"
        # Points back at the root, so following it would hit the depth limit.
        subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(self.root)],
                       check=True, capture_output=True)
        self.addCleanup(os.rmdir, junction)
        self.assertTrue(is_link(junction))
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")):
            report = self.scanner.invoke("malware", root_alias="test")
        self.assertEqual(report["status"], "completed")

    def test_depth_check_excludes_windows_junctions(self):
        directory = self.root.joinpath(*(["d"] * 15))
        (directory / "junction").mkdir(parents=True)
        real_lstat = os.lstat

        def junction_lstat(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if Path(path).name == "junction":
                return SimpleNamespace(st_mode=info.st_mode, st_reparse_tag=0xA0000003)
            return info

        with patch("pc_scanner.core.os.lstat", side_effect=junction_lstat), patch(
                "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")):
            report = self.scanner.invoke("malware", root_alias="test")
        self.assertEqual(report["status"], "completed")

    def deny_listing(self, directory, junction=False):
        """Deny listing as the OS would: chmod on POSIX, an ACL deny entry on Windows."""
        if os.name == "nt":
            # Everyone by SID so localized Windows works; (S,RD) matches the legacy
            # profile junctions such as Documents\My Music. /L acts on a junction itself.
            link = ["/L"] if junction else []
            subprocess.run(["icacls", str(directory), "/deny", "*S-1-1-0:(S,RD)", *link],
                           check=True, capture_output=True)
            self.addCleanup(subprocess.run, ["icacls", str(directory), "/remove:d", "*S-1-1-0", *link],
                            check=True, capture_output=True)
        else:
            directory.chmod(0)
            self.addCleanup(directory.chmod, 0o755)
        try:
            as_standard_user(lambda: os.listdir(directory))
        except PermissionError:
            return
        self.skipTest("Directory permissions are not enforced for this user")

    def test_unreadable_directory_is_partial_and_keeps_findings(self):
        locked = self.root / "locked"
        locked.mkdir()
        self.deny_listing(locked)
        output = f"{self.root.resolve() / 'sample.txt'}: Test.Signature FOUND\nScanned files: 1\n"
        with patch("pc_scanner.core.run_bounded", return_value=(1, output, "")) as run:
            report = as_standard_user(lambda: self.scanner.invoke("malware", root_alias="test"))
        run.assert_called_once()
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["findings"][0]["kind"], "malware")
        self.assertEqual(report["data"]["unreadable_directories"], ["locked"])
        self.assertTrue(any("could not be read" in warning for warning in report["warnings"]))

    def test_directory_coverage_timeout_does_not_start_engine(self):
        with patch("pc_scanner.core.time.monotonic", side_effect=[0, self.scanner.timeout + 1]), patch(
                "pc_scanner.core.run_bounded") as run:
            report = self.scanner.invoke("malware", root_alias="test")
        self.assertEqual(report["status"], "error")
        self.assertIn("timed out", report["error"])
        run.assert_not_called()

    def test_coverage_check_and_engine_share_time_budget(self):
        with patch("pc_scanner.core.time.monotonic", side_effect=[0, 0, 100]), patch(
                "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")) as run:
            self.scanner.invoke("malware", root_alias="test")
        self.assertEqual(run.call_args.args[1], self.scanner.timeout - 100)

    def test_minimum_timeout_still_starts_engine(self):
        scanner = Scanner({"local": {"clamav_binary": sys.executable, "timeout_seconds": 1},
                           "scan_roots": {"test": str(self.root)}})
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")) as run:
            report = scanner.invoke("malware", root_alias="test", relative_path="sample.txt")
        run.assert_called_once()
        self.assertEqual(report["status"], "completed")

    def test_remaining_time_boundary(self):
        scanner = Scanner({"local": {"clamav_binary": sys.executable, "timeout_seconds": 1},
                           "scan_roots": {"test": str(self.root)}})
        for elapsed, starts in ((0.25, True), (1.0, False), (1.25, False)):
            with self.subTest(elapsed=elapsed), patch(
                    "pc_scanner.core.time.monotonic", side_effect=[0, elapsed]), patch(
                    "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")) as run:
                report = scanner.invoke("malware", root_alias="test", relative_path="sample.txt")
                self.assertEqual(report["status"], "completed" if starts else "error")
                if starts:
                    run.assert_called_once()
                    self.assertEqual(run.call_args.args[1], 0.75)
                else:
                    run.assert_not_called()

    def test_engine_line_length_boundary(self):
        from pc_scanner.core import excerpt
        for length in (499, 500, 501):
            with self.subTest(length=length):
                text = "x" * (length - 4) + "TAIL"
                report, truncated = excerpt(text)
                self.assertEqual(truncated, length > 500)
                self.assertTrue(report.endswith("TAIL"))
                if length <= 500:
                    self.assertEqual(report, text)

    def test_long_engine_line_is_flagged_and_keeps_its_end(self):
        diagnostic = "x" * 500 + " ERROR: disk read failure"
        with patch("pc_scanner.core.run_bounded", return_value=(2, "Scanned files: 1\n", diagnostic)):
            report = self.scanner.invoke("malware", root_alias="test")
        self.assertTrue(report["data"]["engine_text_truncated"])
        self.assertIn("ERROR: disk read failure", report["data"]["diagnostic"])
        self.assertLess(len(report["data"]["diagnostic"]), len(diagnostic))

    def test_clamav_report_is_relative_and_bounded(self):
        root = self.root.resolve()
        output = "\n".join([f"{root / 'sample.txt'}: Test.Signature FOUND"]
                           + [f"{root / f'f{i}'}: Access denied. ERROR" for i in range(200)]
                           + ["Scanned files: 1"])
        with patch("pc_scanner.core.run_bounded", return_value=(1, output, "")):
            report = self.scanner.invoke("malware", root_alias="test")
        self.assertEqual(report["findings"][0]["path"], "sample.txt")
        self.assertNotIn(str(root), json.dumps(report))
        self.assertNotIn("FOUND", report["data"]["engine_report"])
        self.assertTrue(report["data"]["engine_text_truncated"])
        self.assertLessEqual(len(report["data"]["engine_report"].splitlines()), 61)
        self.assertIn("Scanned files: 1", report["data"]["engine_report"])

    def test_clamav_findings_capped_with_malware_first(self):
        output = "\n".join([f"big{i}: Heuristics.Limits.Exceeded.MaxFileSize FOUND" for i in range(600)]
                           + ["evil: Test.Signature FOUND", "Scanned files: 601"])
        with patch("pc_scanner.core.run_bounded", return_value=(1, output, "")):
            report = self.scanner.invoke("malware", root_alias="test")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(len(report["findings"]), 500)
        self.assertEqual(report["findings"][0]["kind"], "malware")
        self.assertEqual(report["data"]["findings_total"], 601)

    def test_runner_decodes_ansi_code_page_output(self):
        script = "import sys; sys.stdout.buffer.write('ダウンロード'.encode('cp932'))"
        with patch("pc_scanner.core.locale.getpreferredencoding", return_value="cp932"):
            _, output, _ = run_bounded([sys.executable, "-c", script], 5, 1024)
        self.assertEqual(output, "ダウンロード")

    def engine_with_grandchild(self, exit_after_start, **popen_options):
        """Write an engine script that starts a long-running grandchild and records its PID."""
        pid_file = self.root / "grandchild.pid"
        script = self.root / "engine.py"
        script.write_text(
            "import os, subprocess, sys, time\n"
            f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], **{popen_options!r})\n"
            f"with open({str(pid_file) + '.tmp'!r}, 'w') as f:\n"
            "    f.write(str(child.pid))\n"
            f"os.replace({str(pid_file) + '.tmp'!r}, {str(pid_file)!r})\n"
            + ("" if exit_after_start else "time.sleep(30)\n"))
        return [sys.executable, str(script)], pid_file

    def test_runner_stops_descendants_when_cancelled(self):
        argv, pid_file = self.engine_with_grandchild(exit_after_start=False)
        cancel = threading.Event()

        def cancel_once_started():
            wait_for(pid_file.exists, 20)
            cancel.set()

        threading.Thread(target=cancel_once_started, daemon=True).start()
        with self.assertRaisesRegex(ScannerError, "cancelled"):
            run_bounded(argv, 60, 1024, cancel=cancel)
        grandchild = int(pid_file.read_text())
        self.assertTrue(wait_for(lambda: not process_running(grandchild), 5), "grandchild still running")

    def test_runner_stops_descendants_left_after_exit(self):
        argv, pid_file = self.engine_with_grandchild(exit_after_start=True)
        code, _, _ = run_bounded(argv, 60, 1024)
        self.assertEqual(code, 0)
        grandchild = int(pid_file.read_text())
        self.assertTrue(wait_for(lambda: not process_running(grandchild), 5), "grandchild still running")

    @unittest.skipIf(os.name == "nt", "Processes cannot leave the engine's job object on Windows")
    def test_runner_reports_pipes_held_by_escaped_process(self):
        # A new session leaves the engine's process group, so stopping the group misses it.
        script = ("import subprocess, sys; "
                  "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(6)'], start_new_session=True)")
        with self.assertRaisesRegex(ScannerError, "left the engine's process group"):
            run_bounded([sys.executable, "-c", script], 10, 1024)

    def test_runner_stops_engine_when_cancelled(self):
        cancel = threading.Event()
        timer = threading.Timer(0.3, cancel.set)
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        with self.assertRaisesRegex(ScannerError, "cancelled"):
            run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], 60, 1024, cancel=cancel)
        # run_bounded only returns after the engine process has exited.
        self.assertLess(time.monotonic() - started, 10)

    def test_cancel_before_engine_does_not_start_it(self):
        cancel = threading.Event()
        cancel.set()
        for relative_path in (".", "sample.txt"):
            with self.subTest(relative_path=relative_path), patch("subprocess.Popen") as popen:
                report = self.scanner.invoke("malware", root_alias="test", relative_path=relative_path,
                                             cancel=cancel)
                self.assertEqual(report["status"], "error")
                self.assertIn("cancelled", report["error"])
                popen.assert_not_called()

    def test_engines_receive_cancel_signal(self):
        cancel = threading.Event()
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")) as run:
            self.scanner.invoke("malware", root_alias="test", cancel=cancel)
        self.assertIs(run.call_args.kwargs["cancel"], cancel)
        with patch("pc_scanner.core.run_bounded", return_value=(0, '[{"name":"OS"}]', "")) as run:
            self.scanner.invoke("inventory", query_id="os_version", cancel=cancel)
        self.assertIs(run.call_args.kwargs["cancel"], cancel)

    def test_runner_timeout_and_output_limit(self):
        with self.assertRaisesRegex(ScannerError, "timed out"):
            run_bounded([sys.executable, "-c", "import time; time.sleep(3)"], 1, 1024)
        with self.assertRaisesRegex(ScannerError, "output exceeded"):
            run_bounded([sys.executable, "-c", "print('x'*10000)"], 5, 1024)

    def test_runner_does_not_pass_secrets(self):
        with patch.dict(os.environ, {"PC_SCANNER_WAZUH_PASSWORD": "secret", "OPENAI_API_KEY": "secret",
                                     "SYSTEMDRIVE": "C:", "TZ": "Asia/Tokyo"}):
            code, output, _ = run_bounded([sys.executable, "-c", "import os; print(os.getenv('PC_SCANNER_WAZUH_PASSWORD')); print(os.getenv('OPENAI_API_KEY')); print(os.getenv('SYSTEMDRIVE')); print(os.getenv('TZ'))"], 5, 1024)
        self.assertEqual(code, 0)
        self.assertEqual(output.splitlines(), ["None", "None", "C:", "Asia/Tokyo"])

    def test_signature_version_is_parsed(self):
        # clamscan --version prints the newest daily database time in local ctime() format.
        cases = {"ClamAV 1.5.4/27800/Mon Oct 12 07:43:35 2026\n": ("1.5.4", 27800, datetime(2026, 10, 12, 7, 43, 35)),
                 "ClamAV 0.103.8/26827/Thu Feb  2 08:23:52 2023\n": ("0.103.8", 26827, datetime(2023, 2, 2, 8, 23, 52))}
        for output, (engine, version, local_time) in cases.items():
            with self.subTest(output=output), patch("pc_scanner.core.run_bounded", return_value=(0, output, "")) as run:
                info = clamav_signatures("/engine/clamscan", time.monotonic() + 60, 1024)
                self.assertEqual(run.call_args.args[0], ["/engine/clamscan", "--version"])
                self.assertEqual((info["engine"], info["version"]), (engine, version))
                self.assertEqual(info["built_at"], local_time.astimezone(timezone.utc))

    def test_signature_date_unknown(self):
        for code, output in ((0, "ClamAV 1.5.4\n"),  # no daily database found
                             (2, "ClamAV 1.5.4/27800/Mon Oct 12 07:43:35 2026\n"),
                             (0, "ClamAV 1.5.4/27800/Mon Foo 12 07:43:35 2026\n"),
                             (0, "ClamAV 1.5.4/27800/Mon Feb 31 07:43:35 2026\n"),
                             (0, "unexpected\n")):
            with self.subTest(output=output), patch("pc_scanner.core.run_bounded", return_value=(code, output, "")):
                self.assertIsNone(clamav_signatures("/engine/clamscan", time.monotonic() + 60, 1024)["built_at"])

    def test_signature_check_needs_time_left(self):
        with patch("pc_scanner.core.run_bounded") as run, self.assertRaises(ScannerError):
            clamav_signatures("/engine/clamscan", time.monotonic() - 1, 1024)
        run.assert_not_called()

    def test_fresh_signatures_are_reported(self):
        cancel = threading.Event()
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")):
            report = self.scanner.invoke("malware", root_alias="test", cancel=cancel)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["data"]["signatures"]["version"], 27800)
        self.assertLess(report["data"]["signatures"]["age_days"], 1)
        self.assertEqual(report["data"]["signatures"]["max_age_days"], 7)
        binary, deadline, _ = self.signature_check.call_args.args
        self.assertEqual(binary, str(Path(sys.executable).resolve()))
        self.assertLessEqual(deadline, time.monotonic() + self.scanner.timeout)
        self.assertIs(self.signature_check.call_args.kwargs["cancel"], cancel)

    def test_stale_or_unknown_signatures_make_scan_partial(self):
        for age, words in ((timedelta(days=8), "days old"), (None, "could not be determined")):
            self.signature_check.side_effect = lambda *args, age=age, **kwargs: signatures(age)
            with self.subTest(age=age), patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")) as run:
                report = self.scanner.invoke("malware", root_alias="test")
                run.assert_called_once()  # the scan still runs with what is installed
                self.assertEqual(report["status"], "partial")
                self.assertTrue(any(words in w and "freshclam" in w for w in report["warnings"]))

    def test_signature_age_limit_boundary(self):
        # The default limit is 7 days; any overrun must count, however small.
        fixed_now = datetime(2026, 10, 12, 6, 0, tzinfo=timezone.utc)
        for age, status in ((timedelta(days=7) - timedelta(hours=1), "completed"),
                            (timedelta(days=7), "completed"),
                            (timedelta(days=7) + timedelta(microseconds=1), "partial"),
                            (timedelta(days=7) + timedelta(minutes=1), "partial"),
                            (timedelta(days=7) + timedelta(hours=1), "partial")):
            self.signature_check.side_effect = None
            self.signature_check.return_value = {
                "engine": "1.5.4", "version": 27800, "built_at": fixed_now - age}
            with self.subTest(age=age), patch("pc_scanner.core.datetime") as clock, patch(
                    "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")):
                clock.now.return_value = fixed_now
                report = self.scanner.invoke("malware", root_alias="test")
                self.assertEqual(report["status"], status)
                shown = report["data"]["signatures"]["age_days"]
                # The shown age agrees with the decision: over the limit only when stale.
                self.assertEqual(shown > 7, status == "partial")

    def test_signature_age_limit_is_configurable(self):
        self.signature_check.side_effect = lambda *args, **kwargs: signatures(timedelta(days=2))
        strict = Scanner({"local": {"clamav_binary": sys.executable, "max_signature_age_days": 1},
                          "scan_roots": {"test": str(self.root)}})
        for scanner, status in ((self.scanner, "completed"), (strict, "partial")):
            with self.subTest(status=status), patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\n", "")):
                self.assertEqual(scanner.invoke("malware", root_alias="test")["status"], status)

    def wazuh_response(self, payload, agent_id="001", cursor="", agent_name=""):
        scanner = Scanner({"wazuh": {"url": "https://localhost:9200", "agent_id": agent_id,
                                     "agent_name": agent_name}})
        response = io.BytesIO(json.dumps(payload).encode())
        with patch.dict(os.environ, {"PC_SCANNER_WAZUH_USER": "reader", "PC_SCANNER_WAZUH_PASSWORD": "secret"}), patch(
                "pc_scanner.core.socket.gethostname", return_value="test-pc"), patch("pc_scanner.core.build_opener") as build:
            build.return_value.open.return_value = response
            report = scanner.invoke("vulnerabilities", cursor=cursor)
            request = build.return_value.open.call_args.args[0]
        self.assertEqual(request.method, "GET")
        self.last_body = json.loads(request.data)
        self.assertEqual(self.last_body["query"]["term"]["agent.id"], "001")
        self.assertNotIn("secret", json.dumps(report))
        return report

    def test_wazuh_reports_findings_and_freshness(self):
        payload = {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_source": {
            "agent": {"id": "001", "name": "test-pc"}, "package": {"name": "test", "version": "1"},
            "vulnerability": {"id": "CVE-TEST", "severity": "High"}}}]}}
        report = self.wazuh_response(payload)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["findings"][0]["severity"], "high")
        self.assertEqual(report["data"]["freshness"], "unverified")
        payload["hits"]["total"]["value"] = 501
        self.assertEqual(self.wazuh_response(payload)["status"], "partial")
        payload["hits"]["hits"][0]["_source"]["agent"]["id"] = "002"
        self.assertEqual(self.wazuh_response(payload)["status"], "error")

    def wazuh_hits(self, count, score=9.8):
        return [{"_source": {"agent": {"id": "001", "name": "test-pc"}, "vulnerability": {
                     "id": f"CVE-{i:05d}", "severity": "Critical", "score": {"base": score}}},
                 "sort": [score, f"CVE-{i:05d}", "openssl", "3.0.2", "amd64", "deb", ""]} for i in range(count)]

    def test_wazuh_sorts_most_severe_first_with_unique_order(self):
        report = self.wazuh_response({"hits": {"total": {"value": 1, "relation": "eq"}, "hits": self.wazuh_hits(1)}})
        self.assertEqual(report["status"], "completed")
        self.assertIsNone(report["data"]["next_cursor"])
        self.assertEqual(report["findings"][0]["score"], 9.8)
        # Severity first; then every field Wazuh uses to identify a package, so no two records tie.
        self.assertEqual([next(iter(key)) for key in self.last_body["sort"]], [
            "vulnerability.score.base", "vulnerability.id", "package.name", "package.version",
            "package.architecture", "package.type", "package.path"])
        self.assertEqual(self.last_body["sort"][0]["vulnerability.score.base"]["order"], "desc")
        self.assertEqual(self.last_body["size"], 501)
        self.assertNotIn("from", self.last_body)
        self.assertNotIn("search_after", self.last_body)

    def test_wazuh_pages_with_cursor_beyond_10000(self):
        hits = self.wazuh_hits(501)
        total = {"value": 25000, "relation": "eq"}
        first = self.wazuh_response({"hits": {"total": total, "hits": hits}})
        self.assertEqual(len(first["findings"]), 500)
        self.assertEqual(first["status"], "partial")
        cursor = first["data"]["next_cursor"]
        self.assertIsInstance(cursor, str)
        self.assertTrue(any("next_cursor" in warning for warning in first["warnings"]))
        # Offsets stopped at 10000; a cursor continues from the last record however deep.
        middle = self.wazuh_response({"hits": {"total": total, "hits": hits}}, cursor=cursor)
        self.assertEqual(self.last_body["search_after"], hits[499]["sort"])
        self.assertNotIn("from", self.last_body)
        self.assertIsNotNone(middle["data"]["next_cursor"])
        last = self.wazuh_response({"hits": {"total": total, "hits": hits[:3]}}, cursor=middle["data"]["next_cursor"])
        self.assertIsNone(last["data"]["next_cursor"])
        self.assertEqual(last["status"], "partial")  # a continued page alone is not the full result

    def test_wazuh_rejects_invalid_cursor(self):
        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value).encode()).decode()

        scanner = Scanner({"wazuh": {"url": "https://localhost:9200", "agent_id": "001"}})
        for cursor in ("not a cursor!", encode({"a": 1}), encode([9.8, "CVE-1"]),
                       encode([True, "a", "b", "c", "d", "e", "f"]), encode([9.8, "a", "b", "c", "d", "e", ["f"]]),
                       encode([float("nan"), "a", "b", "c", "d", "e", "f"]),
                       encode([10 ** 400, "a", "b", "c", "d", "e", "f"]),  # too large for a float
                       encode([11, "a", "b", "c", "d", "e", "f"]), encode([-2, "a", "b", "c", "d", "e", "f"]),
                       encode([9.8] + ["x" * 2000] * 6), "A" * 5000, 7):
            with self.subTest(cursor=str(cursor)[:40]), patch.dict(os.environ, {
                    "PC_SCANNER_WAZUH_USER": "reader", "PC_SCANNER_WAZUH_PASSWORD": "secret"}), patch(
                    "pc_scanner.core.build_opener") as build:
                report = scanner.invoke("vulnerabilities", cursor=cursor)
                self.assertEqual(report["status"], "error")
                build.return_value.open.assert_not_called()

    def test_wazuh_unexpected_sort_values_are_rejected(self):
        hits = self.wazuh_hits(501)
        hits[499]["sort"] = [True, "a", "b", "c", "d", "e", "f"]
        report = self.wazuh_response({"hits": {"total": 501, "hits": hits}})
        self.assertEqual(report["status"], "error")

    def test_wazuh_agent_id_is_zero_padded(self):
        payload = {"hits": {"total": 1, "hits": [{"_source": {
            "agent": {"id": "001", "name": "test-pc"}, "vulnerability": {"id": "CVE-TEST", "severity": "Low"}}}]}}
        report = self.wazuh_response(payload, agent_id="1")
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["data"]["agent_id"], "001")

    def test_wazuh_device_identity(self):
        def payload(*names):
            agents = [{"id": "001", **({"name": n} if n is not None else {})} for n in names]
            return {"hits": {"total": len(agents), "hits": [
                {"_source": {"agent": agent, "host": {"os": {"full": "Windows 11 Pro"}},
                             "vulnerability": {"id": f"CVE-{i}", "severity": "Low"}}} for i, agent in enumerate(agents)]}}

        # This PC's host name is patched to "test-pc"; agent_name overrides it when configured.
        cases = [(("TEST-PC.local",), "", "completed", "matched"),  # case and domain suffix ignored
                 (("other-pc",), "", "partial", "mismatch"),
                 (("test-pc", "other-pc"), "", "partial", "mismatch"),
                 (("lab-desktop",), "lab-desktop", "completed", "matched"),
                 (("lab-desktop.dev",), "lab-desktop", "partial", "mismatch"),  # configured name is exact
                 ((None,), "", "partial", "unknown")]
        for names, agent_name, status, identity in cases:
            with self.subTest(names=names, agent_name=agent_name):
                report = self.wazuh_response(payload(*names), agent_name=agent_name)
                self.assertEqual(report["status"], status)
                self.assertEqual(report["data"]["device"]["identity"], identity)
                self.assertEqual(len(report["findings"]), len(names))  # findings are kept either way
                if identity != "matched":
                    self.assertTrue(any("another device" in w or "could not be verified" in w
                                        for w in report["warnings"]))
        self.assertIn("agent.name", self.last_body["_source"])
        report = self.wazuh_response(payload("test-pc"))
        self.assertEqual(report["data"]["device"], {"identity": "matched", "expected_name": "test-pc",
                                                  "agent_names": ["test-pc"], "os": ["Windows 11 Pro"]})

    def test_wazuh_zero_records_is_not_completed(self):
        report = self.wazuh_response({"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}})
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["findings"], [])
        self.assertTrue(any("agent_id" in warning for warning in report["warnings"]))

    def test_wazuh_incomplete_and_invalid_payloads(self):
        for payload, status in [({"hits": {"total": 0, "hits": []}, "timed_out": True}, "partial"),
                                ({"hits": {"total": 0, "hits": []}, "_shards": {"failed": 1}}, "partial"),
                                ({"unexpected": True}, "error")]:
            with self.subTest(payload=payload):
                self.assertEqual(self.wazuh_response(payload)["status"], status)

    def test_redirect_rejected(self):
        with self.assertRaises(ScannerError):
            NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other")

    def test_cli_rejects_huge_cursor_as_json_error(self):
        config = self.root / "config.toml"
        config.write_text('[wazuh]\nurl = "https://127.0.0.1:9"\nagent_id = "001"\n')
        cursor = base64.urlsafe_b64encode(json.dumps([10 ** 400, "a", "b", "c", "d", "e", "f"]).encode()).decode()
        run = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config),
                              "vulnerabilities", "--cursor", cursor], capture_output=True, text=True,
                             env={**os.environ, "PC_SCANNER_WAZUH_USER": "r", "PC_SCANNER_WAZUH_PASSWORD": "p"})
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertEqual(json.loads(run.stdout)["status"], "error")
        self.assertNotIn("Traceback", run.stderr)

    def test_cli_json_and_failure_exit(self):
        config = self.root / "config.toml"
        config.write_text("[local]\n")
        command = [sys.executable, "-m", "pc_scanner.cli", "--config", str(config)]
        status = subprocess.run(command + ["status"], capture_output=True, text=True)
        self.assertEqual(status.returncode, 0)
        self.assertEqual(json.loads(status.stdout)["source"], "bridge")
        failed = subprocess.run(command + ["inventory", "os_version"], capture_output=True, text=True)
        self.assertEqual(failed.returncode, 2)
        self.assertEqual(json.loads(failed.stdout)["status"], "error")


if __name__ == "__main__":
    unittest.main()
