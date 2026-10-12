import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from pc_scanner.core import NoRedirect, Scanner, ScannerError, run_bounded


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "sample.txt").write_text("ordinary test file")
        self.scanner = Scanner({"local": {"clamav_binary": sys.executable,
                                          "osquery_binary": sys.executable},
                                "scan_roots": {"test": str(self.root)}})

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

    def test_config_rejects_http_and_relative_binary(self):
        for config in ({"wazuh": {"url": "http://localhost:9200", "agent_id": "001"}},
                       {"wazuh": {"url": "https://user:pass@localhost:9200", "agent_id": "001"}},
                       {"local": {"osquery_binary": "osqueryi"}},
                       {"local": {"timeout_seconds": 0}}):
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

    def test_unreadable_directory_is_partial_and_keeps_findings(self):
        locked = self.root / "locked"
        locked.mkdir()
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o755)
        if os.access(locked, os.R_OK):
            self.skipTest("Directory permissions are not enforced for this user")
        output = f"{self.root.resolve() / 'sample.txt'}: Test.Signature FOUND\nScanned files: 1\n"
        with patch("pc_scanner.core.run_bounded", return_value=(1, output, "")) as run:
            report = self.scanner.invoke("malware", root_alias="test")
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

    def test_runner_reports_pipes_held_by_child_process(self):
        script = ("import subprocess, sys; "
                  "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])")
        with self.assertRaisesRegex(ScannerError, "child process may still be running"):
            run_bounded([sys.executable, "-c", script], 10, 1024)

    def test_runner_timeout_and_output_limit(self):
        with self.assertRaisesRegex(ScannerError, "timed out"):
            run_bounded([sys.executable, "-c", "import time; time.sleep(3)"], 1, 1024)
        with self.assertRaisesRegex(ScannerError, "output exceeded"):
            run_bounded([sys.executable, "-c", "print('x'*10000)"], 5, 1024)

    def test_runner_does_not_pass_secrets(self):
        with patch.dict(os.environ, {"PC_SCANNER_WAZUH_PASSWORD": "secret", "OPENAI_API_KEY": "secret",
                                     "SYSTEMDRIVE": "C:"}):
            code, output, _ = run_bounded([sys.executable, "-c", "import os; print(os.getenv('PC_SCANNER_WAZUH_PASSWORD')); print(os.getenv('OPENAI_API_KEY')); print(os.getenv('SYSTEMDRIVE'))"], 5, 1024)
        self.assertEqual(code, 0)
        self.assertEqual(output.strip(), "None\nNone\nC:")

    def wazuh_response(self, payload, agent_id="001", offset=0):
        scanner = Scanner({"wazuh": {"url": "https://localhost:9200", "agent_id": agent_id}})
        response = io.BytesIO(json.dumps(payload).encode())
        with patch.dict(os.environ, {"PC_SCANNER_WAZUH_USER": "reader", "PC_SCANNER_WAZUH_PASSWORD": "secret"}), patch("pc_scanner.core.build_opener") as build:
            build.return_value.open.return_value = response
            report = scanner.invoke("vulnerabilities", offset=offset)
            request = build.return_value.open.call_args.args[0]
        self.assertEqual(request.method, "GET")
        self.last_body = json.loads(request.data)
        self.assertEqual(self.last_body["query"]["term"]["agent.id"], "001")
        self.assertNotIn("secret", json.dumps(report))
        return report

    def test_wazuh_reports_findings_and_freshness(self):
        payload = {"hits": {"total": {"value": 1, "relation": "eq"}, "hits": [{"_source": {
            "agent": {"id": "001"}, "package": {"name": "test", "version": "1"},
            "vulnerability": {"id": "CVE-TEST", "severity": "High"}}}]}}
        report = self.wazuh_response(payload)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["findings"][0]["severity"], "high")
        self.assertEqual(report["data"]["freshness"], "unverified")
        payload["hits"]["total"]["value"] = 501
        self.assertEqual(self.wazuh_response(payload)["status"], "partial")
        payload["hits"]["hits"][0]["_source"]["agent"]["id"] = "002"
        self.assertEqual(self.wazuh_response(payload)["status"], "error")

    def test_wazuh_sorts_most_severe_first_and_pages(self):
        hit = {"_source": {"agent": {"id": "001"}, "vulnerability": {
            "id": "CVE-A", "severity": "Critical", "score": {"base": 9.8}}}}
        first = self.wazuh_response({"hits": {"total": {"value": 501, "relation": "eq"}, "hits": [hit] * 500}})
        self.assertEqual(list(self.last_body["sort"][0]), ["vulnerability.score.base"])
        self.assertEqual(self.last_body["sort"][0]["vulnerability.score.base"]["order"], "desc")
        self.assertEqual(self.last_body["from"], 0)
        self.assertEqual(first["status"], "partial")
        self.assertEqual(first["data"]["next_offset"], 500)
        self.assertEqual(first["findings"][0]["score"], 9.8)
        last = self.wazuh_response({"hits": {"total": {"value": 501, "relation": "eq"}, "hits": [hit]}}, offset=500)
        self.assertEqual(self.last_body["from"], 500)
        self.assertIsNone(last["data"]["next_offset"])
        self.assertEqual(last["status"], "partial")

    def test_wazuh_agent_id_is_zero_padded(self):
        payload = {"hits": {"total": 1, "hits": [{"_source": {
            "agent": {"id": "001"}, "vulnerability": {"id": "CVE-TEST", "severity": "Low"}}}]}}
        report = self.wazuh_response(payload, agent_id="1")
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["data"]["agent_id"], "001")

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
