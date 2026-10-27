"""Read-only signature status and advice before potentially long scan traversal."""
import json
import asyncio
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pc_scanner.core import Scanner, ScannerError
from pc_scanner.progress import ScanProgress


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {"local": {"clamav_binary": sys.executable},
                       "history": {"file": str(self.root / "state" / "history.jsonl")}}

    def test_standalone_status_is_read_only_and_does_not_require_a_scan_root(self):
        built = datetime.now(timezone.utc) - timedelta(hours=1)
        with patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": "1.5.4", "version": 28166, "built_at": built}):
            scanner = Scanner(self.config)
            scanner.via = "cli"
            report = scanner.invoke("check_clamav_signatures")
        self.assertEqual(report["status"], "completed")
        info = report["data"]["signature_check"]
        self.assertEqual(info["freshness"], "fresh")
        self.assertEqual(info["version"], 28166)
        self.assertEqual(info["built_at"], built.isoformat())
        self.assertFalse(info["update_performed"])
        self.assertIn("freshclam", " ".join(info["update_steps"]))
        self.assertFalse((self.root / "state").exists())

    def test_scan_publishes_advice_before_directory_walk_and_keeps_stdout_data(self):
        self.config["scan_roots"] = {"test": str(self.root)}
        (self.root / "ordinary.txt").write_text("ordinary local data")
        progress = ScanProgress()
        def walk(*args, **kwargs):
            info = progress.snapshot()["signature_check"]
            self.assertEqual(info["freshness"], "stale")
            self.assertIn("freshclam", " ".join(info["update_steps"]))
            return False, [], []
        with patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": "1.5.4", "version": 28157,
                "built_at": datetime.now(timezone.utc) - timedelta(days=8)}), patch(
                "pc_scanner.core.inspect_directories", side_effect=walk), patch(
                "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\nInfected files: 0\n", "")):
            report = Scanner(self.config).invoke("malware", root_alias="test", progress=progress)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["data"]["signature_check"]["freshness"], "stale")

    def test_exact_age_limit_and_one_microsecond_over_are_distinct(self):
        now = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
        for delta, expected in ((timedelta(days=7), "fresh"),
                                (timedelta(days=7, microseconds=1), "stale")):
            with self.subTest(expected=expected), patch("pc_scanner.core.datetime") as clock, patch(
                    "pc_scanner.core.clamav_signatures", return_value={
                        "engine": "1.5.4", "version": 1, "built_at": now - delta}):
                clock.now.return_value = now
                info = Scanner(self.config).invoke("check_clamav_signatures")["data"]["signature_check"]
                self.assertEqual(info["freshness"], expected)
                self.assertFalse(info["update_performed"])

    def test_missing_or_future_date_is_unknown_not_fresh(self):
        for built in (None, datetime.now(timezone.utc) + timedelta(days=1)):
            with self.subTest(built=built), patch("pc_scanner.core.clamav_signatures", return_value={
                    "engine": "1.5.4", "version": None, "built_at": built}):
                report = Scanner(self.config).invoke("check_clamav_signatures")
                self.assertEqual(report["status"], "partial")
                self.assertEqual(report["data"]["signature_check"]["freshness"], "unknown")

    def test_failed_check_is_distinct_and_never_starts_a_folder_walk(self):
        self.config["scan_roots"] = {"test": str(self.root)}
        with patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": None, "version": None, "built_at": None}), patch(
                "pc_scanner.core.inspect_directories", side_effect=AssertionError("must not walk")):
            for operation, kwargs in (("check_clamav_signatures", {}), ("malware", {"root_alias": "test"})):
                report = Scanner(self.config).invoke(operation, **kwargs)
                self.assertEqual(report["status"], "error")
                self.assertEqual(report["data"]["signature_check"]["freshness"], "check_failed")

    def test_read_only_check_only_executes_version_and_has_no_release_lookup(self):
        self.config["updates"] = {"lookup": True}
        with patch("pc_scanner.core.run_bounded", return_value=(0, "ClamAV 1.5.4", "")) as engine, patch(
                "pc_scanner.updates.check", side_effect=AssertionError("no network lookup")):
            report = Scanner(self.config).invoke("check_clamav_signatures")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(engine.call_count, 1)
        self.assertEqual(engine.call_args.args[0], [str(Path(sys.executable).resolve()), "--version"])
        self.assertLessEqual(engine.call_args.args[1], 30)
        self.assertFalse((self.root / "state").exists())

    def test_cancelled_check_never_launches_an_engine(self):
        import threading
        cancel = threading.Event()
        cancel.set()
        with patch("pc_scanner.core.run_bounded", side_effect=AssertionError("must not run")):
            report = Scanner(self.config).invoke("check_clamav_signatures", cancel=cancel)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["data"]["signature_check"]["freshness"], "check_failed")

    def test_scan_error_after_advice_preserves_the_pre_scan_check(self):
        self.config["scan_roots"] = {"test": str(self.root)}
        with patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": "1.5.4", "version": 1, "built_at": datetime.now(timezone.utc)}), patch(
                "pc_scanner.core.inspect_directories", side_effect=ScannerError("Directory coverage check timed out")):
            report = Scanner(self.config).invoke("malware", root_alias="test")
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["data"]["signature_check"]["freshness"], "fresh")

    def test_unauthorized_alias_is_rejected_before_starting_definition_check(self):
        with patch("pc_scanner.core.run_bounded", side_effect=AssertionError("must not start")):
            report = Scanner(self.config).invoke("malware", root_alias="not_authorized")
        self.assertEqual(report["error"], "Scan root alias is not authorized")

    def test_cli_status_command_returns_one_json_without_updating(self):
        config = self.root / "scanner.toml"
        config.write_text('[local]\nclamav_binary=' + json.dumps(sys.executable) + '\n')
        # Python --version is deliberately not a valid ClamAV response.
        process = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config),
                                  "check-clamav-signatures"], text=True, capture_output=True, timeout=10)
        report = json.loads(process.stdout)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(report["data"]["signature_check"]["freshness"], "check_failed")
        self.assertFalse(report["data"]["signature_check"]["update_performed"])

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_mcp_tool_is_local_read_only_and_works_without_scan_roots(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def exercise():
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                annotations = tools["check_clamav_signatures"].annotations
                self.assertTrue(annotations.readOnlyHint)
                self.assertFalse(annotations.openWorldHint)
                reply = await session.call_tool("check_clamav_signatures", {})
                report = json.loads(reply.content[0].text)
                self.assertEqual(report["status"], "completed")
                self.assertFalse(report["data"]["signature_check"]["update_performed"])
        with patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": "1.5.4", "version": 1, "built_at": datetime.now(timezone.utc)}):
            asyncio.run(exercise())

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_mcp_pre_scan_advice_is_delivered_before_walking(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        messages = []
        self.config["scan_roots"] = {"test": str(self.root)}
        (self.root / "ordinary.txt").write_text("ordinary")
        async def callback(progress, total, message):
            messages.append(message)
        def walk(*args, **kwargs):
            self.assertTrue(any("definitions=stale" in m and "freshclam" in m for m in messages))
            return False, [], []
        async def exercise():
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                reply = await session.call_tool("scan_malware", {"root_alias": "test"}, progress_callback=callback)
                self.assertEqual(json.loads(reply.content[0].text)["status"], "partial")
        with patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": "1.5.4", "version": 1, "built_at": datetime.now(timezone.utc) - timedelta(days=8)}), patch(
                "pc_scanner.core.inspect_directories", side_effect=walk), patch(
                "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\nInfected files: 0\n", "")):
            asyncio.run(exercise())

    def test_time_limit_stops_actual_signature_check_child(self):
        import os
        import time
        from pc_scanner.core import run_bounded
        self.config["local"]["timeout_seconds"] = 1
        marker = self.root / "child.pid"
        code = "import os,time; from pathlib import Path; Path(%r).write_text(str(os.getpid())); time.sleep(30)" % str(marker)
        def engine(argv, timeout, limit, **kwargs):
            return run_bounded([sys.executable, "-c", code], timeout, limit, **kwargs)
        started = time.monotonic()
        with patch("pc_scanner.core.run_bounded", side_effect=engine):
            report = Scanner(self.config).invoke("check_clamav_signatures", progress=ScanProgress())
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["data"]["progress"]["stage"], "timed_out")
        self.assertEqual(report["data"]["signature_check"]["freshness"], "check_failed")
        self.assertTrue(marker.exists())
        # POSIX kill(pid, 0) does not carry Windows process-probe semantics.
        if os.name != "nt":
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)

    def test_pre_scan_probe_and_engine_share_one_time_budget(self):
        import time
        from pc_scanner.core import run_bounded
        self.config["local"]["timeout_seconds"] = 1
        self.config["scan_roots"] = {"test": str(self.root)}
        (self.root / "ordinary.txt").write_text("ordinary")
        checks = []
        def signatures(*args, **kwargs):
            if not checks:
                time.sleep(0.6)
            checks.append(True)
            return {"engine": "1.5.4", "version": 1, "built_at": datetime.now(timezone.utc)}
        def engine(argv, timeout, limit, **kwargs):
            self.assertLess(timeout, 0.5, "pre-scan probe time must not reset the scan deadline")
            return run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], timeout, limit, **kwargs)
        with patch("pc_scanner.core.clamav_signatures", side_effect=signatures), patch(
                "pc_scanner.core.run_bounded", side_effect=engine):
            report = Scanner(self.config).invoke("malware", root_alias="test", progress=ScanProgress())
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["data"]["progress"]["stage"], "timed_out")
        self.assertEqual(report["data"]["signature_check"]["freshness"], "fresh")

    def test_engine_version_is_escaped_before_displaying_advice(self):
        from pc_scanner.progress import message
        progress = ScanProgress()
        with patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": "bad\n\u202eevil", "version": 1, "built_at": datetime.now(timezone.utc)}):
            Scanner(self.config).invoke("check_clamav_signatures", progress=progress)
        displayed = message(progress.snapshot())
        self.assertNotIn("\n", displayed)
        self.assertNotIn("\u202e", displayed)
