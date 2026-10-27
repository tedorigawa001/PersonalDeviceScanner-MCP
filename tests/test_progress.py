"""Progress observations through Scanner, CLI and the actual MCP transport."""
import json
import asyncio
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pc_scanner.core import Scanner
from pc_scanner.progress import ScanProgress


class ProgressTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "home"
        self.root.mkdir()
        for name in ("a.txt", "b.txt"):
            (self.root / name).write_text("ordinary test data")
        self.config = {"local": {"clamav_binary": sys.executable},
                       "scan_roots": {"test": str(self.root)},
                       "history": {"file": str(self.base / "state" / "history.jsonl")}}
        self.enterContext(patch("pc_scanner.core.clamav_signatures", return_value={
            "engine": "test", "version": 42, "built_at": datetime.now(timezone.utc)}))

    def test_cancel_after_part_reports_actual_checkpoint_and_pending_counts(self):
        progress = ScanProgress()
        self.assertIsNone(progress.snapshot()["pending"])
        cancel = threading.Event()
        seen = []
        def engine(*args, **kwargs):
            seen.append(progress.snapshot())
            cancel.set()
            return 0, "Scanned files: 1\nInfected files: 0\n", ""
        with patch("pc_scanner.core.run_bounded", side_effect=engine):
            report = Scanner(self.config).invoke("malware", root_alias="test", batch=True,
                                                 cancel=cancel, progress=progress)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(seen[0]["stage"], "scanning")
        state = report["data"]["progress"]
        self.assertEqual(state["stage"], "cancelled")
        self.assertEqual((state["finished"], state["pending"], state["reused"]), (1, 1, 0))
        self.assertEqual(state["checkpoint"], "saved")
        self.assertEqual(state["saved_parts"], 1)
        self.assertGreaterEqual(state["elapsed_seconds"], 0)

    def test_cli_progress_uses_stderr_and_leaves_one_json_result_on_stdout(self):
        config = self.base / "scanner.toml"
        config.write_text('[local]\nclamav_binary = ' + json.dumps(sys.executable)
                          + '\n[scan_roots]\ntest = ' + json.dumps(str(self.root))
                          + '\n[history]\nfile = ' + json.dumps(self.config["history"]["file"]) + '\n')
        process = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config),
                                  "malware", "test", "--batch"], capture_output=True, text=True, timeout=15)
        report = json.loads(process.stdout)
        self.assertIn("pc-scanner progress: stage=", process.stderr)
        self.assertIn("checkpoint=saved saved_parts=2", process.stderr)
        self.assertEqual(report["data"]["progress"]["saved_parts"], 2)
        self.assertNotIn(str(self.root), process.stderr)

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_mcp_final_notification_contains_real_counts_and_no_names(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        messages = []
        numbers = []
        totals = []
        async def callback(progress, total, message):
            numbers.append(progress)
            totals.append(total)
            messages.append(message)
        async def exercise():
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                reply = await session.call_tool("scan_malware", {"root_alias": "test", "batch": True},
                                                progress_callback=callback)
                report = json.loads(reply.content[0].text)
                self.assertEqual(report["data"]["progress"]["pending"], 0)
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\nInfected files: 0\n", "")):
            asyncio.run(exercise())
        self.assertTrue(messages)
        self.assertIn("stage=completed", messages[-1])
        self.assertIn("finished=2 pending=0 reused=0", messages[-1])
        self.assertIn("checkpoint=saved saved_parts=2", messages[-1])
        self.assertEqual(numbers, sorted(numbers))
        self.assertTrue(all(t is None for t in totals))
        self.assertTrue(all(str(self.root) not in m and "a.txt" not in m for m in messages))

    def test_failed_save_keeps_last_durable_count_separate_from_observed_work(self):
        from pc_scanner.history import replace_private
        progress = ScanProgress()
        writes = []
        def save(path, data):
            writes.append(path)
            if len(writes) == 2:
                raise OSError("test disk failure")
            return replace_private(path, data)
        with patch("pc_scanner.history.replace_private", side_effect=save), patch(
                "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\nInfected files: 0\n", "")):
            report = Scanner(self.config).invoke("malware", root_alias="test", batch=True, progress=progress)
        state = report["data"]["progress"]
        self.assertEqual(report["status"], "partial")
        self.assertEqual(state["finished"], 1)
        self.assertEqual(state["checkpoint"], "write_failed")
        self.assertEqual(state["saved_parts"], 0)

    def test_resumed_counts_match_result_and_do_not_expose_paths(self):
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\nInfected files: 0\n", "")):
            Scanner(self.config).invoke("malware", root_alias="test", batch=True)
            report = Scanner(self.config).invoke("malware", root_alias="test", resume=True, progress=ScanProgress())
        state = report["data"]["progress"]
        self.assertEqual((state["finished"], state["pending"], state["reused"]), (2, 0, 2))
        self.assertEqual(state["saved_parts"], 2)
        self.assertNotIn("a.txt", json.dumps(state))

    def test_timeout_reports_saved_work_and_stops_real_child(self):
        from pc_scanner.core import run_bounded
        config = {**self.config, "local": {**self.config["local"], "timeout_seconds": 1}}
        def engine(argv, timeout, limit, **kwargs):
            if Path(argv[-1]).name == "b.txt":
                return run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], timeout, limit, **kwargs)
            return 0, "Scanned files: 1\nInfected files: 0\n", ""
        with patch("pc_scanner.core.run_bounded", side_effect=engine):
            report = Scanner(config).invoke("malware", root_alias="test", batch=True, progress=ScanProgress())
        state = report["data"]["progress"]
        self.assertEqual(state["stage"], "timed_out")
        self.assertEqual((state["saved_parts"], state["pending"]), (1, 1))

    @unittest.skipIf(os.name == "nt", "POSIX SIGINT test; MCP cancellation is tested on all platforms")
    def test_cli_ctrl_c_reports_saved_checkpoint_and_stops_child_without_traceback(self):
        config = self.base / "scanner.toml"
        config.write_text('[local]\nclamav_binary = ' + json.dumps(sys.executable)
                          + '\n[scan_roots]\ntest = ' + json.dumps(str(self.root))
                          + '\n[history]\nfile = ' + json.dumps(self.config["history"]["file"]) + '\n')
        marker = self.base / "child.pid"
        bootstrap = '''
import sys
from pathlib import Path
from datetime import datetime, timezone
from pc_scanner import core, cli
config, marker = sys.argv[1:]
real = core.run_bounded
built = datetime.now(timezone.utc)
core.clamav_signatures = lambda *a, **k: {"engine": "test", "version": 42, "built_at": built}
def engine(argv, timeout, limit, **kwargs):
    if Path(argv[-1]).name == "b.txt":
        code = "import os,time; from pathlib import Path; Path(%r).write_text(str(os.getpid())); time.sleep(30)" % marker
        return real([sys.executable, "-c", code], timeout, limit, **kwargs)
    return 0, "Scanned files: 1\\nInfected files: 0\\n", ""
core.run_bounded = engine
sys.argv = ["pc-scanner", "--config", config, "malware", "test", "--batch"]
cli.main()
'''
        process = subprocess.Popen([sys.executable, "-u", "-c", bootstrap, str(config), str(marker)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and time.monotonic() < deadline and process.poll() is None:
                time.sleep(0.01)
            self.assertTrue(marker.exists(), "the second engine must actually start")
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 2)
            state = json.loads(stdout)["data"]["progress"]
            self.assertEqual(state["stage"], "cancelled")
            self.assertEqual((state["saved_parts"], state["pending"]), (1, 1))
            self.assertIn("stage=cancelled", stderr)
            self.assertNotIn("Traceback", stderr)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(marker.read_text()), 0)
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=5)

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_mcp_cancel_keeps_the_saved_state_without_notifying_a_finished_request(self):
        # Found in the review of 2026-10-27: a final notification was sent after the client had
        # cancelled. MCP progress may only refer to requests in progress, and the TypeScript SDK
        # reports a notification for a token it no longer tracks as an error.
        import anyio
        import mcp.types as types
        from mcp.server.session import ServerSession
        from mcp.shared.exceptions import McpError
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        from pc_scanner.core import ScannerError
        started = threading.Event()
        messages, sent = [], []
        original_send = ServerSession.send_progress_notification
        async def record_send(session, progress_token, progress, total=None, message=None, **kwargs):
            sent.append(message)
            return await original_send(session, progress_token, progress, total, message, **kwargs)
        def engine(argv, *a, **k):
            if Path(argv[-1]).name == "b.txt":
                started.set()
                self.assertTrue(k["cancel"].wait(5))
                raise ScannerError("Scan cancelled; engine stopped before completing")
            return 0, "Scanned files: 1\nInfected files: 0\n", ""
        async def callback(progress, total, message):
            messages.append(message)
        async def exercise():
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                request_id = session._request_id
                async def call():
                    with self.assertRaises(McpError):
                        await session.call_tool("scan_malware", {"root_alias": "test", "batch": True},
                                                progress_callback=callback)
                async with anyio.create_task_group() as group:
                    group.start_soon(call)
                    self.assertTrue(await anyio.to_thread.run_sync(started.wait, 5))
                    await session.send_notification(types.ClientNotification(types.CancelledNotification(
                        params=types.CancelledNotificationParams(requestId=request_id))))
                # The SDK may remove the callback before a cancelled worker finishes. Querying
                # the retained state is the reliable way to read its eventual saved checkpoint.
                with anyio.fail_after(3):
                    while True:
                        reply = await session.call_tool("get_scan_progress", {})
                        state = json.loads(reply.content[0].text)["data"]
                        if state["stage"] == "cancelled":
                            break
                        await anyio.sleep(0.01)
                self.assertEqual(state["saved_parts"], 1)
                self.assertEqual(state["checkpoint"], "saved")
                self.assertEqual(state["pending"], 1)
                self.assertNotIn(str(self.root), json.dumps(state))
        with patch("pc_scanner.core.run_bounded", side_effect=engine), \
                patch.object(ServerSession, "send_progress_notification", record_send):
            asyncio.run(exercise())
        self.assertTrue(any("scan_id=" in m for m in messages))
        self.assertTrue(sent)
        self.assertFalse([m for m in sent if "stage=cancelled" in m], sent)

    def test_warning_text_does_not_forge_a_timeout_stage(self):
        config = {**self.config, "local": {**self.config["local"], "timed out": True}}
        with patch("pc_scanner.core.run_bounded", return_value=(2, "Scanned files: 1\nInfected files: 0\n", "")):
            report = Scanner(config).invoke("malware", root_alias="test", batch=True, progress=ScanProgress())
        self.assertEqual(report["data"]["progress"]["stage"], "partial")

    def test_ordinary_scan_does_not_claim_to_have_a_checkpoint(self):
        with patch("pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 2\nInfected files: 0\n", "")):
            report = Scanner(self.config).invoke("malware", root_alias="test", progress=ScanProgress())
        state = report["data"]["progress"]
        self.assertEqual((state["finished"], state["pending"]), (1, 0))
        self.assertEqual(state["checkpoint"], "not_applicable")
        self.assertIsNone(state["saved_parts"])

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_mcp_streams_real_mid_scan_counters_and_elapsed_time(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        messages = []
        def engine(*a, **k):
            time.sleep(0.15)
            return 0, "Scanned files: 1\nInfected files: 0\n", ""
        async def callback(progress, total, message):
            messages.append((progress, message))
        async def exercise():
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                await session.call_tool("scan_malware", {"root_alias": "test", "batch": True}, progress_callback=callback)
        with patch("pc_scanner.server.HEARTBEAT_SECONDS", 0.03), patch("pc_scanner.core.run_bounded", side_effect=engine):
            asyncio.run(exercise())
        self.assertTrue(any("stage=scanning" in m and "finished=1 pending=1 reused=0" in m
                            and "checkpoint=saved saved_parts=1" in m for _, m in messages))
        values = [v for v, _ in messages]
        self.assertEqual(values, sorted(values))
        self.assertGreater(values[-1], values[0])

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_mcp_progress_query_is_bounded_and_unknown_ids_are_errors(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def exercise():
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                ids = []
                for _ in range(3):
                    reply = await session.call_tool("scan_malware", {"root_alias": "test", "batch": True})
                    ids.append(json.loads(reply.content[0].text)["data"]["progress"]["scan_id"])
                for key, expected in ((ids[0], "error"), (ids[-1], "completed"), ("unrecognized", "error")):
                    reply = await session.call_tool("get_scan_progress", {"scan_id": key})
                    self.assertEqual(json.loads(reply.content[0].text)["status"], expected)
        with patch("pc_scanner.server.MAX_PROGRESS_RECORDS", 2), patch("pc_scanner.core.run_bounded", return_value=(
                0, "Scanned files: 1\nInfected files: 0\n", "")):
            asyncio.run(exercise())

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_progress_notification_failure_does_not_fail_the_scan(self):
        from mcp.server.fastmcp import Context
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def broken(*a, **k):
            raise OSError("notification channel unavailable")
        async def exercise():
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                reply = await session.call_tool("scan_malware", {"root_alias": "test", "batch": True})
                report = json.loads(reply.content[0].text)
                self.assertEqual(report["status"], "completed")
                self.assertEqual(report["data"]["progress"]["saved_parts"], 2)
        with patch.object(Context, "report_progress", broken), patch("pc_scanner.core.run_bounded", return_value=(
                0, "Scanned files: 1\nInfected files: 0\n", "")):
            asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
