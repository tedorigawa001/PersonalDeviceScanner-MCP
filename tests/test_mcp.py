"""Real stdio MCP round trip, optional SDK required."""
import asyncio
import importlib.util
import json
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

class SlowScanner:
    """Stands in for engines that take a long time, recording overlap."""

    roots = {"test": ""}
    android_devices = {}
    routers = {}
    router_settings = {"jvn_lookup": False}
    update_lookup = False

    def __init__(self, delay):
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()

    def invoke(self, operation, **kwargs):
        self.last_kwargs = kwargs
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(self.delay)
        with self.lock:
            self.active -= 1
        return {"source": operation, "status": "completed", "findings": [], "warnings": []}

class CancellableScanner:
    """Stands in for an engine that runs until it is told to stop."""

    roots = {"test": ""}
    android_devices = {}
    routers = {}
    router_settings = {"jvn_lookup": False}
    update_lookup = False

    def __init__(self):
        self.started = threading.Event()
        self.stopped_by_cancel = False

    def invoke(self, operation, cancel=None, **kwargs):
        self.started.set()
        self.stopped_by_cancel = cancel is not None and cancel.wait(5)
        return {"source": operation, "status": "error", "findings": [], "warnings": []}

@unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
class MCPTests(unittest.TestCase):
    def test_batch_and_resume_over_mcp_reuse_unchanged_parts(self):
        from unittest.mock import patch
        from datetime import datetime, timezone
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.core import Scanner
        from pc_scanner.server import create_server

        async def exercise(root):
            home = root / "home"
            home.mkdir()
            (home / "one.txt").write_text("test")
            scanner = Scanner({"local": {"clamav_binary": sys.executable},
                               "scan_roots": {"test": str(home)},
                               "history": {"file": str(root / "state" / "history.jsonl")}})
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                for argument, reused in (("batch", 0), ("resume", 1)):
                    reply = await session.call_tool("scan_malware", {"root_alias": "test", argument: True})
                    self.assertFalse(reply.isError)
                    report = json.loads(reply.content[0].text)
                    self.assertEqual(report["status"], "completed")
                    self.assertEqual(report["data"]["batch"]["reused"], reused)
                    self.assertEqual(report["data"]["engine_counts"]["scanned"], 1)
        with tempfile.TemporaryDirectory() as directory, patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": "test", "version": 42, "built_at": datetime.now(timezone.utc)}), patch(
                "pc_scanner.core.run_bounded", return_value=(0, "Scanned files: 1\nInfected files: 0\n", "")) as engine:
            asyncio.run(exercise(Path(directory)))
            self.assertEqual(engine.call_count, 1)

    def test_cloud_placeholder_is_partial_over_mcp(self):
        from unittest.mock import patch
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.core import Scanner
        from pc_scanner.server import create_server

        async def exercise(root):
            # Version is checked before traversal, but a cloud-only target never starts a scan.
            scanner = Scanner({"local": {"clamav_binary": sys.executable}, "scan_roots": {"test": str(root)}})
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                reply = await session.call_tool("scan_malware", {"root_alias": "test", "relative_path": "remote.txt"})
                self.assertFalse(reply.isError)
                report = json.loads(reply.content[0].text)
                self.assertEqual(report["status"], "partial")
                self.assertFalse(report["data"]["scan_started"])
                self.assertEqual(report["data"]["cloud_excluded_paths"], ["remote.txt"])
                self.assertTrue(any("cloud placeholder" in warning for warning in report["warnings"]))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "remote.txt").write_text("test")
            with patch("pc_scanner.core.cloud_placeholder", return_value=True), patch(
                    "pc_scanner.core.clamav_signatures", return_value={
                        "engine": "test", "version": 1, "built_at": datetime.now(timezone.utc)}), patch(
                    "pc_scanner.core.run_bounded", side_effect=AssertionError("cloud target must not scan")):
                asyncio.run(exercise(root))

    def test_stdio_round_trip(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        async def exercise(config):
            params = StdioServerParameters(command=sys.executable, args=[
                "-m", "pc_scanner.cli", "--config", str(config), "serve"])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = {t.name: t for t in (await session.list_tools()).tools}
                    self.assertEqual(set(tools), {
                    "scanner_status", "get_scan_progress", "check_clamav_signatures", "collect_inventory", "scan_malware", "get_vulnerabilities",
                    "list_malware_gaps", "rescan_malware_targets", "discover_lan_devices", "observe_outbound_connections", "review_processes", "check_connection_destinations",
                        "collect_android", "check_android_monitoring_apps", "check_router"})
                    # No JVN lookup configured, so the router check stays on this PC.
                    self.assertFalse(tools["check_router"].annotations.openWorldHint)
                    self.assertEqual(tools["collect_android"].inputSchema["properties"]["query_id"]["enum"],
                                     ["device", "apps", "privileged_access"])
                    self.assertEqual(tools["collect_inventory"].inputSchema["properties"]["query_id"]["enum"],
                                     ["os_version", "applications", "listening_ports"])
                    self.assertIn("downloads", tools["scan_malware"].description)
                    self.assertTrue(all(t.annotations.readOnlyHint for t in tools.values()))
                    call = await session.call_tool("scanner_status", {})
                    self.assertFalse(call.isError)
                    report = json.loads(call.content[0].text)
                    self.assertEqual(report["status"], "completed")
                    failed = await session.call_tool("collect_inventory", {"query_id": "DROP TABLE users"})
                    self.assertTrue(failed.isError)

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "scanner.toml"
            config.write_text(f"[local]\n[scan_roots]\ndownloads = {json.dumps(directory)}\n"
                              f"[history]\nfile = {json.dumps(str(Path(directory) / 'history.jsonl'))}\n")
            asyncio.run(exercise(config))

    def test_long_scan_reports_progress(self):
        from unittest.mock import patch
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server

        scanner = SlowScanner(delay=0.5)
        updates = []

        async def on_progress(progress, total, message):
            updates.append(progress)

        async def exercise():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                await session.call_tool("scan_malware", {"root_alias": "test"}, progress_callback=on_progress)

        with patch("pc_scanner.server.HEARTBEAT_SECONDS", 0.1):
            asyncio.run(exercise())
        self.assertGreaterEqual(len(updates), 2)
        self.assertEqual(updates, sorted(updates))

    def test_long_scan_does_not_block_server(self):
        import anyio
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server

        scanner = SlowScanner(delay=1.0)

        async def exercise():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                async with anyio.create_task_group() as group:
                    group.start_soon(session.call_tool, "scan_malware", {"root_alias": "test"})
                    await anyio.sleep(0.2)
                    with anyio.fail_after(0.5):
                        await session.send_ping()
                    self.assertEqual(scanner.active, 1, "ping must be answered while the scan runs")

        asyncio.run(exercise())

    def test_cancel_stops_running_engine(self):
        import anyio
        import mcp.types as types
        from mcp.shared.exceptions import McpError
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server

        scanner = CancellableScanner()

        async def exercise():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                request_id = session._request_id  # id the next request will use

                async def call():
                    with self.assertRaises(McpError):
                        await session.call_tool("scan_malware", {"root_alias": "test"})

                async with anyio.create_task_group() as group:
                    group.start_soon(call)
                    self.assertTrue(await anyio.to_thread.run_sync(scanner.started.wait, 5))
                    await session.send_notification(types.ClientNotification(types.CancelledNotification(
                        params=types.CancelledNotificationParams(requestId=request_id))))

        asyncio.run(exercise())
        self.assertTrue(scanner.stopped_by_cancel, "cancellation must reach the running engine")

    def test_wazuh_requests_are_serialized_and_cancellable(self):
        import anyio
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server

        scanner = SlowScanner(delay=0.2)

        async def exercise():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                tools = {t.name: t for t in (await session.list_tools()).tools}
                self.assertEqual(set(tools["get_vulnerabilities"].inputSchema["properties"]), {"cursor"})
                async with anyio.create_task_group() as group:
                    for _ in range(3):
                        group.start_soon(session.call_tool, "get_vulnerabilities", {})

        asyncio.run(exercise())
        self.assertEqual(scanner.max_active, 1)
        self.assertIn("cancel", scanner.last_kwargs)

    def test_engine_runs_are_serialized(self):
        import anyio
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server

        scanner = SlowScanner(delay=0.2)

        async def exercise():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                async with anyio.create_task_group() as group:
                    group.start_soon(session.call_tool, "scan_malware", {"root_alias": "test"})
                    group.start_soon(session.call_tool, "scan_malware", {"root_alias": "test"})
                    group.start_soon(session.call_tool, "collect_inventory", {"query_id": "os_version"})

        asyncio.run(exercise())
        self.assertEqual(scanner.max_active, 1)
