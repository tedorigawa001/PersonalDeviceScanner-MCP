"""Real stdio MCP round trip, optional SDK required."""
import asyncio
import importlib.util
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

class SlowScanner:
    """Stands in for engines that take a long time, recording overlap."""

    roots = {"test": ""}

    def __init__(self, delay):
        self.delay = delay
        self.active = 0
        self.max_active = 0
        self.lock = threading.Lock()

    def invoke(self, operation, **kwargs):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(self.delay)
        with self.lock:
            self.active -= 1
        return {"source": operation, "status": "completed", "findings": [], "warnings": []}

@unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
class MCPTests(unittest.TestCase):
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
                        "scanner_status", "collect_inventory", "scan_malware", "get_vulnerabilities"})
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
            config.write_text(f"[local]\n[scan_roots]\ndownloads = {json.dumps(directory)}\n")
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
