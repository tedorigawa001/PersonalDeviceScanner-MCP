"""Synthetic, owner-selected targets only. Never read this computer's process data."""
import copy
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from pc_scanner import process_review as p
from pc_scanner.core import Scanner, ScannerError


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.script = self.root / "private-script.js"
        self.script.write_text("throw new Error('MUST NEVER RUN');")
        self.package = self.root / "package.json"
        self.package.write_text(json.dumps({"dependencies": {"private-dependency": "1.0"}}))
        self.launch = self.root / "private-job.plist"
        self.launch.write_bytes(plistlib.dumps({"Label": "private.job", "ProgramArguments": [
            "/private/node", str(self.script)], "RunAtLoad": True, "KeepAlive": True}))
        self.target = {"pid": 42, "start_time": 1000, "script_file": str(self.script),
                       "package_file": str(self.package), "launch_file": str(self.launch)}
        self.row = {"pid": "42", "start_time": "1000", "path": "/private/node", "name": "private-name",
                    "parent": "1", "parent_path": "/private/parent", "parent_start_time": "10"}
        # Enabled but in this temporary folder, never the owner's real history: any save would appear here.
        self.history_file = self.root / "history.jsonl"
        # The loaded job as `launchctl print` shows it: one tab for top-level fields, two inside blocks.
        self.job = (f"\tpath = {self.launch}\n\tprogram = /private/node\n\tpid = 42\n"
                    f"\targuments = {{\n\t\t/private/node\n\t\t{self.script}\n\t}}\n")

    def scanner(self, target=None, **settings):
        return Scanner({"history": {"enabled": True, "details": True, "file": str(self.history_file)}, "process_review": {
            "enabled": True, "targets": {"private-alias": self.target if target is None else target}, **settings}})

    def invoke(self, scanner=None, rows=None, query=None, **kwargs):
        scanner = scanner or self.scanner()
        with patch.object(p.Backend, "__init__", return_value=None), \
             patch.object(p.Backend, "limits", set(), create=True), \
             patch.object(p.Backend, "query", return_value=[self.row] if rows is None else rows, side_effect=query), \
             patch.object(p.platform, "system", return_value="Darwin"), \
             patch("pc_scanner.core.run_bounded", return_value=(0, self.job, "")):
            return scanner.invoke("review_processes", **kwargs)

    def test_disabled_and_empty_do_not_start_engine(self):
        with patch.object(p, "Backend", side_effect=AssertionError("must not start")):
            for scanner, error in ((Scanner({}), "Process review is disabled"),
                                   (self.scanner(targets={}), "No owner-selected process review targets configured")):
                report = scanner.invoke("review_processes")
                self.assertEqual(report["status"], "error")
                # Fixed texts the owner can act on survive the anonymous view.
                self.assertEqual(p.for_mcp(report)["error"], error)

    def test_settings_and_duplicate_identity_are_rejected(self):
        for settings in [{"enabled": "yes"}, {"timeout_seconds": True}, {"timeout_seconds": 61},
                         {"targets": []}, {"targets": {"a": {"pid": "42", "start_time": 1000}}},
                         {"targets": {"a": {**self.target, "script_file": "/a/../b"}}},
                         {"targets": {"a": self.target, "b": self.target}}]:
            with self.subTest(settings=settings):
                with self.assertRaises(ScannerError) as caught:
                    self.scanner(**settings)
                self.assertIn(str(caught.exception), p.ERRORS)
        with self.assertRaises(ScannerError) as caught:
            Scanner({"process_review": 7})
        self.assertIn(str(caught.exception), p.ERRORS)

    def test_pid_reuse_and_exit_never_read_files(self):
        for rows in [[], [{**self.row, "start_time": "1001"}], [{**self.row, "pid": "43"}]]:
            with self.subTest(rows=rows), patch.object(p, "read_file", side_effect=AssertionError("stale target")):
                report = self.invoke(rows=rows)
                self.assertEqual(report["status"], "partial")
                self.assertEqual(report["data"]["processes"][0]["details"], {})

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-based file reader")
    def test_runtime_script_package_and_loaded_launch_job(self):
        dep = self.root / "node_modules/private-dependency/package.json"
        dep.parent.mkdir(parents=True)
        dep.write_text(json.dumps({"name": "private-dependency", "version": "1.0"}))
        report = self.invoke()
        row = report["data"]["processes"][0]
        self.assertEqual(report["status"], "completed")
        self.assertEqual(row["runtime"], "node")
        self.assertEqual(row["launch"], "loaded_job_pid_matches")
        self.assertEqual(row["details"]["package"]["metadata_found"], 1)
        self.assertEqual(len(row["details"]["script"]["sha256"]), 64)

    def test_anonymous_response_removes_identifiers_errors_and_warnings(self):
        scanner = self.scanner()
        scanner.via = "mcp"
        report = p.for_mcp(self.invoke(scanner))
        text = json.dumps(report)
        for value in ["private-name", "private-alias", "private.job", "private-dependency", str(self.root), "/private/node"]:
            self.assertNotIn(value, text)
        raw = copy.deepcopy(report)
        raw.update(error="secret-path", warnings=["secret-host"], findings=[{"secret": "secret"}])
        self.assertNotIn("secret", json.dumps(p.for_mcp(raw)))

    def test_metadata_query_never_collects_cmdline_environment_or_sockets(self):
        class Backend:
            def query(inner, sql):
                for forbidden in ["cmdline", "environ", "process_open_sockets", "SELECT *"]:
                    self.assertNotIn(forbidden, sql)
                self.assertIn("WHERE p.pid = 42 LIMIT 2", sql)
                return [self.row]
        self.assertEqual(p.metadata(Backend(), self.target)["pid"], "42")

    def test_cancellation_and_busy_are_bounded(self):
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(self.invoke(cancel=cancel)["data"]["stop_reason"], "cancelled")
        scanner = self.scanner()
        scanner._process_review_lock.acquire()
        try:
            self.assertEqual(p.for_mcp(self.invoke(scanner))["error"], "Process review is busy")
        finally:
            scanner._process_review_lock.release()

    def test_a_stop_marks_only_the_target_still_being_checked(self):
        # Query 2 is the first target's final check; query 1 is followed by reading its script.
        for stop_after, first, expected in ((2, {"pid": 42, "start_time": 1000}, "start_time_matches"),
                                            (1, {"pid": 42, "start_time": 1000, "script_file": str(self.script)},
                                             "not_rechecked")):
            cancel, calls = threading.Event(), []
            def query(sql, calls=calls, cancel=cancel, stop_after=stop_after):
                calls.append(sql)
                if len(calls) == stop_after:
                    cancel.set()
                return [self.row] if "p.pid = 42 " in sql else [{**self.row, "pid": "43", "start_time": "2000"}]
            scanner = self.scanner(targets={"a": first, "b": {"pid": 43, "start_time": 2000}})
            with self.subTest(stop_after=stop_after):
                report = self.invoke(scanner, query=query, cancel=cancel)
                row = report["data"]["processes"][0]
                self.assertEqual((report["data"]["stop_reason"], report["data"]["reviewed_count"]), ("cancelled", 1))
                self.assertEqual(row["identity"], expected)
                self.assertEqual(bool(row["details"]), expected == "start_time_matches")
                self.assertEqual("interrupted_before_final_identity_check" in row["attention"], expected == "not_rechecked")

    def test_history_is_never_written_through_cli_or_mcp(self):
        for via in ("cli", "mcp"):
            scanner = self.scanner()
            scanner.via = via
            with self.subTest(via=via):
                report = self.invoke(scanner)
                # A failed save would only add a warning, so check both the warning and the file.
                self.assertEqual(report["warnings"], [])
                self.assertEqual(report["data"]["persistence"], "not_saved")
                self.assertFalse(self.history_file.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-based file reader")
    def test_links_fifo_cloud_and_oversized_files_are_never_read(self):
        link = self.root / "link"
        link.symlink_to(self.script)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        big = self.root / "big"
        big.write_bytes(b"x" * (p.MAX_FILE + 1))
        hard = self.root / "hard"
        os.link(self.script, hard)
        for path in [link, fifo, big, hard]:
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                p.read_file(path, time.monotonic() + 1, None)
        with patch.object(p.core, "cloud_placeholder", return_value=True), \
             patch.object(p.os, "read", side_effect=AssertionError("no hydration")), self.assertRaises(ValueError):
            p.read_file(self.package, time.monotonic() + 1, None)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-based file reader")
    def test_parent_symlink_refused(self):
        folder = self.root / "actual"
        folder.mkdir()
        (folder / "data").write_text("x")
        link = self.root / "alias"
        link.symlink_to(folder, target_is_directory=True)
        with self.assertRaises(ValueError):
            p.read_file(link / "data", time.monotonic() + 1, None)

    def test_no_arbitrary_target_arguments_in_invoke(self):
        with patch.object(p, "Backend", side_effect=AssertionError("must not start")):
            r = self.scanner().invoke("review_processes", pid=42, script_file=str(self.script))
        self.assertEqual(r["status"], "error")

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-based file reader")
    def test_dependency_missing_and_linked_candidates_remain_unconfirmed(self):
        r = self.invoke()
        self.assertEqual(r["data"]["processes"][0]["details"]["package"]["not_found"], 1)
        self.assertEqual(r["status"], "partial")
        mod = self.root / "node_modules"
        mod.mkdir()
        (mod / "private-dependency").symlink_to(self.root, target_is_directory=True)
        r = self.invoke()
        self.assertEqual(r["data"]["processes"][0]["details"]["package"]["unavailable"], 1)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-based file reader")
    def test_launch_requires_exact_args_and_pid(self):
        target = {**self.target, "script_file": str(self.root / "different.js")}
        r = self.invoke(self.scanner(target=target))
        self.assertEqual(r["data"]["processes"][0]["launch"], "configured_mismatch")
        with patch.object(p.platform, "system", return_value="Linux"):
            info = p.launch_details(self.launch, self.row, self.target, time.monotonic()+2, None)
        self.assertEqual(info["state"], "configured_match_unverified")

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-based file reader")
    def test_loaded_job_must_come_from_the_selected_plist(self):
        # The same label and PID are not enough: another source plist, program or script stays unverified.
        for old, new in ((f"path = {self.launch}", "path = /other/private-job.plist"),
                         ("program = /private/node", "program = /other/node"),
                         (f"\t\t{self.script}\n", "\t\t/other/script.js\n"),
                         ("\tpid = 42\n", "\tpid = 43\n"),
                         ("\tpid = 42\n", "\tspawn = {\n\t\tpid = 42\n\t}\n"),
                         ("\tpid = 42\n", "\tpid = 42\n\tpid = 42\n")):
            with self.subTest(changed=new), patch.object(p.platform, "system", return_value="Darwin"), \
                 patch("pc_scanner.core.run_bounded", return_value=(0, self.job.replace(old, new), "")):
                info = p.launch_details(self.launch, self.row, self.target, time.monotonic() + 2, None)
                self.assertEqual(info["state"], "configured_match_unverified")
        with patch.object(p.platform, "system", return_value="Darwin"), \
             patch("pc_scanner.core.run_bounded", return_value=(0, self.job, "")):
            info = p.launch_details(self.launch, self.row, self.target, time.monotonic() + 2, None)
        self.assertEqual(info["state"], "loaded_job_pid_matches")

    def test_identity_changed_after_inspection_clears_attribution(self):
        calls = 0
        def metadata(*args):
            nonlocal calls
            calls += 1
            return self.row if calls == 1 else None
        with patch.object(p, "metadata", side_effect=metadata):
            report = self.invoke()
        row = report["data"]["processes"][0]
        self.assertEqual(row["details"], {})
        self.assertEqual(row["launch"], "unavailable")

    def test_cli_default_does_not_disclose_private_details(self):
        from pc_scanner import cli
        from io import StringIO
        report = self.invoke()
        report["status"] = "partial"
        report["data"]["processes"][0]["details"]["test_path"] = str(self.root)
        class Output(StringIO):
            def reconfigure(self, **kwargs): pass
        for extra in [[], ["--show-details"]]:
            out = Output()
            with patch.object(sys, "argv", ["pc-scanner", "review-processes", "--json", *extra]), \
                 patch.object(Scanner, "load", return_value=self.scanner()), \
                 patch.object(Scanner, "invoke", return_value=copy.deepcopy(report)), \
                 patch("sys.stdout", out):
                try: cli.main()
                except SystemExit as exc: self.assertEqual(exc.code, 2)
            self.assertEqual(str(self.root) in out.getvalue(), bool(extra))

    def test_cli_default_shows_fixed_errors_and_only_counts_warnings(self):
        from pc_scanner import cli
        from io import StringIO
        class Output(StringIO):
            def reconfigure(self, **kwargs): pass
        # A misspelt setting: the cause stays readable without leaving the anonymous view.
        scanner = Scanner({"history": {"enabled": False}, "process_review": {"enable": True}})
        for extra in [[], ["--show-details"]]:
            out, err = Output(), Output()
            with self.subTest(extra=extra), patch.object(sys, "argv", ["pc-scanner", "review-processes", "--json", *extra]), \
                 patch.object(Scanner, "load", return_value=scanner), patch("sys.stdout", out), patch("sys.stderr", err):
                with self.assertRaises(SystemExit):
                    cli.main()
                report = json.loads(out.getvalue())
                self.assertEqual(report["error"], "Process review is disabled")
                self.assertEqual(bool(report["warnings"]), bool(extra))
                self.assertEqual("1 warning(s) omitted" in err.getvalue(), not extra)
                if not extra:
                    self.assertNotIn("process_review.enable", out.getvalue() + err.getvalue())

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_real_mcp_transport_returns_only_anonymous_summary(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        scanner = self.scanner(target={"pid": 42, "start_time": 1000})
        scanner.via = "mcp"
        scanner.config_warnings = ["private-config-value"]
        async def run():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                tools = {t.name: t for t in (await session.list_tools()).tools}
                tool = tools["review_processes"]
                self.assertEqual(tool.inputSchema.get("properties", {}), {})
                self.assertTrue(tool.annotations.readOnlyHint)
                self.assertFalse(tool.annotations.destructiveHint)
                self.assertFalse(tool.annotations.openWorldHint)
                response = await session.call_tool("review_processes", {})
                text = response.content[0].text
                self.assertEqual(json.loads(text)["data"]["processes"][0]["runtime"], "node")
                for value in ["private-name", "/private/node", "private-config-value", "private-alias"]:
                    self.assertNotIn(value, text)
                self.assertNotIn('"pid"', text)
                self.assertLess(len(text.encode()), 64 * 1024)
        with patch.object(p.Backend, "__init__", lambda self, *a: setattr(self, "limits", set())), \
             patch.object(p.Backend, "query", return_value=[self.row]):
            asyncio.run(run())

    @unittest.skipUnless(importlib.util.find_spec("mcp"), "agent extra not installed")
    def test_real_mcp_cancellation_stops_backend(self):
        import anyio
        import mcp.types as types
        from mcp.shared.exceptions import McpError
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        started, stopped = threading.Event(), threading.Event()
        scanner = self.scanner()
        scanner.via = "mcp"
        def init(backend, scanner, deadline, cancel):
            backend.deadline, backend.cancel, backend.limits = deadline, cancel, set()
        def query(backend, sql):
            started.set()
            try:
                while True:
                    p.check(backend.deadline, backend.cancel)
                    backend.cancel.wait(.01)
            finally: stopped.set()
        async def run():
            async with create_connected_server_and_client_session(create_server(scanner)) as session:
                request_id = session._request_id
                async def call():
                    with self.assertRaises(McpError):
                        await session.call_tool("review_processes", {})
                async with anyio.create_task_group() as group:
                    group.start_soon(call)
                    self.assertTrue(await anyio.to_thread.run_sync(started.wait, 2))
                    await session.send_notification(types.ClientNotification(types.CancelledNotification(
                        params=types.CancelledNotificationParams(requestId=request_id))))
                self.assertTrue(await anyio.to_thread.run_sync(stopped.wait, 1))
                self.assertFalse(scanner._process_review_lock.locked())
        with patch.object(p.Backend, "__init__", init), patch.object(p.Backend, "query", query):
            asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
