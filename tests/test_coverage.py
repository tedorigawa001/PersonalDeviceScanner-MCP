import json
import asyncio
import copy
import os
import subprocess
import sys
import threading
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pc_scanner.core import Scanner
from pc_scanner import coverage, malware_batch, history, dashboard


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "files"
        self.root.mkdir()
        for name in ("a.txt", "b.txt"):
            (self.root / name).write_text("ordinary")
        self.config = {"local": {"clamav_binary": sys.executable},
                       "scan_roots": {"test": str(self.root)},
                       "history": {"file": str(self.base / "state" / "history.jsonl")}}
        self.enterContext(patch("pc_scanner.core.clamav_signatures", return_value={
            "engine": "test", "version": 1, "built_at": datetime.now(timezone.utc)}))

    @staticmethod
    def clean(*args, **kwargs):
        return 0, "Scanned files: 1\nInfected files: 0\n", ""

    def limited(self, argv, *args, **kwargs):
        return 1, f"{argv[-1]}: Heuristics.Limits.Exceeded.MaxFileSize FOUND\nScanned files: 1\nInfected files: 0\n", ""

    def batch(self):
        with patch("pc_scanner.core.run_bounded", side_effect=self.limited):
            return Scanner(self.config).invoke("malware", root_alias="test", batch=True)

    def selection(self, report, name="a.txt"):
        ledger = malware_batch.read_coverage(Scanner(self.config), "test", ".")
        info = report["data"]["coverage"]
        return {"retry": info["scan_group_id"], "revision": info["revision"],
                "target_ids": [ledger["nodes"][name]["id"]]}

    def test_cloud_gap_is_structured_and_does_not_start_an_engine(self):
        with patch("pc_scanner.core.cloud_placeholder", return_value=True), patch(
                "pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan")):
            report = Scanner(self.config).invoke("malware", root_alias="test", relative_path="a.txt")
        self.assertEqual(report["status"], "partial")
        info = report["data"]["coverage"]
        self.assertEqual(info["by_reason"], {"cloud_placeholder": 1})
        self.assertEqual(info["unresolved"]["count"], 1)
        self.assertNotIn("a.txt", json.dumps(info))

    def test_batch_cloud_retry_stays_partial_then_local_materialization_resolves_once(self):
        scanner = Scanner(self.config)
        def cloud(path):
            return Path(path).name == "b.txt"
        clean = (0, "Scanned files: 1\nInfected files: 0\n", "")
        with patch("pc_scanner.core.cloud_placeholder", side_effect=cloud), patch(
                "pc_scanner.core.run_bounded", return_value=clean):
            first = scanner.invoke("malware", root_alias="test", batch=True)
            info = first["data"]["coverage"]
            self.assertEqual(info["by_reason"], {"cloud_placeholder": 1})
            selected = first["data"]["coverage_targets"][0]["target_id"]
            with patch("pc_scanner.core.run_bounded", side_effect=AssertionError("cloud target must not scan")):
                retry = scanner.invoke("malware", root_alias="test", retry=info["scan_group_id"],
                                       revision=info["revision"], target_ids=[selected, selected])
        self.assertEqual(retry["status"], "partial")
        self.assertEqual(retry["data"]["coverage"]["by_reason"], {"cloud_placeholder": 1})
        info = retry["data"]["coverage"]
        with patch("pc_scanner.core.run_bounded", return_value=clean) as engine:
            resolved = scanner.invoke("malware", root_alias="test", retry=info["scan_group_id"],
                                      revision=info["revision"], target_ids=[selected])
        self.assertEqual(engine.call_count, 1)
        self.assertEqual(resolved["data"]["coverage"]["unresolved"]["count"], 0)
        self.assertEqual(resolved["status"], "completed")

    def test_selected_retry_replaces_one_observation_and_preserves_other_gap(self):
        first = self.batch()
        self.assertEqual(first["data"]["coverage"]["by_reason"], {"file_size_limit": 2})
        with patch("pc_scanner.core.run_bounded", side_effect=self.clean) as engine:
            second = Scanner(self.config).invoke("malware", root_alias="test", **self.selection(first))
        self.assertEqual(engine.call_count, 1)
        self.assertEqual(Path(engine.call_args.args[0][-1]).name, "a.txt")
        self.assertEqual(second["status"], "partial")
        self.assertEqual(second["data"]["attempt"]["status"], "completed")
        self.assertEqual(second["data"]["coverage"]["by_reason"], {"file_size_limit": 1})
        self.assertEqual(len(second["findings"]), 1)
        self.assertEqual(second["findings"][0]["path"], "b.txt")

    def test_same_partial_result_reused_repeatedly_does_not_inflate_gaps(self):
        self.batch()
        with patch("pc_scanner.core.run_bounded", side_effect=AssertionError("must reuse")):
            for _ in range(3):
                report = Scanner(self.config).invoke("malware", root_alias="test", resume=True)
                self.assertEqual(report["data"]["coverage"]["unresolved"]["count"], 2)
                self.assertEqual(report["data"]["coverage"]["by_reason"], {"file_size_limit": 2})
                self.assertEqual(len(report["findings"]), 2)

    def test_multiple_reasons_and_duplicate_notifications_count_one_scope(self):
        ledger = coverage.new_ledger()
        coverage.replace_scope(ledger, "a.txt", [coverage.issue("a.txt", "file_size_limit"),
            coverage.issue("a.txt", "archive_limit"), coverage.issue("a.txt", "file_size_limit")])
        result = coverage.summary(ledger)
        self.assertEqual(result["unresolved"]["count"], 1)
        self.assertEqual(result["by_reason"], {"archive_limit": 1, "file_size_limit": 1})

    def test_unknown_limit_is_not_guessed_from_warning_text(self):
        def engine(argv, *args, **kwargs):
            return 1, f"{argv[-1]}: Heuristics.Limits.Exceeded.NewUnknown FOUND\nScanned files: 1\nInfected files: 0\n", ""
        with patch("pc_scanner.core.run_bounded", side_effect=engine):
            report = Scanner(self.config).invoke("malware", root_alias="test", relative_path="a.txt")
        self.assertEqual(report["data"]["coverage"]["by_reason"], {"engine_limit_unknown": 1})

    def test_stale_revision_forged_id_and_foreign_group_start_no_engine(self):
        first = self.batch()
        args = self.selection(first)
        for changes in ({"revision": args["revision"] - 1}, {"target_ids": ["0" * 32]},
                        {"retry": "f" * 32}, {"target_ids": ["../a.txt"]}):
            with self.subTest(changes=changes), patch("pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan")):
                report = Scanner(self.config).invoke("malware", root_alias="test", **{**args, **changes})
                self.assertEqual(report["status"], "error")

    def test_changed_definition_context_requires_explicit_resume(self):
        first = self.batch()
        args = self.selection(first)
        with patch("pc_scanner.core.clamav_signatures", return_value={
                "engine": "test", "version": 2, "built_at": datetime.now(timezone.utc)}), patch(
                "pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan")):
            report = Scanner(self.config).invoke("malware", root_alias="test", **args)
        self.assertEqual(report["status"], "error")
        self.assertIn("context changed", report["error"])

    def test_metadata_unavailable_during_retry_never_means_local(self):
        first = self.batch()
        args = self.selection(first)
        real = coverage.metadata
        def observed(path):
            return ("metadata_unavailable", None) if path.name == "a.txt" else real(path)
        with patch("pc_scanner.coverage.metadata", side_effect=observed), patch(
                "pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan")):
            report = Scanner(self.config).invoke("malware", root_alias="test", **args)
        self.assertEqual(report["data"]["coverage"]["by_reason"], {"file_size_limit": 1, "metadata_unavailable": 1})

    def test_cancelled_running_scope_and_not_reached_scope_are_distinct(self):
        from pc_scanner.core import ScannerError
        cancel = threading.Event()
        def engine(*args, **kwargs):
            cancel.set()
            raise ScannerError("Scan cancelled")
        with patch("pc_scanner.core.run_bounded", side_effect=engine):
            report = Scanner(self.config).invoke("malware", root_alias="test", batch=True, cancel=cancel)
        self.assertEqual(report["data"]["coverage"]["by_reason"], {"cancelled": 1, "not_reached": 1})
        self.assertEqual(report["data"]["coverage"]["stop_reason"], "cancelled")

    def test_parent_partition_replaces_parent_and_tracks_remainder_exclusions(self):
        ledger = coverage.new_ledger()
        coverage.put(ledger, "folder", ["metadata_limit"], "unlisted_remainder")
        coverage.put(ledger, "folder", (), "subtree_remainder", active=False)
        coverage.put(ledger, "folder/a", ["not_reached"])
        coverage.put(ledger, "folder/b", ["cloud_placeholder"])
        self.assertEqual(coverage.summary(ledger)["unresolved"]["count"], 2)
        coverage.put(ledger, "folder", ["metadata_unavailable"], "subtree_remainder")
        coverage.normalize(ledger)
        self.assertEqual(set(ledger["nodes"]["folder"]["excludes"]),
                         {ledger["nodes"]["folder/a"]["id"], ledger["nodes"]["folder/b"]["id"]})

    def test_failed_save_retains_previous_revision_and_disables_latest_selection(self):
        first = self.batch()
        old = malware_batch.read_coverage(Scanner(self.config), "test", ".")
        with patch("pc_scanner.core.run_bounded", side_effect=self.clean), patch(
                "pc_scanner.history.replace_private", side_effect=OSError("test disk failure")):
            report = Scanner(self.config).invoke("malware", root_alias="test", **self.selection(first))
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["data"]["coverage"]["last_saved_revision"], old["revision"])
        self.assertEqual(malware_batch.read_coverage(Scanner(self.config), "test", ".")["revision"], old["revision"])
        self.assertFalse(report["data"]["coverage"]["selection_available"])

    def test_old_schema_requires_reinspection_before_new_selection(self):
        self.batch()
        checkpoint = next((self.base / "state/malware-checkpoints").glob("*.json"))
        state = json.loads(checkpoint.read_text())
        state["schema"] = 1
        state.pop("coverage")
        for record in state["parts"].values():
            record.pop("coverage_issues", None)
        checkpoint.write_text(json.dumps(state))
        with self.assertRaises(Exception):
            malware_batch.read_coverage(Scanner(self.config), "test", ".")
        with patch("pc_scanner.core.run_bounded", side_effect=self.clean) as engine:
            report = Scanner(self.config).invoke("malware", root_alias="test", resume=True)
        self.assertEqual(engine.call_count, 2)
        self.assertEqual(report["data"]["coverage"]["unresolved"]["count"], 0)
        self.assertEqual(json.loads(checkpoint.read_text())["schema"], 2)

    def test_local_listing_is_name_free_unless_explicitly_requested(self):
        first = self.batch()
        config = self.base / "scanner.toml"
        config.write_text('[scan_roots]\ntest=' + json.dumps(str(self.root)) + '\n[history]\nfile='
                          + json.dumps(self.config["history"]["file"]) + '\n')
        command = [sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "malware-gaps", "test",
                   "--scan", first["data"]["coverage"]["scan_group_id"], "--json"]
        public = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(public.returncode, 0)
        self.assertNotIn("a.txt", public.stdout)
        private = subprocess.run(command + ["--show-paths"], capture_output=True, text=True, timeout=10)
        self.assertEqual(private.returncode, 0)
        self.assertEqual({r["relative_path"] for r in json.loads(private.stdout)["data"]["targets"]}, {"a.txt", "b.txt"})

    def test_summary_history_has_counts_without_target_names(self):
        scanner = Scanner(self.config)
        scanner.via = "cli"
        with patch("pc_scanner.core.run_bounded", side_effect=self.limited):
            scanner.invoke("malware", root_alias="test", batch=True)
        raw = Path(self.config["history"]["file"]).read_text()
        self.assertNotIn("a.txt", raw)
        entries, skipped = history.read(Path(self.config["history"]["file"]), 10)
        self.assertEqual(skipped, 0)
        self.assertEqual(entries[0]["coverage"]["unresolved"]["count"], 2)
        self.assertIn("Unverified target scopes: 2", dashboard.scan_body(entries[0], None, "off"))

    def test_dashboard_uses_highest_revision_and_rejects_conflicting_duplicate(self):
        first = self.batch()
        now = datetime.now(timezone.utc)
        old = history.entry("malware", {"root_alias": "test", "relative_path": "."}, first, now, 1, "cli")
        with patch("pc_scanner.core.run_bounded", side_effect=self.clean):
            second = Scanner(self.config).invoke("malware", root_alias="test", **self.selection(first))
        new = history.entry("malware", {"root_alias": "test", "relative_path": "."}, second, now, 1, "cli")
        runs = dashboard.latest_runs([old, new, copy.deepcopy(old), copy.deepcopy(new)])
        self.assertEqual(len(runs), 1)
        self.assertEqual(len(runs[0]), 1)
        self.assertEqual(runs[0][0][1]["coverage"]["unresolved"]["count"], 1)
        conflict = copy.deepcopy(new)
        conflict["coverage"]["by_reason"] = {}
        runs = dashboard.latest_runs([new, conflict])
        self.assertEqual(runs[0][0][1]["status"], "partial")
        self.assertEqual(runs[0][0][1]["coverage"]["unresolved"]["quality"], "unknown")

    def test_dashboard_selection_has_no_scripts_or_private_paths(self):
        report = self.batch()
        html = dashboard.coverage_selection(report["data"])
        self.assertIn('type="checkbox"', html)
        self.assertIn("--retry", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("a.txt", html)
        fake = copy.deepcopy(report["data"])
        fake["coverage_targets"][0]["target_id"] = '" onclick="evil'
        self.assertNotIn("onclick", dashboard.coverage_selection(fake))

    def test_pagination_is_bound_to_filter_and_revision(self):
        self.batch()
        ledger = malware_batch.read_coverage(Scanner(self.config), "test", ".")
        page = coverage.listing(ledger, limit=1)
        cursor = page["next_cursor"]
        a = coverage.listing(ledger, cursor=cursor, limit=1)
        b = coverage.listing(ledger, cursor=cursor, limit=1)
        self.assertEqual(a["targets"], b["targets"])
        self.assertEqual(a["coverage"]["unresolved"]["count"], 2)
        with self.assertRaises(Exception):
            coverage.listing(ledger, reasons=["cloud_placeholder"], cursor=cursor)
        ledger["revision"] += 1
        with self.assertRaises(Exception):
            coverage.listing(ledger, cursor=cursor)

    def test_mcp_selection_uses_only_live_results_and_loses_access_after_restart(self):
        from mcp.shared.memory import create_connected_server_and_client_session
        from pc_scanner.server import create_server
        async def exercise():
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                reply = await session.call_tool("scan_malware", {"root_alias": "test", "batch": True})
                first = json.loads(reply.content[0].text)
                scan_id = first["data"]["progress"]["scan_id"]
                reply = await session.call_tool("list_malware_gaps", {"scan_id": scan_id, "limit": 1})
                rows = json.loads(reply.content[0].text)["data"]
                self.assertNotIn("a.txt", json.dumps(rows))
                reply = await session.call_tool("rescan_malware_targets", {"scan_id": scan_id,
                    "revision": rows["coverage"]["revision"], "target_ids": [rows["targets"][0]["target_id"]]})
                new = json.loads(reply.content[0].text)
                self.assertEqual(new["data"]["coverage"]["unresolved"]["count"], 2)
                reply = await session.call_tool("list_malware_gaps", {"scan_id": scan_id})
                self.assertEqual(json.loads(reply.content[0].text)["status"], "error")
            async with create_connected_server_and_client_session(create_server(Scanner(self.config))) as session:
                reply = await session.call_tool("list_malware_gaps", {"scan_id": scan_id})
                self.assertEqual(json.loads(reply.content[0].text)["status"], "error")
        with patch("pc_scanner.core.run_bounded", side_effect=self.limited):
            asyncio.run(exercise())

    def test_cloud_ancestor_transition_never_descends_or_starts_content_scan(self):
        folder = self.root / "folder"
        folder.mkdir()
        child = folder / "child.txt"
        child.write_text("local before transition")
        def limited(argv, *args, **kwargs):
            if Path(argv[-1]) == folder.resolve():
                return 1, f"{child.resolve()}: Heuristics.Limits.Exceeded.MaxFileSize FOUND\nScanned files: 1\nInfected files: 0\n", ""
            return self.clean()
        with patch("pc_scanner.core.run_bounded", side_effect=limited):
            first = Scanner(self.config).invoke("malware", root_alias="test", batch=True)
        args = self.selection(first, "folder/child.txt")
        real_scandir = os.scandir
        def guard(path):
            if Path(path) == folder.resolve():
                raise AssertionError("must not descend into placeholder folder")
            return real_scandir(path)
        with patch("pc_scanner.core.cloud_placeholder", side_effect=lambda p: Path(p) == folder.resolve()), patch(
                "os.scandir", side_effect=guard), patch("pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan")):
            report = Scanner(self.config).invoke("malware", root_alias="test", **args)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["data"]["coverage"]["by_reason"], {"cloud_placeholder": 1})

    def test_selected_deep_file_cannot_reset_original_depth_limit(self):
        folder = self.root / "deep"
        folder.mkdir()
        current = folder
        for _ in range(16):
            current = current / "d"
            current.mkdir()
        child = current / "child.txt"
        child.write_text("deep local test")
        def limited(argv, *args, **kwargs):
            if Path(argv[-1]) == folder.resolve():
                return 1, f"{child.resolve()}: Heuristics.Limits.Exceeded.MaxFileSize FOUND\nScanned files: 1\nInfected files: 0\n", ""
            return self.clean()
        with patch("pc_scanner.core.run_bounded", side_effect=limited):
            first = Scanner(self.config).invoke("malware", root_alias="test", batch=True)
        args = self.selection(first, str(child.relative_to(self.root)))
        with patch("pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan beyond original depth")):
            report = Scanner(self.config).invoke("malware", root_alias="test", **args)
        self.assertEqual(report["status"], "partial")
        self.assertGreaterEqual(report["data"]["coverage"]["by_reason"].get("directory_depth_limit", 0), 1)

    def test_real_cli_retry_parses_target_ids_and_replaces_saved_counts(self):
        first = self.batch()
        args = self.selection(first)
        config = self.base / "scanner.toml"
        config.write_text('[local]\nclamav_binary=' + json.dumps(sys.executable) + '\n[scan_roots]\ntest='
                          + json.dumps(str(self.root)) + '\n[history]\nenabled=false\nfile='
                          + json.dumps(self.config["history"]["file"]) + '\n')
        # Same signature stamp as the first real CLI process would observe; fixture datetime is stable.
        # Context includes history-independent local settings; take the timestamp from the test's probe.
        from pc_scanner import core
        stamp = core.clamav_signatures(None, None, None)["built_at"].isoformat()
        bootstrap = ('from pc_scanner import core,cli; from datetime import datetime; '
            'core.clamav_signatures=lambda *a,**k: {"engine":"test","version":1,"built_at":datetime.fromisoformat('
            + repr(stamp) + ')}; core.run_bounded=lambda *a,**k: (0,"Scanned files: 1\\nInfected files: 0\\n",""); cli.main()')
        process = subprocess.run([sys.executable, "-c", bootstrap, "--config", str(config), "malware", "test",
            "--retry", args["retry"], "--revision", str(args["revision"]), "--target", args["target_ids"][0]],
            text=True, capture_output=True, timeout=10)
        report = json.loads(process.stdout)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(report["data"]["coverage"]["unresolved"]["count"], 1)
        self.assertEqual(report["data"]["attempt"]["selected"], 1)

    def test_a_late_retry_of_an_older_group_does_not_replace_a_newer_group(self):
        first = self.batch()
        record = history.entry("malware", {"root_alias": "test", "relative_path": "."}, first,
                               datetime.now(timezone.utc), 1, "cli")
        new = copy.deepcopy(record)
        new["coverage"]["scan_group_id"] = "f" * 32
        new["coverage"]["group_started_at"] = "2099-01-01T00:00:00+00:00"
        late = copy.deepcopy(record)
        late["coverage"]["revision"] += 10
        runs = dashboard.latest_runs([record, new, late])
        self.assertEqual(runs[0][0][1]["coverage"]["scan_group_id"], "f" * 32)

    def test_target_limit_retains_unknown_remainder_instead_of_zero(self):
        with patch("pc_scanner.coverage.MAX_TARGETS", 2), patch("pc_scanner.core.run_bounded", side_effect=self.clean):
            report = Scanner(self.config).invoke("malware", root_alias="test", batch=True)
        self.assertEqual(report["status"], "partial")
        self.assertFalse(report["data"]["coverage"]["enumeration_complete"])
        self.assertEqual(report["data"]["coverage"]["unresolved"]["quality"], "lower_bound")
        self.assertEqual(report["data"]["coverage"]["by_reason"], {"metadata_limit": 1})

    def test_last_scannable_directory_metadata_failure_cannot_start_engine(self):
        first = self.batch()
        args = self.selection(first)
        with patch("pc_scanner.coverage.safety", return_value="metadata_unavailable"), patch(
                "pc_scanner.core.run_bounded", side_effect=AssertionError("must not read contents")):
            report = Scanner(self.config).invoke("malware", root_alias="test", **args)
        self.assertEqual(report["data"]["coverage"]["by_reason"], {"file_size_limit": 1, "metadata_unavailable": 1})

    def test_distinct_private_paths_with_same_truncated_display_are_not_deduplicated(self):
        report = {"status": "partial", "warnings": [], "observed_at": "2026-10-27T00:00:00+00:00",
                  "findings": [{"path": "same...(truncated)", "kind": "malware", "signature": "Test"}], "data": {}}
        records = {"first": {"report": report, "finding_paths": ["first/raw"], "evidence_revision": 1},
                   "second": {"report": report, "finding_paths": ["second/raw"], "evidence_revision": 2}}
        self.assertEqual(sum(len(r["findings"]) for r in malware_batch.group_reports(records)), 2)

    def test_retained_old_finding_is_not_resurrected_after_clean_child_retry(self):
        dirty = {"status": "partial", "warnings": [], "observed_at": "old",
                 "findings": [{"path": "folder/a", "kind": "malware", "signature": "Test", "retained": True,
                               "evidence_revision": 1}], "data": {}}
        clean = {"status": "completed", "warnings": [], "observed_at": "new", "findings": [], "data": {}}
        records = {"folder": {"report": dirty, "finding_paths": ["folder/a"], "evidence_revision": 3,
                               "finished": True, "excludes": ["folder/a"]},
                   "folder/a": {"report": clean, "finding_paths": [], "evidence_revision": 2, "finished": True}}
        self.assertEqual(sum(len(r["findings"]) for r in malware_batch.group_reports(records)), 0)

    def test_selection_styles_are_in_the_csp_approved_stylesheet(self):
        self.assertIn("input:checked~.retry-option", dashboard.STYLE)
        report = self.batch()
        self.assertNotIn("<style", dashboard.coverage_selection(report["data"]))

    def test_summary_keeps_selected_attempt_separate_from_whole_group(self):
        first = self.batch()
        with patch("pc_scanner.core.run_bounded", side_effect=self.clean):
            report = Scanner(self.config).invoke("malware", root_alias="test", **self.selection(first))
        value = coverage.project(report["data"]["coverage"])
        self.assertEqual(value["attempt"]["status"], "completed")
        self.assertEqual(value["unresolved"]["count"], 1)
        html = dashboard.coverage_panel(value)
        self.assertIn("Selected attempt: completed", html)
        self.assertIn("Unverified target scopes: 1", html)

    def test_zero_scanned_due_to_known_limit_is_not_reported_as_an_engine_failure(self):
        def engine(argv, *args, **kwargs):
            return 1, f"{argv[-1]}: Heuristics.Limits.Exceeded.MaxFileSize FOUND\nScanned files: 0\nInfected files: 0\n", ""
        with patch("pc_scanner.core.run_bounded", side_effect=engine):
            report = Scanner(self.config).invoke("malware", root_alias="test", relative_path="a.txt")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["data"]["coverage"]["by_reason"], {"file_size_limit": 1})

    def cloud_folder(self):
        folder = self.root / "d"
        folder.mkdir()
        for name in ("x.txt", "y.txt", "c.txt"):
            (folder / name).write_text("ordinary")
        return patch("pc_scanner.core.cloud_placeholder", side_effect=lambda path: Path(path).name == "c.txt")

    def test_unstarted_scan_keeps_its_unscanned_remainder_as_a_gap(self):
        # Found in the review of 2026-10-28: when the cloud exclusions could not be passed, only the
        # cloud items were counted, although the rest of the folder was not scanned either.
        with self.cloud_folder(), patch("pc_scanner.core.CLAMAV_MATCH_BYTES", 10), patch(
                "pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan")):
            report = Scanner(self.config).invoke("malware", root_alias="test", relative_path="d")
        info = report["data"]["coverage"]
        self.assertEqual(report["status"], "partial")
        self.assertEqual(info["by_reason"], {"cloud_placeholder": 1, "not_reached": 1})
        self.assertEqual(info["unresolved"]["count"], 2)

    def test_selected_retry_that_cannot_start_keeps_the_folder_unresolved(self):
        # Found in the review of 2026-10-28: the selected folder was marked resolved although no engine ran.
        from pc_scanner.core import ScannerError
        def first(argv, *args, **kwargs):
            if Path(argv[-1]).name == "d":
                raise ScannerError("engine failed (test)")
            return self.clean()
        with self.cloud_folder():
            scanner = Scanner(self.config)
            with patch("pc_scanner.core.run_bounded", side_effect=first):
                batch = scanner.invoke("malware", root_alias="test", batch=True)
            self.assertEqual(batch["data"]["coverage"]["by_reason"], {"engine_error": 1})
            ledger = malware_batch.read_coverage(scanner, "test", ".")
            info = batch["data"]["coverage"]
            with patch("pc_scanner.core.MAX_EXCLUSION_CHARS", 1), patch(
                    "pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan")):
                retry = scanner.invoke("malware", root_alias="test", retry=info["scan_group_id"],
                                       revision=info["revision"], target_ids=[ledger["nodes"]["d"]["id"]])
            node = malware_batch.read_coverage(scanner, "test", ".")["nodes"]["d"]
        self.assertEqual(retry["status"], "partial")
        self.assertEqual((node["active"], node["reasons"]), (True, ["not_reached"]))
        self.assertEqual(retry["data"]["coverage"]["by_reason"], {"cloud_placeholder": 1, "not_reached": 1})

    # Vulnerability check of 2026-10-28 (independent review, each reproduced before fixing).

    @staticmethod
    def excluding_engine(argv, *args, **kwargs):
        """Stand-in for clamscan: walks the target and applies --exclude/--exclude-dir as ClamAV's
        regex matching does, reporting files that contain a test marker."""
        import re
        files = [re.compile(a.split("=", 1)[1]) for a in argv if a.startswith("--exclude=")]
        dirs = [re.compile(a.split("=", 1)[1]) for a in argv if a.startswith("--exclude-dir=")]
        target, found, scanned = argv[-1], [], 0
        for current, subdirs, names in os.walk(target):
            subdirs[:] = [d for d in subdirs if not any(p.search(os.path.join(current, d)) for p in dirs)]
            for name in names:
                path = os.path.join(current, name)
                if any(p.search(path) for p in files):
                    continue
                scanned += 1
                if b"TEST-MARKER" in Path(path).read_bytes():
                    found.append(f"{path}: Test.Marker FOUND")
        output = "\n".join(found + [f"Scanned files: {scanned}", f"Infected files: {len(found)}"]) + "\n"
        return int(bool(found)), output, ""

    def test_folder_exclusion_does_not_hide_a_sibling_named_with_a_backslash(self):
        import re
        from pc_scanner import core
        pattern = re.compile(core.exclusion_pattern("/r/P/big.iso", True))
        self.assertTrue(pattern.search("/r/P/big.iso"))
        self.assertTrue(pattern.search("/r/P/big.iso/inner"))
        self.assertFalse(pattern.search("/r/P/big.isox"))
        if os.name != "nt":
            self.assertFalse(pattern.search("/r/P/big.iso\\payload"))  # a sibling; "\" is part of its name
        with patch.object(core.os, "name", "nt"):
            windows = re.compile(core.exclusion_pattern("C:\\r\\P", True))
        self.assertTrue(windows.search("C:\\r\\P\\inner"))
        self.assertFalse(windows.search("C:\\r\\Px"))

    @unittest.skipIf(os.name == "nt", "a backslash cannot be part of a Windows file name")
    def test_cloud_folder_exclusion_still_scans_a_backslash_sibling(self):
        sibling = self.root / "sub" / ".x.icloud\\payload"
        sibling.mkdir(parents=True)
        (self.root / "sub" / ".x.icloud").mkdir()
        (sibling / "mal.exe").write_bytes(b"xx TEST-MARKER xx")
        with patch("pc_scanner.core.cloud_placeholder", side_effect=lambda path: Path(path).name == ".x.icloud"), \
                patch("pc_scanner.core.run_bounded", side_effect=self.excluding_engine):
            report = Scanner(self.config).invoke("malware", root_alias="test", relative_path="sub")
        self.assertEqual([Path(f["path"]).name for f in report["findings"]], ["mal.exe"])

    def test_selective_rescan_bookkeeping_stays_fast_on_a_large_ledger(self):
        import secrets
        import time
        first = self.batch()
        folder = Path(self.config["history"]["file"]).parent.resolve() / "malware-checkpoints"
        path = next(folder.glob("*.json"))
        state = json.loads(path.read_bytes())
        nodes, ids = state["coverage"]["nodes"], []
        for parent in range(10):
            for child in range(99):  # recorded before their parent, as after a later split
                nodes[f"D{parent}/f{child}"] = {"id": secrets.token_hex(16), "reasons": ["file_size_limit"],
                                                "kind": "file", "active": True}
        for parent in range(10):
            nodes[f"D{parent}"] = {"id": secrets.token_hex(16), "reasons": ["changed_during_scan"],
                                   "kind": "subtree_remainder", "active": True}
            ids.append(nodes[f"D{parent}"]["id"])
        history.replace_private(path, json.dumps(state).encode())
        info = first["data"]["coverage"]
        started = time.monotonic()
        with patch("pc_scanner.core.run_bounded", side_effect=self.clean):
            retry = Scanner(self.config).invoke("malware", root_alias="test", retry=info["scan_group_id"],
                                                revision=info["revision"], target_ids=ids)
        self.assertLess(time.monotonic() - started, 10)  # took about 49 s before the fix
        self.assertEqual(retry["data"]["attempt"]["selected"], 10)

    def test_a_folder_too_big_to_divide_stays_a_gap_and_later_folders_are_scanned(self):
        (self.root / "big").mkdir()
        for index in range(8):
            (self.root / "big" / f"{index}.txt").write_text("x")
        (self.root / "zz").mkdir()
        (self.root / "zz" / "late.txt").write_text("x")
        scanned = []
        def engine(argv, *args, **kwargs):
            scanned.append(Path(argv[-1]).name)
            return self.clean()
        with patch("pc_scanner.malware_batch.MAX_PART_ENTRIES", 3), patch("pc_scanner.malware_batch.MAX_PARTS", 5), \
                patch("pc_scanner.core.run_bounded", side_effect=engine):
            report = Scanner(self.config).invoke("malware", root_alias="test", batch=True)
        self.assertIn("zz", scanned)
        self.assertNotIn("big", scanned)
        self.assertEqual(report["data"]["coverage"]["by_reason"], {"metadata_limit": 1})
        self.assertEqual(report["status"], "partial")

    def test_checkpoint_folder_is_recognised_in_any_letter_case(self):
        probe = self.base / "case-probe"
        probe.write_text("x")
        if not (self.base / "CASE-PROBE").exists():
            self.skipTest("this file system distinguishes letter case")
        config = {**self.config, "history": {"file": str(self.root / "state" / "history.jsonl")}}
        (self.root / "state" / "malware-checkpoints").mkdir(parents=True, mode=0o700)
        os.chmod(self.root / "state", 0o700)
        with patch("pc_scanner.core.run_bounded", side_effect=AssertionError("must not scan")):
            refused = Scanner(config).invoke("malware", root_alias="test", relative_path="state/MALWARE-CHECKPOINTS",
                                             batch=True)
        self.assertEqual(refused["error"], "Checkpoint files cannot be a batch scan target")
        targets = []
        def engine(argv, *args, **kwargs):
            targets.append(argv[-1].lower())
            return self.clean()
        with patch("pc_scanner.core.run_bounded", side_effect=engine):
            Scanner(config).invoke("malware", root_alias="test", relative_path="STATE", batch=True)
        self.assertFalse([t for t in targets if "malware-checkpoints" in t], targets)

    def test_gap_listing_json_escapes_names(self):
        (self.root / "evil\u202etxt.exe").write_text("x")
        first = self.batch()
        config = self.base / "scanner.toml"
        config.write_text('[local]\nclamav_binary=' + json.dumps(sys.executable) + '\n[scan_roots]\ntest='
                          + json.dumps(str(self.root)) + '\n[history]\nenabled=false\nfile='
                          + json.dumps(self.config["history"]["file"]) + '\n')
        process = subprocess.run([sys.executable, "-m", "pc_scanner.cli", "--config", str(config), "malware-gaps", "test",
                                  "--scan", first["data"]["coverage"]["scan_group_id"], "--show-paths", "--json"],
                                 text=True, encoding="utf-8", capture_output=True, timeout=30,
                                 cwd=Path(__file__).resolve().parents[1])
        self.assertNotIn("\u202e", process.stdout)
        self.assertIn("evil\\\\u202etxt.exe", process.stdout)

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_batch_creates_a_private_history_folder(self):
        config = {**self.config, "history": {"file": str(self.base / "fresh" / "history.jsonl")}}
        with patch("pc_scanner.core.run_bounded", side_effect=self.clean):
            Scanner(config).invoke("malware", root_alias="test", batch=True)
        self.assertEqual((self.base / "fresh").stat().st_mode & 0o077, 0)

    def test_rescanning_the_whole_root_does_not_inspect_folders_above_it(self):
        first = self.batch()
        folder = Path(self.config["history"]["file"]).parent.resolve() / "malware-checkpoints"
        path = next(folder.glob("*.json"))
        state = json.loads(path.read_bytes())
        state["coverage"]["nodes"]["."].update(reasons=["changed_during_scan"], active=True)
        history.replace_private(path, json.dumps(state).encode())
        info = first["data"]["coverage"]
        above = self.root.resolve().parent
        with patch("pc_scanner.core.cloud_placeholder", side_effect=lambda p: Path(p) == above), \
                patch("pc_scanner.core.run_bounded", side_effect=self.clean) as engine:
            Scanner(self.config).invoke("malware", root_alias="test", retry=info["scan_group_id"],
                                        revision=info["revision"], target_ids=[state["coverage"]["nodes"]["."]["id"]])
        self.assertEqual(engine.call_count, 1)
