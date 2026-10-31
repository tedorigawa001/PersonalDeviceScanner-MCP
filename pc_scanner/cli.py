import argparse
import json
import sys
import webbrowser
from pathlib import Path

from .core import Scanner, ScannerError, result, stop_engines_on_terminate


def check_limit(limit: int) -> None:
    from . import history
    if type(limit) is not int or not 1 <= limit <= history.MAX_LIMIT:
        raise ScannerError(f"--limit must be 1..{history.MAX_LIMIT}")


def show_history(scanner: Scanner, limit: int) -> dict:
    from . import history
    check_limit(limit)
    path = scanner.history_path()
    try:
        entries, skipped = history.read(path, limit)
    except OSError:
        raise ScannerError("Cannot read the scan history file") from None
    # The source follows from the operation; it is added here rather than kept in the file.
    entries = [{**entry, "source": history.source(entry["operation"])} for entry in entries]
    return result("bridge", "completed", data={"file": str(path), "recording": scanner.history_enabled,
                                               "entries": entries, "skipped_lines": skipped},
                  warnings=scanner.config_warnings
                  + ([] if scanner.history_enabled else ["Recording is turned off (history.enabled = false)"])
                  + ([f"{skipped} damaged lines in the history file were skipped"] if skipped else []))


def print_history(report: dict) -> None:
    from . import history
    entries = report["data"]["entries"]
    print(history.table(entries) if entries else f"No scans recorded yet in {report['data']['file']}")
    for warning in report["warnings"]:
        print(f"pc-scanner: {warning}", file=sys.stderr)


def write_dashboard(scanner: Scanner, limit: int, open_page: bool) -> None:
    from . import dashboard
    check_limit(limit)
    try:
        page, skipped = dashboard.build(scanner.history_path(), limit, scanner.history_enabled,
                                        scanner.history_details, scanner.history_details_mb)
    except OSError:
        raise ScannerError("Cannot read the scan history or write the dashboard page") from None
    print(f"Dashboard written to {page}")
    for warning in scanner.config_warnings + ([f"{skipped} damaged lines in the history file were skipped"]
                                              if skipped else []):
        print(f"pc-scanner: {warning}", file=sys.stderr)
    if open_page and not webbrowser.open(page.as_uri()):
        print("pc-scanner: could not open a browser; open the file above yourself", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Restricted local OSS scanner bridge")
    parser.add_argument("--config", default="scanner.toml")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("check-clamav-signatures", help="read definition freshness and update steps; never updates")
    lan_devices = commands.add_parser("lan-devices", help="observe devices on an owner-authorized LAN; names, IPs and MACs are included")
    lan_devices.add_argument("network_alias")
    lan_devices.add_argument("--json", action="store_true", help="print the complete LAN observations")
    outbound = commands.add_parser("outbound-connections", help="read OS-visible processes and destinations; no packets or payloads")
    outbound.add_argument("--json", action="store_true", help="print complete socket observations with coverage limitations")
    outbound.add_argument("--check-ip-threats", action="store_true", help="check cached public threat lists locally; no network lookup")
    threat_update = commands.add_parser("update-ip-threat-lists", help="explicit local-only public-list download; never sends observed destinations")
    threat_update.add_argument("--json", action="store_true")
    review = commands.add_parser("review-processes", help="read owner-selected process provenance; anonymous summary by default")
    review.add_argument("--show-details", action="store_true", help="include private process names, PIDs, paths and package metadata locally")
    review.add_argument("--save-details", action="store_true", help="save private details only with process_review.storage.enabled; independent of history settings")
    review.add_argument("--json", action="store_true", help="print structured process provenance")
    records = commands.add_parser("process-review-records", help="local-only private record management; never available to MCP")
    record_actions = records.add_subparsers(dest="record_action", required=True)
    listing = record_actions.add_parser("list")
    listing.add_argument("--show-details", action="store_true")
    listing.add_argument("--json", action="store_true")
    removal = record_actions.add_parser("delete")
    removal.add_argument("record_id")
    removal.add_argument("--revision", required=True)
    removal.add_argument("--json", action="store_true")
    prune = record_actions.add_parser("prune")
    prune.add_argument("--expired", action="store_true", required=True)
    prune.add_argument("--dry-run", action="store_true", help="preview record deletions; stale managed HTML may still be invalidated")
    prune.add_argument("--json", action="store_true")
    page = record_actions.add_parser("dashboard", help="generate a local page containing private names and paths")
    page.add_argument("--no-open", action="store_true")
    inventory = commands.add_parser("inventory")
    inventory.add_argument("query_id", choices=["os_version", "applications", "listening_ports"])
    inventory.add_argument("--offset", type=int, default=0, help="continue from data.next_offset")
    malware = commands.add_parser("malware")
    malware.add_argument("root_alias")
    malware.add_argument("relative_path", nargs="?", default=".")
    malware.add_argument("--batch", action="store_true", help="split into resumable parts; saves private checkpoints")
    malware.add_argument("--resume", action="store_true", help="resume the same root/path; recheck changed parts")
    malware.add_argument("--retry", default="", help="select from a saved coverage group")
    malware.add_argument("--revision", type=int, default=None, help="required saved coverage revision")
    malware.add_argument("--target", dest="target_ids", action="append", default=None, help="opaque target ID; repeat up to 100")
    gaps = commands.add_parser("malware-gaps", help="list private batch coverage targets locally")
    gaps.add_argument("root_alias")
    gaps.add_argument("relative_path", nargs="?", default=".")
    gaps.add_argument("--scan", required=True)
    gaps.add_argument("--reason", action="append", default=[])
    gaps.add_argument("--show-paths", action="store_true")
    gaps.add_argument("--json", action="store_true")
    checkpoints = commands.add_parser("malware-checkpoints", help="locally list or remove saved batch progress; never exposed to MCP")
    actions = checkpoints.add_subparsers(dest="checkpoint_action", required=True)
    saved_list = actions.add_parser("list", help="list saved checkpoint IDs and revision tokens")
    saved_list.add_argument("--show-paths", action="store_true", help="show saved relative target names locally")
    saved_list.add_argument("--json", action="store_true")
    saved_delete = actions.add_parser("delete", help="delete one unchanged checkpoint; scan files/history stay intact")
    saved_delete.add_argument("checkpoint_id")
    saved_delete.add_argument("--revision", required=True, help="exact revision token from the checkpoint list")
    saved_delete.add_argument("--json", action="store_true")
    vulnerabilities = commands.add_parser("vulnerabilities")
    vulnerabilities.add_argument("--cursor", default="", help="continue from data.next_cursor")
    android = commands.add_parser("android", help="read fixed facts from a registered Android device over USB")
    android.add_argument("device_alias")
    android.add_argument("query_id", choices=["device", "apps", "privileged_access"])
    android_check = commands.add_parser("android-check", help="check a registered Android device for known "
                                                              "monitoring apps")
    android_check.add_argument("device_alias")
    router_check = commands.add_parser("router-check", help="check a registered home router without contacting it")
    router_check.add_argument("router_alias")
    router_products = commands.add_parser("router-products", help="list a maker's models and CPE names in JVN, to "
                                                                  "choose routers.<alias>.jvn_cpes")
    router_products.add_argument("maker", choices=["buffalo", "nec", "iodata", "elecom"])
    router_products.add_argument("keyword", help="part of the model name, e.g. WSR-3200")
    history = commands.add_parser("history", help="show the scan summaries recorded on this PC; the AI cannot "
                                                  "read them")
    history.add_argument("--limit", type=int, default=20, help="number of latest scans to show (1..1000)")
    history.add_argument("--json", action="store_true", help="print JSON instead of a table")
    dashboard = commands.add_parser("dashboard", help="write the scan history, with any kept details, to an HTML "
                                                      "page on this PC and open it; the AI cannot read it")
    dashboard.add_argument("--limit", type=int, default=100, help="number of latest scans to include (1..1000)")
    dashboard.add_argument("--no-open", action="store_true", help="write the page without opening it")
    commands.add_parser("serve", help="MCP over local stdio; requires agent extra")
    args = parser.parse_args()
    # File and app names may hold characters the terminal cannot encode; never crash on them.
    sys.stdout.reconfigure(errors="backslashreplace")
    stop_engines_on_terminate()
    try:
        scanner = Scanner.load(args.config)
        if args.command == "serve":
            from .server import serve
            serve(scanner)
            return
        if args.command == "dashboard":
            write_dashboard(scanner, args.limit, not args.no_open)
            return
        if args.command == "process-review-records":
            from . import process_store
            scanner.via = "cli"
            report = process_store.manage(scanner, args.record_action, record_id=getattr(args, "record_id", None),
                revision=getattr(args, "revision", None), show_details=getattr(args, "show_details", False),
                dry_run=getattr(args, "dry_run", False))
            if args.record_action == "dashboard" and report.get("data", {}).get("page") and not args.no_open:
                webbrowser.open(Path(report["data"]["page"]).as_uri())
        if args.command == "malware-gaps":
            from . import coverage, malware_batch
            ledger = malware_batch.read_coverage(scanner, args.root_alias, args.relative_path)
            if ledger["group"] != args.scan:
                raise ScannerError("Invalid or stale coverage group")
            rows = coverage.targets(ledger, args.show_paths)
            if args.reason and not set(args.reason) <= coverage.REASONS:
                raise ScannerError("Invalid coverage reason")
            rows = [row for row in rows if not args.reason or set(row["reasons"]) & set(args.reason)]
            # Names are escaped for --json too, as everywhere else (found in the review of 2026-10-28).
            from .core import clean_text, PATH_CHARS
            rows = [{**row, "relative_path": clean_text(row["relative_path"], PATH_CHARS)} if "relative_path" in row else row
                    for row in rows]
            report = result("clamav", "completed", data={"coverage": coverage.summary(ledger), "targets": rows})
            if not args.json:
                print(f"Coverage {ledger['group']} revision={ledger['revision']} (target scopes, not file counts)")
                for row in rows:
                    print(row["target_id"], "; ".join(coverage.LABELS[r] for r in row["reasons"]), row["eligibility"].replace("_", " "),
                          row.get("relative_path", ""))
                return
        if args.command == "process-review-records":
            pass
        elif args.command == "malware-checkpoints":
            from . import checkpoints
            scanner.via = "cli"
            report = (checkpoints.list_checkpoints(scanner, args.show_paths) if args.checkpoint_action == "list"
                      else checkpoints.delete_checkpoint(scanner, args.checkpoint_id, args.revision))
            report["warnings"] = scanner.config_warnings + report["warnings"]
        elif args.command == "history":
            report = show_history(scanner, args.limit)
            if not args.json:
                print_history(report)
                return
        elif args.command != "malware-gaps":
            scanner.via = "cli"
            kwargs = {k: v for k, v in vars(args).items() if k not in {"config", "command", "json", "show_details"}}
            operation = {"lan-devices": "discover_lan_devices", "outbound-connections": "observe_outbound_connections", "review-processes": "review_processes"}.get(args.command, args.command.replace("-", "_"))
            if args.command == "outbound-connections" and kwargs.pop("check_ip_threats", False):
                operation = "check_connection_destinations"
            if args.command in {"malware", "check-clamav-signatures", "lan-devices", "outbound-connections", "review-processes", "update-ip-threat-lists"}:
                from .progress import CLIProgress
                with CLIProgress() as display:
                    report = scanner.invoke(operation,
                                            progress=display.progress, cancel=display.cancel, **kwargs)
            else:
                report = scanner.invoke(args.command.replace("-", "_"), **kwargs)
    except ScannerError as exc:
        report = result("bridge", "error", error=str(exc))
    except ImportError:
        report = result("bridge", "error", error="Install the agent extra to use MCP")
    except Exception as exc:
        # Exit 2 ("not completed"), never 1, which means "completed with findings".
        report = result("bridge", "error",
                        error=f"Unexpected internal error ({type(exc).__name__}); the operation was not completed")
    if args.command == "review-processes" and not args.show_details:
        from .process_review import for_cli
        omitted = len(report.get("warnings", []))
        report = for_cli(report)
        if omitted:
            # Only the count: warning texts can quote configured names, which the anonymous view never shows.
            print(f"pc-scanner: {omitted} warning(s) omitted from the anonymous view; "
                  "run with --show-details to read them locally", file=sys.stderr)
    if args.command == "malware-checkpoints" and not args.json:
        data = report.get("data", {})
        print("Status:", report["status"])
        if args.checkpoint_action == "list":
            print("Checkpoint slots:", data.get("capacity_count", "unknown"), "/", data.get("capacity", "unknown"),
                  "Batch scan running:", data.get("scan_running", "unknown"))
            for row in data.get("checkpoints", []):
                print(row["checkpoint_id"], "state=" + row["state"], "deletable=" + str(row["deletable"]),
                      "target=" + row.get("root_alias", "unknown (legacy or damaged)"), row.get("relative_path", ""))
                print("  revision=" + row.get("revision", "unavailable"), "saved=" + str(row.get("last_saved_at", "unknown")),
                      "parts=" + str(row.get("saved_parts", "unknown")))
            print("Deleting a checkpoint removes its saved progress/findings, not scan files or history.")
        elif data.get("deleted"):
            print("Deleted checkpoint:", data["checkpoint_id"])
        for warning in report["warnings"] + ([report["error"]] if report.get("error") else []):
            print("pc-scanner: " + warning, file=sys.stderr)
    elif args.command == "outbound-connections" and not args.json:
        data = report.get("data", {})
        print("Observed connections: direction and actual transmissions unknown; short-lived connections may be missed")
        print("Status:", report["status"], "Observed at:", data.get("finished_at", "unknown"),
              "Elapsed:", data.get("duration_seconds", "unknown"), "Saved:", data.get("persistence", "not_saved"))
        print("PID / process\tDestination / scope / port\tProtocol\tClass\tAttribution")
        for row in data.get("connections", []):
            print(str(row["pid"]) + " / " + (row["process"] or "unknown"),
                  row["remote_ip"] + ("%" + row["remote_scope"] if row["remote_scope"] else "") + ":" + str(row["remote_port"]),
                  row["protocol"], row["classification"], row["attribution_quality"], sep="\t")
        print("Observed records:", data.get("connection_count", "unknown"), "Sampling:", data.get("sampling", {}))
        print("Limitations:", ", ".join(data.get("limitations", [])))
        if "destination_threats" in data:
            from .ip_threats import NOTICE
            print(NOTICE)
            print("Destination threat-list check:", json.dumps(data["destination_threats"], ensure_ascii=False))
            for row in data.get("connections", []):
                assessment = row.get("threat", {})
                print("Destination check:", row["remote_ip"], row["pid"], row["process"] or "unknown",
                      assessment.get("state"), assessment.get("reason"),
                      "matched_out_of_date_list" if assessment.get("historical_match") else "-",
                      json.dumps(assessment.get("evidence", [])), sep="\t")
        for warning in report["warnings"] + ([report["error"]] if report.get("error") else []):
            print("pc-scanner: " + warning, file=sys.stderr)
    elif args.command == "lan-devices" and not args.json:
        print("Observed LAN devices (not all devices; cached records do not prove online status)")
        print("IP / scope\tNames\tMAC\tMethods / states\tAdvertised services (not probed)")
        for row in report.get("data", {}).get("devices", []):
            print("\t".join([", ".join(a["ip"] + ("%" + a["scope"] if a["scope"] else "") for a in row["addresses"]),
                ", ".join(row["names"]) or "unknown", row["mac"] or "unknown", ", ".join(row["methods"]) + " / " +
                ", ".join(str(e["state"]) for e in row["evidence"]),
                ", ".join(s["type"] + ":" + str(s["port"]) for s in row["services"]) or "none observed"]))
        print("Status:", report["status"], "Observed records:", report.get("data", {}).get("device_count", "unknown"))
        print("Methods:", ", ".join(k + "=" + v["status"] for k, v in report.get("data", {}).get("methods", {}).items()))
        print("Limitations:", ", ".join(report.get("data", {}).get("limitations", [])))
        for warning in report["warnings"] + ([report["error"]] if report.get("error") else []):
            print("pc-scanner: " + warning, file=sys.stderr)
    else:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] in {"partial", "error"}:
        raise SystemExit(2)
    if report["findings"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
