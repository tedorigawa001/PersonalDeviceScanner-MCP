import argparse
import json
import sys
import webbrowser

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
        if args.command == "history":
            report = show_history(scanner, args.limit)
            if not args.json:
                print_history(report)
                return
        elif args.command != "malware-gaps":
            scanner.via = "cli"
            kwargs = {k: v for k, v in vars(args).items() if k not in {"config", "command"}}
            if args.command in {"malware", "check-clamav-signatures"}:
                from .progress import CLIProgress
                with CLIProgress() as display:
                    report = scanner.invoke(args.command.replace("-", "_"),
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
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] in {"partial", "error"}:
        raise SystemExit(2)
    if report["findings"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
