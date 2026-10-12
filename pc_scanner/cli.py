import argparse
import json
import sys

from .core import Scanner, ScannerError, result, stop_engines_on_terminate


def main():
    parser = argparse.ArgumentParser(description="Restricted local OSS scanner bridge")
    parser.add_argument("--config", default="scanner.toml")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    inventory = commands.add_parser("inventory")
    inventory.add_argument("query_id", choices=["os_version", "applications", "listening_ports"])
    inventory.add_argument("--offset", type=int, default=0, help="continue from data.next_offset")
    malware = commands.add_parser("malware")
    malware.add_argument("root_alias")
    malware.add_argument("relative_path", nargs="?", default=".")
    vulnerabilities = commands.add_parser("vulnerabilities")
    vulnerabilities.add_argument("--cursor", default="", help="continue from data.next_cursor")
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
        kwargs = {k: v for k, v in vars(args).items() if k not in {"config", "command"}}
        report = scanner.invoke(args.command, **kwargs)
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
