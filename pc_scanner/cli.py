import argparse
import json

from .core import Scanner, ScannerError, result


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
    vulnerabilities.add_argument("--offset", type=int, default=0, help="continue from data.next_offset")
    commands.add_parser("serve", help="MCP over local stdio; requires agent extra")
    args = parser.parse_args()
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
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] in {"partial", "error"}:
        raise SystemExit(2)
    if report["findings"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
