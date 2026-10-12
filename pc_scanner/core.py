"""Restricted operations shared by the CLI and MCP server."""
from __future__ import annotations

import base64
import json
import locale
import os
import platform
import re
import ssl
import stat
import subprocess
import threading
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (HTTPSHandler, HTTPRedirectHandler, ProxyHandler,
                            Request, build_opener)


class ScannerError(Exception):
    """Safe, user-facing operation failure."""


MAX_DIRECTORY_LEVELS = 16
PAGE_SIZE = 500
# OpenSearch rejects from + size beyond the default index.max_result_window (10000).
MAX_OFFSET = 10000 - PAGE_SIZE
REPORT_LINES = 60
REPORTED_DIRECTORIES = 20
# stat defines this only on Windows; the value is fixed by the Windows SDK.
JUNCTION_TAG = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
FOUND = re.compile(r"(.+): (.+) FOUND")
SOURCES = {"status": "bridge", "inventory": "osquery", "malware": "clamav", "vulnerabilities": "wazuh"}


def is_link(path: Path) -> bool:
    """Symlink or Windows junction; scans never follow either."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", 0) == JUNCTION_TAG


def inspect_directories(target: Path, deadline: float) -> tuple[bool, list[str]]:
    """Find directories ClamAV silently skips or cannot read, without following links.

    ClamAV counts the target directory as level 1. Stop at the last scanned
    level; only the presence of a real child directory is needed there.
    """
    if not target.is_dir():
        return False, []
    limit_reached, unreadable = False, []

    def record(error):
        unreadable.append(error.filename or str(target))

    for directory, children, _ in os.walk(target, followlinks=False, onerror=record):
        if time.monotonic() >= deadline:
            raise ScannerError("Directory coverage check timed out; scan was not completed")
        # os.walk only skips symlinks, so junctions must be pruned here.
        children[:] = [name for name in children if not is_link(Path(directory) / name)]
        level = len(Path(directory).relative_to(target).parts) + 1
        if level >= MAX_DIRECTORY_LEVELS:
            limit_reached = limit_reached or bool(children)
            children.clear()
    return limit_reached, unreadable


def check_offset(offset) -> None:
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        raise ScannerError(f"offset must be an integer 0..{MAX_OFFSET}")


def next_page(offset: int, returned: int, more: bool) -> tuple[int | None, list[str]]:
    if not more or not returned:
        return None, []
    if offset + returned > MAX_OFFSET:
        return None, ["Paging limit reached; remaining rows cannot be retrieved"]
    return offset + returned, [f"More rows exist; call again with offset={offset + returned}"]


def excerpt(text: str) -> tuple[str, bool]:
    """Keep engine text small enough for an AI context; head and tail carry errors and summary."""
    rows = [row[:500] for row in text.splitlines()]
    if len(rows) <= REPORT_LINES:
        return "\n".join(rows), False
    half = REPORT_LINES // 2
    omitted = f"... {len(rows) - 2 * half} lines omitted ..."
    return "\n".join(rows[:half] + [omitted] + rows[-half:]), True


def result(source: str, status: str, **fields) -> dict:
    return {"schema_version": 1, "source": source, "status": status,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "findings": [], "warnings": [], **fields}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ScannerError("Wazuh redirect rejected; configure the final HTTPS origin")


def decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Windows engines may print paths in the ANSI code page (cp932 on Japanese Windows).
        return data.decode(locale.getpreferredencoding(False) or "utf-8", errors="replace")


def run_bounded(argv: list[str], timeout: float, limit: int) -> tuple[int, str, str]:
    # Never inherit cloud/API credentials into third-party engines; only locations.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME",
               "SYSTEMDRIVE", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "PROGRAMDATA",
               "PROGRAMFILES", "LOCALAPPDATA", "APPDATA"}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update({"LC_ALL": "C", "LANG": "C"})
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, env=env)
    except OSError:
        raise ScannerError("Configured engine could not be started") from None
    buffers = [bytearray(), bytearray()]
    exceeded = threading.Event()
    lock = threading.Lock()

    def drain(stream, slot):
        try:
            while chunk := stream.read(8192):
                with lock:
                    remaining = limit - sum(map(len, buffers))
                    buffers[slot].extend(chunk[:max(0, remaining)])
                    if len(chunk) > remaining:
                        exceeded.set()
                        process.kill()
                        break
        finally:
            stream.close()

    threads = [threading.Thread(target=drain, args=(stream, i), daemon=True)
               for i, stream in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    for thread in threads:
        thread.join(timeout=2)
    if timed_out:
        raise ScannerError("Engine timed out; scan was not completed")
    if exceeded.is_set():
        raise ScannerError("Engine output exceeded limits; scan was not completed")
    if any(t.is_alive() for t in threads):
        raise ScannerError("Engine output stayed open after exit; a child process may still be running")
    return process.returncode, *(decode(bytes(b)) for b in buffers)


class Scanner:
    def __init__(self, config: dict):
        if not isinstance(config, dict):
            raise ScannerError("Configuration must be a table")
        self.config = config
        self.local = config.get("local", {})
        self.roots = config.get("scan_roots", {})
        self.wazuh = config.get("wazuh", {})
        if not all(isinstance(v, dict) for v in (self.local, self.roots, self.wazuh)):
            raise ScannerError("Configuration sections must be tables")
        self.timeout = self.local.get("timeout_seconds", 600)
        self.limit = self.local.get("max_output_bytes", 1048576)
        if type(self.timeout) is not int or not 1 <= self.timeout <= 3600:
            raise ScannerError("timeout_seconds must be 1..3600")
        if type(self.limit) is not int or not 1024 <= self.limit <= 8388608:
            raise ScannerError("max_output_bytes must be 1024..8388608")
        for key in ("osquery_binary", "clamav_binary"):
            value = self.local.get(key, "")
            if not isinstance(value, str) or (value and not Path(value).is_absolute()):
                raise ScannerError("Engine paths must be absolute strings")
        for alias, value in self.roots.items():
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", alias):
                raise ScannerError("Invalid scan root alias")
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise ScannerError("Scan roots must be absolute paths")
        for key in ("url", "agent_id", "ca_file"):
            if not isinstance(self.wazuh.get(key, ""), str):
                raise ScannerError("Wazuh settings must be strings")
        url = self.wazuh.get("url", "")
        self.agent_id = ""
        if url:
            parsed = urlsplit(url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                    or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in ("", "/")):
                raise ScannerError("Wazuh URL must be an HTTPS origin without credentials")
            try:
                parsed.port
            except ValueError:
                raise ScannerError("Invalid Wazuh port") from None
            if not re.fullmatch(r"[0-9]{1,10}", self.wazuh.get("agent_id", "")):
                raise ScannerError("Configure one numeric Wazuh agent_id")
            # Wazuh indexes agent.id zero-padded ("001"); "1" would silently match nothing.
            self.agent_id = f"{int(self.wazuh['agent_id']):03d}"

    @classmethod
    def load(cls, path: str):
        try:
            with open(path, "rb") as f:
                return cls(tomllib.load(f))
        except (OSError, ValueError):
            raise ScannerError("Cannot read valid TOML configuration") from None

    def binary(self, key: str) -> str:
        value = self.local.get(key, "")
        if not value or not Path(value).is_file():
            raise ScannerError(f"{key} is not configured or not installed")
        resolved = Path(value).resolve(strict=True)
        if any(path.suffix.lower() in {".bat", ".cmd"} for path in (Path(value), resolved)):
            raise ScannerError("Use a native executable; batch wrappers are forbidden")
        return str(resolved)

    def status(self) -> dict:
        return result("bridge", "completed", data={
            "platform": platform.system(),
            "osquery_configured": bool(self.local.get("osquery_binary")),
            "clamav_configured": bool(self.local.get("clamav_binary")),
            "wazuh_configured": bool(self.wazuh.get("url")),
            "scan_root_aliases": list(self.roots),
            "note": "Configuration status only; engines, signatures, connectivity and PC safety are unverified"})

    def inventory(self, query_id: str, offset: int = 0) -> dict:
        check_offset(offset)
        # Stable ORDER BY keeps offset paging consistent between calls.
        queries = {
            "os_version": "SELECT name, version, major, minor, patch, platform FROM os_version",
            "listening_ports": ("SELECT lp.pid, p.name AS process, lp.address, lp.port, lp.protocol, lp.family "
                                "FROM listening_ports lp LEFT JOIN processes p USING (pid) "
                                "WHERE lp.port != 0 ORDER BY lp.port, lp.address, lp.pid"),
            "applications": {
                "Windows": "SELECT name, version FROM programs ORDER BY name, version",
                "Darwin": "SELECT name, bundle_short_version FROM apps ORDER BY name, bundle_short_version",
                "Linux": ("SELECT name, version FROM deb_packages UNION ALL "
                          "SELECT name, version FROM rpm_packages ORDER BY name, version"),
            }.get(platform.system()),
        }
        query = queries.get(query_id)
        if not query:
            raise ScannerError("Unsupported inventory query_id or platform")
        code, output, diagnostic = run_bounded(
            [self.binary("osquery_binary"), "--json", "--disable_extensions=true",
             f"{query} LIMIT {PAGE_SIZE + 1} OFFSET {offset};"],
            self.timeout, self.limit)
        if code != 0:
            raise ScannerError("osquery failed; table may be unsupported or permission denied")
        try:
            rows = json.loads(output)
        except ValueError:
            raise ScannerError("osquery returned invalid JSON") from None
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise ScannerError("Unexpected osquery result schema")
        page = rows[:PAGE_SIZE]
        next_offset, page_warnings = next_page(offset, len(page), len(rows) > PAGE_SIZE)
        partial = len(rows) > PAGE_SIZE or offset > 0 or bool(diagnostic.strip()) or not rows
        return result("osquery", "partial" if partial else "completed",
                      data={"query_id": query_id, "offset": offset, "next_offset": next_offset, "rows": page},
                      warnings=["Inventory only; this does not confirm vulnerabilities or malware"]
                      + (["Standard-user runs may omit sockets owned by other users or the system"]
                         if query_id == "listening_ports" else [])
                      + page_warnings
                      + (["One page, engine warning, or no observable rows; coverage incomplete"] if partial else []))

    def malware(self, root_alias: str, relative_path: str = ".") -> dict:
        if root_alias not in self.roots:
            raise ScannerError("Scan root alias is not authorized")
        if not isinstance(relative_path, str) or "\x00" in relative_path:
            raise ScannerError("Invalid relative path")
        relative = Path(relative_path)
        if relative.is_absolute() or relative.drive or ".." in relative.parts:
            raise ScannerError("Use a relative path within the authorized root")
        root = Path(self.roots[root_alias]).resolve(strict=True)
        target = (root / relative).resolve(strict=True)
        if not target.is_relative_to(root):
            raise ScannerError("Scan target escapes the authorized root")
        if not (target.is_dir() or target.is_file()):
            raise ScannerError("Scan target must be a regular file or directory")

        def within_root(location: str) -> str:
            # Report paths relative to the alias so owner paths are not passed onward.
            try:
                return Path(location).relative_to(root).as_posix()
            except ValueError:
                return location

        def mask(text: str) -> str:
            return text.replace(str(root), f"<{root_alias}>")

        # Coverage check and engine share one time budget.
        deadline = time.monotonic() + self.timeout
        binary = self.binary("clamav_binary")
        directory_limit, unreadable = inspect_directories(target, deadline)
        remaining = deadline - time.monotonic()
        if remaining < 1:
            raise ScannerError("Directory coverage check used the time budget; scan was not completed")
        code, output, diagnostic = run_bounded([
            binary, "--recursive=yes", "--infected",
            "--follow-dir-symlinks=0", "--follow-file-symlinks=0",
            f"--max-dir-recursion={MAX_DIRECTORY_LEVELS}",
            "--max-filesize=100M", "--max-scansize=200M", "--max-recursion=16",
            "--alert-exceeds-max=yes", str(target)], remaining, self.limit)
        findings, messages = [], []
        for line in output.splitlines():
            match = FOUND.fullmatch(line)
            if not match:
                messages.append(line)
                continue
            location, signature = match.groups()
            limit_hit = signature.startswith("Heuristics.Limits.Exceeded")
            findings.append({"kind": "scan_limit" if limit_hit else "malware",
                             "severity": "unknown" if limit_hit else "high",
                             "path": within_root(location), "signature": signature})
        findings.sort(key=lambda f: f["kind"] != "malware")
        findings_capped = len(findings) > PAGE_SIZE
        engine_report, report_truncated = excerpt(mask("\n".join(messages)))
        engine_diagnostic, diagnostic_truncated = excerpt(mask(diagnostic))
        scanned = re.search(r"^Scanned files:\s*(\d+)\s*$", output, re.MULTILINE)
        partial = (directory_limit or bool(unreadable) or findings_capped
                   or code not in (0, 1) or bool(diagnostic.strip()) or "ERROR" in output
                   or not scanned or int(scanned.group(1)) == 0
                   or any(f["kind"] == "scan_limit" for f in findings)
                   or (code == 1 and not findings))
        return result("clamav", "partial" if partial else "completed", findings=findings[:PAGE_SIZE],
                      data={"root_alias": root_alias, "relative_path": relative_path,
                            "exit_code": code, "findings_total": len(findings),
                            "unreadable_directories": [within_root(p) for p in unreadable[:REPORTED_DIRECTORIES]],
                            "engine_report": engine_report, "diagnostic": engine_diagnostic,
                            "engine_text_truncated": report_truncated or diagnostic_truncated},
                      warnings=["Signature-based detection only; no detection does not prove safety",
                                "Symlinks excluded; file/archive limits apply; signature freshness not verified"]
                      + (["Directory depth limit reached; deeper directories were not scanned"] if directory_limit else [])
                      + ([f"{len(unreadable)} directories could not be read and were not scanned"] if unreadable else [])
                      + ([f"Findings capped at {PAGE_SIZE}; malware findings are listed first"] if findings_capped else [])
                      + (["Scan coverage incomplete or engine error; do not report this PC as safe"] if partial else []))

    def vulnerabilities(self, offset: int = 0) -> dict:
        check_offset(offset)
        origin = self.wazuh.get("url", "")
        if not origin:
            raise ScannerError("Wazuh indexer is not configured")
        user = os.environ.get("PC_SCANNER_WAZUH_USER", "")
        password = os.environ.get("PC_SCANNER_WAZUH_PASSWORD", "")
        if not user or not password or ":" in user:
            raise ScannerError("Valid Wazuh credentials must be set in environment variables")
        body = {"from": offset, "size": PAGE_SIZE, "track_total_hits": True,
                "query": {"term": {"agent.id": self.agent_id}},
                # Most severe first, so a truncated result still carries the critical records.
                "sort": [{"vulnerability.score.base": {"order": "desc", "unmapped_type": "float"}},
                         {"vulnerability.id": {"order": "asc", "unmapped_type": "keyword"}},
                         {"package.name": {"order": "asc", "unmapped_type": "keyword"}}],
                "_source": ["agent.id", "package.name", "package.version", "vulnerability.id",
                            "vulnerability.severity", "vulnerability.score.base",
                            "vulnerability.detected_at"]}
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        request = Request(origin.rstrip("/") + "/wazuh-states-vulnerabilities-*/_search",
                          data=json.dumps(body).encode(), method="GET",
                          headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"})
        context = ssl.create_default_context(cafile=self.wazuh.get("ca_file") or None)
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
        try:
            with opener.open(request, timeout=min(self.timeout, 30)) as response:
                raw = response.read(self.limit + 1)
            if len(raw) > self.limit:
                raise ScannerError("Wazuh response exceeded size limit")
            payload = json.loads(raw)
        except HTTPError as exc:
            raise ScannerError(f"Wazuh HTTP error {exc.code}; access or index may be unavailable") from None
        except (URLError, TimeoutError, OSError):
            raise ScannerError("Wazuh connection or TLS verification failed") from None
        except ValueError:
            raise ScannerError("Wazuh returned invalid JSON") from None
        try:
            hits = payload["hits"]["hits"]
            total = payload["hits"]["total"]
            if isinstance(total, dict):
                total_value, relation = total["value"], total["relation"]
            else:
                total_value, relation = total, "eq"
            if not isinstance(hits, list) or type(total_value) is not int:
                raise ValueError()
            findings = []
            for hit in hits[:PAGE_SIZE]:
                source = hit["_source"]
                if source["agent"]["id"] != self.agent_id:
                    raise ScannerError("Wazuh returned data for an unauthorized agent")
                vulnerability = source["vulnerability"]
                severity = str(vulnerability.get("severity", "unknown")).lower()
                score = vulnerability.get("score")
                findings.append({"kind": "vulnerability", "id": vulnerability["id"],
                                 "severity": severity if severity in {"critical", "high", "medium", "low"} else "unknown",
                                 "score": score.get("base") if isinstance(score, dict) else None,
                                 "package": source.get("package", {}),
                                 "detected_at": vulnerability.get("detected_at")})
            next_offset, page_warnings = next_page(offset, len(findings), offset + len(findings) < total_value)
            incomplete = (relation != "eq" or offset > 0 or offset + len(findings) != total_value
                          or payload.get("timed_out", False)
                          or payload.get("_shards", {}).get("failed", 0) > 0)
            no_records = total_value == 0
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ScannerError("Unexpected Wazuh vulnerability result schema") from None
        return result("wazuh", "partial" if incomplete or no_records else "completed", findings=findings,
                      data={"agent_id": self.agent_id, "total": total_value, "offset": offset,
                            "next_offset": next_offset, "freshness": "unverified", "live_scan_triggered": False},
                      warnings=["Existing index inventory; endpoint identity and inventory freshness require verification",
                                "Zero findings can mean no inventory; this is not a safety verdict"]
                      + (["No vulnerability records for this agent_id; it may be wrong, unregistered or never scanned"]
                         if no_records else [])
                      + page_warnings
                      + (["One page of results or index search incomplete"] if incomplete else []))

    def invoke(self, operation: str, **kwargs) -> dict:
        operations = {"status": self.status, "inventory": self.inventory,
                      "malware": self.malware, "vulnerabilities": self.vulnerabilities}
        source = SOURCES.get(operation, "bridge")
        try:
            if operation not in operations:
                raise ScannerError("Unknown operation")
            return operations[operation](**kwargs)
        except ScannerError as exc:
            return result(source, "error", error=str(exc))
        except (OSError, ValueError, TypeError, RuntimeError):
            return result(source, "error", error="Operation could not complete; check configuration and input")
