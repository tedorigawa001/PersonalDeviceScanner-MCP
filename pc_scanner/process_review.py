"""Owner-selected process provenance. Never run inspected code or return identifiers to MCP."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import stat
import time

from . import core, history
from .connections import Backend, Stopped, check, number, now

MAX_TARGETS = 16
MAX_FILE = 1024 * 1024
PACKAGE = re.compile(r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}\Z")
LIMITS = ["not_a_security_assessment", "no_payload_collection", "no_external_queries",
          "process_join_not_atomic", "owner_selected_files_not_proven_runtime_modules",
          "no_source_execution_or_semantic_audit", "no_signature_or_advisory_check",
          "local_filesystem_reads_may_block", "no_history_saved"]


def load(config):
    raw = config.get("process_review", {})
    if not isinstance(raw, dict):
        raise core.ScannerError("process_review must be a table")
    enabled, timeout = raw.get("enabled", False), raw.get("timeout_seconds", 15)
    if type(enabled) is not bool or type(timeout) is not int or not 1 <= timeout <= 60:
        raise core.ScannerError("process_review needs a boolean enabled and timeout_seconds 1..60")
    targets = raw.get("targets", {})
    if not isinstance(targets, dict) or len(targets) > MAX_TARGETS:
        raise core.ScannerError("process_review.targets must contain at most 16 owner-selected targets")
    identities = set()
    for alias, value in targets.items():
        if (not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", alias) or not isinstance(value, dict)
                or set(value) - {"pid", "start_time", "script_file", "package_file", "launch_file"}):
            raise core.ScannerError("Invalid process review target settings")
        for field, maximum in (("pid", 2147483647), ("start_time", 253402300799)):
            if type(value.get(field)) is not int or not 1 <= value[field] <= maximum:
                raise core.ScannerError("Process review targets need positive integer pid and start_time")
        for field in ("script_file", "package_file", "launch_file"):
            p = value.get(field)
            if p is not None and (not isinstance(p, str) or len(p) > 4096 or "\0" in p
                                  or not Path(p).is_absolute() or ".." in Path(p).parts):
                raise core.ScannerError("Process review files must be absolute paths without parent traversal")
        identity = value["pid"], value["start_time"]
        if identity in identities:
            raise core.ScannerError("Duplicate process review identity")
        identities.add(identity)
    from . import process_store
    return {"enabled": enabled, "timeout_seconds": timeout, "targets": targets,
            "storage": process_store.load(raw.get("storage", {}))}


def read_file(path, deadline, cancel):
    """Pin every POSIX directory; refuse links, placeholders and special files before reading.

    Unsupported platforms do not fall back to a path-based read through unchecked parents.
    Never chmod the input; package/script metadata need not already have private permissions.
    """
    check(deadline, cancel)
    if os.name != "posix":
        raise ValueError("file_backend_unavailable")
    p = Path(path)
    if not p.is_absolute() or ".." in p.parts:
        raise ValueError("file_unavailable")
    fd = os.open(p.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        current = Path(p.anchor)
        for index, part in enumerate(p.parts[1:]):
            check(deadline, cancel)
            current /= part
            info = os.stat(part, dir_fd=fd, follow_symlinks=False)
            if core.cloud_placeholder(current) or stat.S_ISLNK(info.st_mode):
                raise ValueError("file_unavailable")
            last = index == len(p.parts) - 2
            if not (stat.S_ISREG(info.st_mode) if last else stat.S_ISDIR(info.st_mode)):
                raise ValueError("file_unavailable")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if not last:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or not history.owned(fd, info)
                or info.st_nlink != 1 or info.st_size > MAX_FILE
                or getattr(info, "st_flags", 0) & core.SF_DATALESS):
            raise ValueError("file_unavailable")
        data = bytearray()
        while len(data) <= MAX_FILE:
            check(deadline, cancel)
            block = os.read(fd, min(65536, MAX_FILE + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) > MAX_FILE:
            raise ValueError("file_unavailable")
        check(deadline, cancel)
        return bytes(data), {"sha256": hashlib.sha256(data).hexdigest(),
                             "world_writable": bool(info.st_mode & 2), "bytes": len(data)}
    finally:
        os.close(fd)


def metadata(backend, target):
    # Integers validated in load(), not tool arguments or strings copied from OS output.
    pid = target["pid"]
    rows = backend.query("SELECT p.pid, p.start_time, p.path, p.name, p.parent, "
        "pp.path AS parent_path, pp.start_time AS parent_start_time FROM processes p "
        "LEFT JOIN processes pp ON p.parent = pp.pid WHERE p.pid = " + str(pid) + " LIMIT 2;")
    if not rows:
        return None
    if len(rows) != 1 or number(rows[0].get("pid"), 2147483647) != pid:
        raise ValueError("process_identity_unavailable")
    row = rows[0]
    if number(row.get("start_time"), 253402300799) != target["start_time"]:
        raise ValueError("process_identity_changed")
    for field in ("path", "name", "parent_path"):
        if row.get(field) is not None and (not isinstance(row[field], str) or len(row[field]) > 4096):
            raise ValueError("process_metadata_invalid")
    return row


def package_details(path, deadline, cancel):
    data, info = read_file(path, deadline, cancel)
    obj = json.loads(data)
    if not isinstance(obj, dict) or not isinstance(obj.get("dependencies", {}), dict):
        raise ValueError("package_metadata_invalid")
    deps = obj.get("dependencies", {})
    if len(deps) > 100:
        raise ValueError("dependency_limit")
    resolved, missing, unavailable, records = 0, 0, 0, []
    for name in deps:
        check(deadline, cancel)
        if not isinstance(name, str) or not PACKAGE.fullmatch(name):
            raise ValueError("package_metadata_invalid")
        state, location = "not_found_in_checked_locations", None
        # Standard ancestor lookup only, never NODE_PATH, global installs or executing a loader.
        for base in [Path(path).parent, *Path(path).parent.parents]:
            candidate = base / "node_modules" / name / "package.json"
            try:
                content, _ = read_file(candidate, deadline, cancel)
                package = json.loads(content)
                if not isinstance(package, dict) or package.get("name") != name:
                    raise ValueError("package_metadata_invalid")
                state, location = "metadata_found_not_runtime_proven", str(candidate)
                resolved += 1
                break
            except FileNotFoundError:
                continue
            except (OSError, ValueError, RecursionError):
                # A symlink/unreadable earlier candidate may be the actual Node resolution;
                # do not silently attribute a later package to this runtime.
                state = "resolution_unavailable"
                unavailable += 1
                break
        else:
            missing += 1
        records.append({"name": core.clean_text(name), "state": state,
                        "metadata_path": core.clean_text(location) if location else None})
    return {**info, "dependency_count": len(deps), "metadata_found": resolved,
            "not_found": missing, "unavailable": unavailable, "dependencies": records,
            "resolution_scope": "standard_ancestor_metadata_only"}


def launch_details(path, row, target, deadline, cancel):
    data, info = read_file(path, deadline, cancel)
    obj = plistlib.loads(data)
    if not isinstance(obj, dict):
        raise ValueError("launch_metadata_invalid")
    args = obj.get("ProgramArguments", [])
    if not isinstance(args, list) or len(args) > 256 or not all(isinstance(a, str) for a in args):
        raise ValueError("launch_metadata_invalid")
    program = obj.get("Program", args[0] if args else None)
    # Exact lexical match only; no shlex, substring or basename matching of argv.
    configured_match = program == row.get("path") and (
        not target.get("script_file") or target["script_file"] in args[1:])
    state = "configured_match_unverified" if configured_match else "configured_mismatch"
    label = obj.get("Label")
    if (configured_match and platform.system() == "Darwin" and isinstance(label, str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", label)):
        check(deadline, cancel)
        code, output, _ = core.run_bounded(["/bin/launchctl", "print", f"gui/{os.getuid()}/{label}"],
            max(.001, min(2, deadline - time.monotonic())), 128 * 1024, cancel)
        check(deadline, cancel)
        # Top-level fields only (nested blocks are indented deeper). The loaded job itself must come from this
        # plist with the same program and script; a shared label or a plist edited after loading is not enough.
        loaded = {}
        for key, value in re.findall(r"^\t(path|program|pid) = (.*)$", output, re.M):
            loaded.setdefault(key, []).append(value)
        blocks = re.findall(r"^\targuments = \{\n((?:\t\t.*\n)*)\t\}$", output, re.M)
        loaded_args = [a[2:] for a in blocks[0].splitlines()] if len(blocks) == 1 else []
        if (code == 0 and loaded.get("pid") == [str(target["pid"])] and loaded.get("path") == [str(Path(path))]
                and loaded.get("program") == [row.get("path")]
                and (not target.get("script_file") or target["script_file"] in loaded_args[1:])):
            state = "loaded_job_pid_matches"
    return {**info, "state": state, "run_at_load": obj.get("RunAtLoad") is True,
            "keep_alive_configured": bool(obj.get("KeepAlive")),
            "label": core.clean_text(label) if isinstance(label, str) else None}


def review(scanner, cancel=None, progress=None, save_details=False):
    settings = scanner.process_review_settings
    if not settings["enabled"]:
        raise core.ScannerError("Process review is disabled")
    if type(save_details) is not bool or (save_details and (scanner.via != "cli" or not settings["storage"]["enabled"])):
        raise core.ScannerError("Process review detail saving is not authorized")
    if not scanner._process_review_lock.acquire(False):
        raise core.ScannerError("Process review is busy")
    started_at, run_id = now(), secrets.token_hex(16)
    deadline = time.monotonic() + settings["timeout_seconds"]
    # current is the target still being checked; a stop marks only it, never one that passed its final check.
    rows, stop, current = [], None, None
    try:
        if progress:
            progress.set_deadline(deadline)
        check(deadline, cancel)
        if not settings["targets"]:
            raise core.ScannerError("No owner-selected process review targets configured")
        backend = Backend(scanner, deadline, cancel)
        for index, target in enumerate(settings["targets"].values(), 1):
            check(deadline, cancel)
            current = item = {"label": f"P{index:02}", "identity": "unavailable", "runtime": "unknown",
                              "launch": "not_requested", "script": "not_requested", "package": "not_requested",
                              "attention": [], "details": {}}
            rows.append(item)
            try:
                row = metadata(backend, target)
                if row is None:
                    item["identity"] = "not_observed"
                    item["attention"].append("process_not_observed")
                    current = None
                    continue
                item["identity"] = "start_time_matches"
                item["details"]["process"] = {k: core.clean_text(v, 4096) if isinstance(v, str) else v
                                               for k, v in row.items()}
                base = (row.get("path") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
                item["runtime"] = "node" if base in {"node", "node.exe"} else (
                    "python" if re.fullmatch(r"python(?:[0-9.]+)?(?:\.exe)?", base) else "other")
                for field, kind in (("script_file", "script"), ("package_file", "package"), ("launch_file", "launch")):
                    if field not in target:
                        continue
                    try:
                        if kind == "script":
                            _, info = read_file(target[field], deadline, cancel)
                            info["state"] = "owner_selected_file_hashed"
                        elif kind == "package":
                            info = package_details(target[field], deadline, cancel)
                            info["state"] = "metadata_checked"
                            if info["not_found"] or info["unavailable"]:
                                item["attention"].append("dependency_resolution_unconfirmed")
                        else:
                            info = launch_details(target[field], row, target, deadline, cancel)
                        item[kind] = info["state"]
                        item["details"][kind] = {"path": core.clean_text(target[field], 4096), **info}
                        if info["world_writable"]:
                            item["attention"].append(kind + "_world_writable")
                    except (OSError, ValueError, plistlib.InvalidFileException, RecursionError):
                        item[kind] = "unavailable"
                        item["attention"].append(kind + "_unavailable")
                # Re-check after launchctl/file work; a PID match alone is not provenance.
                again = metadata(backend, target)
                if again is None or again.get("path") != row.get("path"):
                    raise ValueError("process_identity_changed")
            except (OSError, ValueError, core.ScannerError) as exc:
                if isinstance(exc, Stopped):
                    raise
                item["identity"] = "unavailable"
                item["attention"].append("process_identity_or_read_unavailable")
                # Do not retain a stale attribution when the final identity check failed.
                item["details"] = {}
                item["launch"] = item["script"] = item["package"] = "unavailable"
            current = None
            if progress:
                progress.update(stage="running")
        check(deadline, cancel)
        if backend.limits:
            stop = "read_limit_or_warning"
    except Stopped as exc:
        stop = exc.reason
        if current is not None:
            current["identity"] = "not_rechecked"
            current["launch"] = "unavailable"
            current["attention"].append("interrupted_before_final_identity_check")
            current["details"] = {}
    finally:
        scanner._process_review_lock.release()
    data = {"checked_at": now(), "started_at": started_at, "finished_at": now(), "run_id": run_id,
            "target_count": len(settings["targets"]), "reviewed_count": len(rows),
            "processes": rows, "attention_counts": dict(Counter(a for r in rows for a in r["attention"])),
            "limitations": LIMITS, "stop_reason": stop, "persistence": "not_saved"}
    report = core.result("process_review", "partial" if stop or any(r["attention"] for r in rows) else "completed", data=data)
    # An allowed launch mismatch/unverified result is explicitly incomplete, not a success claim.
    if any(r["launch"] not in {"not_requested", "loaded_job_pid_matches"} for r in rows):
        report["status"] = "partial"
    if save_details:
        from . import process_store
        if progress and not data["stop_reason"] and not (cancel is not None and cancel.is_set()):
            progress.update(stage="saving", persistence="not_saved")
            progress.set_deadline(time.monotonic() + 5)
        process_store.save(scanner, report, cancel)
    return for_mcp(report) if scanner.via == "mcp" else report


# Fixed texts the owner can act on; none quotes a configured name, path or value. Any other error is replaced.
ERRORS = frozenset({
    "Process review is disabled", "Process review is busy",
    "No owner-selected process review targets configured", "osquery_binary is not configured or not installed",
    "Configuration sections must be tables", "process_review must be a table",
    "process_review needs a boolean enabled and timeout_seconds 1..60",
    "process_review.targets must contain at most 16 owner-selected targets", "Invalid process review target settings",
    "Process review targets need positive integer pid and start_time",
    "Process review files must be absolute paths without parent traversal", "Duplicate process review identity",
    "Invalid process review storage settings", "Process review detail saving is not authorized"})


def for_cli(report):
    view = for_mcp(report)
    data = report.get("data", {})
    state = data.get("persistence", "not_saved")
    if state in {"not_saved", "not_saved_interrupted", "details_saved", "save_failed"}:
        view["data"]["persistence"] = state
    from .process_store import ID
    rid = data.get("record_id")
    if isinstance(rid, str) and ID.fullmatch(rid):
        view["data"]["record_id"] = rid
    return view


def for_mcp(report):
    """Build a fresh allowlisted view, including on errors. Never copy diagnostics or config warnings."""
    data = report.get("data", {})
    keys = ("label", "identity", "runtime", "launch", "script", "package", "attention")
    error = report.get("error")
    return core.result("process_review", report.get("status", "error"),
        **({"error": error if error in ERRORS else "Process review could not complete; check local configuration"}
           if error else {}),
        data={"target_count": data.get("target_count", 0), "reviewed_count": data.get("reviewed_count", 0),
              "processes": [{k: row[k] for k in keys} for row in data.get("processes", [])],
              "attention_counts": data.get("attention_counts", {}), "limitations": LIMITS,
              "stop_reason": data.get("stop_reason"), "persistence": "not_saved"})
