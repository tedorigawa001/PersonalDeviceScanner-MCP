"""Private coverage ledger and bounded, name-free projections. Counts are scopes, never files."""
from __future__ import annotations

import os
import re
import secrets
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

REASONS = frozenset({"cloud_placeholder", "permission_denied", "metadata_unavailable", "file_size_limit",
                     "archive_limit", "engine_limit_unknown", "directory_depth_limit", "timeout", "cancelled",
                     "not_reached", "metadata_limit", "changed_during_scan", "target_missing",
                     "authorization_changed", "engine_error", "output_limit", "attribution_unknown"})
ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_TARGETS = 10000
MAX_BYTES = 16 * 1024 * 1024
LABELS = {"cloud_placeholder": "Cloud file not downloaded (metadata check only)",
          "permission_denied": "Permission denied", "metadata_unavailable": "File state could not be verified",
          "file_size_limit": "File size limit", "archive_limit": "Archive inspection limit",
          "engine_limit_unknown": "Unidentified engine limit", "directory_depth_limit": "Directory depth limit",
          "timeout": "Time limit reached", "cancelled": "Cancelled during inspection", "not_reached": "Not started",
          "metadata_limit": "Remaining range not fully listed", "changed_during_scan": "Changed during inspection",
          "target_missing": "Target no longer present", "authorization_changed": "Authorization or link changed",
          "engine_error": "Engine could not complete inspection", "output_limit": "Result output was incomplete",
          "attribution_unknown": "Result could not be matched reliably to a target"}


def metadata(path):
    """No content reads. Unlike cloud_placeholder, failures never mean local."""
    from . import core
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "target_missing", None
    except OSError:
        return "metadata_unavailable", None
    if core.is_link(path):
        return "authorization_changed", info
    if core.cloud_placeholder(path):
        return "cloud_placeholder", info
    return "local", info


def path_state(root, path):
    """Stop at an unavailable/link/placeholder ancestor, without probing its descendants."""
    state = metadata(root)[0]
    current = root
    for part in path.relative_to(root).parts:
        if state != "local":
            return state
        current = current / part
        state = metadata(current)[0]
    return state


def safety(target, deadline, cancel, levels, excluded=None, excluded_scopes=()):
    """Observe only metadata; no descent into placeholders or links. Unknowns block this engine part."""
    from . import core
    stack = [(target, levels)]
    count = 0
    while stack:
        core.check_cancel(cancel)
        if time.monotonic() >= deadline:
            raise core.ScannerError("Directory coverage check timed out; scan was not completed")
        path, depth = stack.pop()
        if path == excluded or path in excluded_scopes:
            continue
        count += 1
        if count > 200000:
            return "metadata_limit"
        state, info = metadata(path)
        if state in {"metadata_unavailable", "target_missing"}:
            return state
        if state != "local" or not stat.S_ISDIR(info.st_mode) or depth <= 0:
            continue
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    core.check_cancel(cancel)
                    stack.append((Path(entry.path), depth - 1))
                    if len(stack) + count > 200000:
                        return "metadata_limit"
        except PermissionError:
            # Existing inspection can report and safely exclude a directory that cannot be listed.
            return "permission_denied"
        except OSError:
            return "metadata_unavailable"
    return None


def new_ledger():
    return {"group": secrets.token_hex(16), "started": datetime.now(timezone.utc).isoformat(),
            "revision": 0, "nodes": {}, "complete": False, "limits": [], "attempt_id": secrets.token_hex(16)}


def put(ledger, relative, reasons=(), kind="file", active=True):
    relative = str(Path(relative))
    nodes = ledger["nodes"]
    if relative not in nodes:
        if len(nodes) >= MAX_TARGETS:
            from .core import ScannerError
            raise ScannerError("Coverage target limit reached")
        nodes[relative] = {"id": secrets.token_hex(16)}
    node = nodes[relative]
    node.update(reasons=sorted(set(reasons) & REASONS), kind=kind, active=active)
    return node


def degrade(ledger, relative):
    name = str(Path(relative))
    old = ledger["nodes"].get(name, {"id": secrets.token_hex(16)})
    ledger["nodes"] = {name: old}
    put(ledger, name, ["metadata_limit"], "unlisted_remainder")
    ledger["complete"] = False


def replace_scope(ledger, relative, issues):
    """Replace observations within this scope; siblings outside the selected scope survive."""
    scope = Path(relative)
    for name, node in ledger["nodes"].items():
        if Path(name) == scope or Path(name).is_relative_to(scope):
            node.update(reasons=[], active=False)
    put(ledger, relative, (), "subtree_remainder")
    for issue in issues:
        old = ledger["nodes"].get(issue["relative"], {}).get("reasons", [])
        put(ledger, issue["relative"], old + issue["reasons"], issue.get("kind", "file"))


def issue(relative, reason, kind="file"):
    return {"relative": relative, "reasons": [reason], "kind": kind}


def eligibility(reasons):
    if "cloud_placeholder" in reasons:
        return "metadata_only"
    if set(reasons) & {"target_missing", "authorization_changed", "metadata_unavailable"}:
        return "unavailable"
    if set(reasons) & {"permission_denied", "file_size_limit", "archive_limit", "engine_limit_unknown",
                       "directory_depth_limit"}:
        return "owner_action_required"
    return "ready"


def summary(ledger, selection=True):
    nodes = [v for v in ledger["nodes"].values() if v["active"] and v["reasons"]]
    counts = {reason: sum(reason in v["reasons"] for v in nodes) for reason in sorted(REASONS)}
    counts = {k: v for k, v in counts.items() if v}
    return {"schema": 1, "scan_group_id": ledger["group"], "group_started_at": ledger["started"],
            "attempt_id": ledger.get("attempt_id"), **({"attempt": ledger["attempt"]} if "attempt" in ledger else {}),
            "revision": ledger["revision"], "unit": "target_scopes",
            "unresolved": {"count": len(nodes), "quality": "exact_scope" if ledger["complete"] else "lower_bound",
                           "file_count": None},
            "by_reason": counts, "reason_counts_overlap": True, "enumeration_complete": ledger["complete"],
            "details_truncated": len(nodes) > 100, "assessment_limits": sorted(set(ledger["limits"])),
            "selection_available": selection and ledger["revision"] > 0,
            "stop_reason": ledger.get("stop_reason")}


def normalize(ledger):
    """An active parent denotes only its remainder, excluding active descendant scopes."""
    active = {name: node for name, node in ledger["nodes"].items() if node["active"] and node["reasons"]}
    for node in ledger["nodes"].values():
        node["excludes"] = []
    for name, node in active.items():
        for parent in Path(name).parents:
            other = active.get(str(parent))
            if other:
                other["excludes"].append(node["id"])
                break


def targets(ledger, show_paths=False):
    rows = []
    for name, node in ledger["nodes"].items():
        if node["active"] and node["reasons"]:
            rows.append({"target_id": node["id"], "scope_kind": node["kind"], "reasons": node["reasons"],
                         "eligibility": eligibility(node["reasons"]),
                         **({"relative_path": name} if show_paths else {})})
    return sorted(rows, key=lambda row: row["target_id"])


def validate(ledger):
    if not isinstance(ledger, dict) or not ID.fullmatch(ledger.get("group", "")):
        raise ValueError("Invalid coverage group")
    date = datetime.fromisoformat(ledger["started"])
    if date.tzinfo is None or type(ledger["revision"]) is not int or not 0 <= ledger["revision"] <= 10**9:
        raise ValueError("Invalid coverage revision")
    if type(ledger["complete"]) is not bool or not isinstance(ledger["limits"], list):
        raise ValueError("Invalid coverage state")
    if ledger.get("stop_reason") is not None and ledger["stop_reason"] not in REASONS:
        raise ValueError("Invalid coverage stop reason")
    if ledger.get("attempt_id") is not None and not ID.fullmatch(ledger["attempt_id"]):
        raise ValueError("Invalid attempt identity")
    if len(ledger["limits"]) > 32 or not all(v in {"stale_definitions", "unknown_definitions", "context_changed",
                                                   "diagnostic", "no_files", "findings_truncated"} for v in ledger["limits"]):
        raise ValueError("Invalid assessment limit")
    nodes = ledger["nodes"]
    if not isinstance(nodes, dict) or len(nodes) > MAX_TARGETS:
        raise ValueError("Invalid coverage targets")
    ids = set()
    for name, node in nodes.items():
        path = Path(name)
        if path.is_absolute() or path.drive or path.root or ".." in path.parts or "\x00" in name or str(path) != name:
            raise ValueError("Invalid coverage path")
        if (not isinstance(node, dict) or not ID.fullmatch(node.get("id", "")) or node["id"] in ids
                or type(node.get("active")) is not bool or not isinstance(node.get("reasons"), list)
                or len(node["reasons"]) > len(REASONS) or not set(node["reasons"]) <= REASONS
                or node.get("kind") not in {"file", "archive", "subtree_remainder", "unlisted_remainder"}):
            raise ValueError("Invalid coverage target")
        ids.add(node["id"])
    return ledger


def project(value):
    """Only validated name-free fields may enter summary history or drive dashboard commands."""
    try:
        if not isinstance(value, dict) or value.get("schema") != 1:
            return None
        group, revision, started = value["scan_group_id"], value["revision"], value["group_started_at"]
        if not isinstance(group, str) or not ID.fullmatch(group) or type(revision) is not int or not 0 <= revision <= 10**9:
            return None
        date = datetime.fromisoformat(started)
        if date.tzinfo is None:
            return None
        count = value["unresolved"]["count"]
        reasons = value["by_reason"]
        if (type(count) is not int or not 0 <= count <= MAX_TARGETS or not isinstance(reasons, dict)
                or not set(reasons) <= REASONS or any(type(v) is not int or not 0 <= v <= count for v in reasons.values())
                or value["unresolved"]["quality"] not in {"exact_scope", "lower_bound", "unknown"}
                or type(value["enumeration_complete"]) is not bool):
            return None
        limits = value["assessment_limits"]
        if not isinstance(limits, list) or len(limits) > 32 or not all(isinstance(v, str) and len(v) < 64 for v in limits):
            return None
        attempt = value.get("attempt")
        if attempt is not None and (not isinstance(attempt, dict) or attempt.get("status") not in {"completed", "partial"}
                or any(type(attempt.get(k)) is not int or not 0 <= attempt[k] <= 100 for k in ("selected", "finished"))
                or attempt["finished"] > attempt["selected"]):
            return None
        stop = value.get("stop_reason")
        if stop is not None and stop not in REASONS:
            return None
        attempt_id = value.get("attempt_id")
        if attempt_id is not None and (not isinstance(attempt_id, str) or not ID.fullmatch(attempt_id)):
            return None
        return {"schema": 1, "scan_group_id": group, "group_started_at": date.astimezone(timezone.utc).isoformat(),
                "revision": revision, "unit": "target_scopes", "unresolved": {"count": count,
                "quality": value["unresolved"]["quality"], "file_count": None}, "by_reason": dict(reasons),
                "reason_counts_overlap": True, "enumeration_complete": value["enumeration_complete"],
                "assessment_limits": list(limits), "details_truncated": bool(value.get("details_truncated")),
                "stop_reason": stop, **({"attempt_id": attempt_id} if attempt_id else {}),
                **({"attempt": {k: attempt[k] for k in ("selected", "finished", "status")}} if attempt else {})}
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        return None


def attach(report, issues, limits=()):
    ledger = new_ledger()
    ledger["complete"] = not any("metadata_limit" in i["reasons"] or i.get("kind") == "unlisted_remainder" for i in issues)
    ledger["limits"] = list(limits)
    try:
        for row in issues:
            old = ledger["nodes"].get(row["relative"], {}).get("reasons", [])
            put(ledger, row["relative"], old + row["reasons"], row.get("kind", "file"))
    except Exception as exc:
        from .core import ScannerError
        if not isinstance(exc, ScannerError):
            raise
        scope = os.path.commonpath([str(Path(i["relative"])) for i in issues]) or "."
        degrade(ledger, scope)
        issues = [issue(scope, "metadata_limit", "unlisted_remainder")]
        report["status"] = "partial"
        report["warnings"].append("Coverage target limit reached; remaining ranges are unknown")
    data = report.setdefault("data", {})
    data["coverage"] = summary(ledger, False)
    data["_coverage_issues"] = issues
    return report


def listing(ledger, reasons=(), cursor="", limit=50, show_paths=False):
    from .core import ScannerError
    if (type(limit) is not int or not 1 <= limit <= 100 or not isinstance(reasons, (list, tuple))
            or len(reasons) > len(REASONS) or not all(isinstance(r, str) and r in REASONS for r in reasons)):
        raise ScannerError("Invalid coverage filter or page limit")
    filters = sorted(set(reasons))
    rows = [row for row in targets(ledger, show_paths) if not filters or set(row["reasons"]) & set(filters)]
    # Cursors are server-issued opaque capabilities for a fixed immutable snapshot and filter.
    if cursor:
        if not isinstance(cursor, str) or not ID.fullmatch(cursor):
            raise ScannerError("Invalid coverage cursor")
        saved = ledger.get("cursors", {}).get(cursor)
        if saved is None or saved[:2] != [ledger["revision"], filters]:
            raise ScannerError("Invalid or stale coverage cursor")
        offset = saved[2]
    else:
        offset = 0
    next_cursor = None
    if offset + limit < len(rows):
        cache = ledger.setdefault("cursors", {})
        if len(cache) >= 256:
            cache.pop(next(iter(cache)))
        next_cursor = secrets.token_hex(16)
        cache[next_cursor] = [ledger["revision"], filters, offset + limit]
    return {"coverage": summary(ledger), "targets": rows[offset:offset + limit], "next_cursor": next_cursor}
