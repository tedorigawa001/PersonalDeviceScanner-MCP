"""Private, local-CLI-only process review records. No collection, execution or network APIs."""
from __future__ import annotations

import base64
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading
import time

from . import core, history

DEFAULTS = dict(enabled=False, directory="", retention_days=7, max_records=32, max_total_mb=32)
ID = re.compile(r"[0-9a-f]{32}\Z")
REV = re.compile(r"[0-9a-f]{64}\Z")
JSON_LIMIT, HTML_LIMIT, ENTRY_LIMIT = 2 * 1024 * 1024, 8 * 1024 * 1024, 1024
_lock = threading.Lock()
IDENTITIES = {"unavailable", "not_observed", "not_rechecked", "start_time_matches"}
LAUNCH = {"not_requested", "unavailable", "configured_mismatch", "configured_match_unverified", "loaded_job_pid_matches"}
SCRIPT = {"not_requested", "unavailable", "owner_selected_file_hashed"}
PACKAGE = {"not_requested", "unavailable", "metadata_checked"}
ATTENTION = {"process_not_observed", "dependency_resolution_unconfirmed", "process_identity_or_read_unavailable",
             "interrupted_before_final_identity_check", *(k + s for k in ("script", "package", "launch")
                                                         for s in ("_unavailable", "_world_writable"))}
NOTICE = ("Local private process observations; unconfirmed does not mean safe. Selected files and package metadata "
          "do not prove runtime loading. Signature, advisory and communication purpose are not evaluated. "
          "Rebuild this static page after expiry. Open browser copies/backups cannot be recalled by deletion.")
LABELS = {"start_time_matches": "Identity matched before and after review",
          "not_rechecked": "Identity not rechecked after interruption", "not_observed": "Process not observed",
          "unavailable": "Could not verify", "not_requested": "Not requested",
          "loaded_job_pid_matches": "Running launch job matched the selected configuration",
          "configured_match_unverified": "Configuration matches; running origin unconfirmed",
          "configured_mismatch": "Launch configuration does not match"}


class MissingParent(OSError):
    """A folder above the store does not exist; it is never created automatically."""


def managed(name):
    """Files this store owns. Anything else in the folder is counted, never read, followed or deleted."""
    return bool(name in {".lock", "dashboard.html", "dashboard.json"}
                or (name.endswith(".json") and ID.fullmatch(name[:-5])) or re.fullmatch(r"\.[0-9a-f]{32}\.tmp", name))


def load(raw):
    if not isinstance(raw, dict) or set(raw) - DEFAULTS.keys():
        raise core.ScannerError("Invalid process review storage settings")
    settings = {**DEFAULTS, **raw}
    if type(settings["enabled"]) is not bool:
        raise core.ScannerError("Invalid process review storage settings")
    for key, maximum in (("retention_days", 30), ("max_records", 100), ("max_total_mb", 128)):
        if type(settings[key]) is not int or not 1 <= settings[key] <= maximum:
            raise core.ScannerError("Invalid process review storage settings")
    path = settings["directory"]
    if not isinstance(path, str) or len(path) > 4096 or "\0" in path or (path and (
            not Path(path).is_absolute() or ".." in Path(path).parts)):
        raise core.ScannerError("Invalid process review storage settings")
    return settings


def clock():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def date(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\+00:00", value):
        raise ValueError("invalid timestamp")
    return datetime.fromisoformat(value)


def integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid count")
    return value


def text(value, maximum=4096, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError("invalid text")
    cleaned = core.clean_text(value, None)
    if len(cleaned) > maximum:
        raise ValueError("escaped text exceeds limit")
    return cleaned


def choice(value, allowed):
    if value not in allowed:
        raise ValueError("invalid state")
    return value


def boolean(value):
    if type(value) is not bool:
        raise ValueError("invalid boolean")
    return value


def digest(value):
    if not isinstance(value, str) or not REV.fullmatch(value):
        raise ValueError("invalid digest")
    return value


def detail(kind, obj):
    if not isinstance(obj, dict):
        raise ValueError("invalid detail")
    if kind == "process":
        out = {}
        for k in ("pid", "start_time", "parent", "parent_start_time"):
            v = obj.get(k)
            # osquery can report -1 for an unavailable parent's start time.
            # Preserve the lack of evidence rather than treating it as a timestamp.
            if k == "parent_start_time" and (type(v) is int and v == -1 or v == "-1"):
                v = None
            out[k] = None if v in (None, "") else integer(int(v) if isinstance(v, str) and v.isascii() and v.isdigit() else v, 253402300799)
        out.update({k: text(obj.get(k), nullable=True) for k in ("path", "name", "parent_path")})
        return out
    out = {"path": text(obj["path"]), "sha256": digest(obj["sha256"]),
           "bytes": integer(obj["bytes"], 1024 * 1024), "world_writable": boolean(obj["world_writable"])}
    out["state"] = choice(obj["state"], {"script": SCRIPT, "package": PACKAGE, "launch": LAUNCH}[kind])
    if kind == "launch":
        out.update(label=text(obj.get("label"), nullable=True), run_at_load=boolean(obj["run_at_load"]),
                   keep_alive_configured=boolean(obj["keep_alive_configured"]))
    if kind == "package":
        deps = obj["dependencies"]
        if not isinstance(deps, list) or len(deps) > 100:
            raise ValueError("invalid dependencies")
        out.update({k: integer(obj[k], 100) for k in ("dependency_count", "metadata_found", "not_found", "unavailable")})
        if out["dependency_count"] != len(deps) or sum(out[k] for k in ("metadata_found", "not_found", "unavailable")) != len(deps):
            raise ValueError("inconsistent dependencies")
        out["dependencies"] = [{"name": text(d["name"], 256), "state": choice(d["state"], {
            "not_found_in_checked_locations", "metadata_found_not_runtime_proven", "resolution_unavailable"}),
            "metadata_path": text(d.get("metadata_path"), nullable=True)} for d in deps]
        out["resolution_scope"] = choice(obj["resolution_scope"], {"standard_ancestor_metadata_only"})
    return out


def snapshot(data, status):
    from .process_review import LIMITS
    rows = data["processes"]
    if not isinstance(rows, list) or len(rows) > 16:
        raise ValueError("invalid targets")
    projected = []
    labels = set()
    for row in rows:
        label = row["label"]
        if not isinstance(label, str) or not re.fullmatch(r"P(?:0[1-9]|1[0-6])", label) or label in labels:
            raise ValueError("invalid label")
        labels.add(label)
        out = {"label": label, "identity": choice(row["identity"], IDENTITIES),
               "runtime": choice(row["runtime"], {"node", "python", "other", "unknown"}),
               "launch": choice(row["launch"], LAUNCH), "script": choice(row["script"], SCRIPT),
               "package": choice(row["package"], PACKAGE)}
        if not isinstance(row["attention"], list) or len(row["attention"]) > 16:
            raise ValueError("invalid attention")
        out["attention"] = [choice(a, ATTENTION) for a in row["attention"]]
        raw = row.get("details", {})
        if not isinstance(raw, dict):
            raise ValueError("invalid details")
        out["details"] = ({k: detail(k, raw[k]) for k in ("process", "script", "package", "launch") if k in raw}
                          if out["identity"] == "start_time_matches" else {})
        if out["identity"] != "start_time_matches" and out["launch"] == "loaded_job_pid_matches":
            raise ValueError("unconfirmed launch")
        projected.append(out)
    target_count = integer(data["target_count"], 16)
    if integer(data["reviewed_count"], 16) != len(projected) or target_count < len(projected):
        raise ValueError("invalid totals")
    return {"status": choice(status, {"completed", "partial"}), "target_count": target_count,
            "reviewed_count": len(projected), "processes": projected, "limitations": list(LIMITS)}


def encode(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def decode(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate JSON key")
            obj[key] = value
        return obj
    return json.loads(raw, object_pairs_hook=unique)


def directory(settings):
    return Path(settings["directory"]) if settings["directory"] else history.default_file().parent / "process-review"


def local_filesystem(fd):
    """Fail closed on unrecognized storage. No network or shell probing."""
    if sys.platform == "darwin":
        import ctypes as c
        # Darwin SDK sys/mount.h: __DARWIN_STRUCT_STATFS64 prefix, MNT_LOCAL = 0x1000.
        class Prefix(c.Structure):
            _fields_ = [("bsize", c.c_uint32), ("iosize", c.c_int32),
                        ("blocks", c.c_uint64 * 5), ("fsid", c.c_int32 * 2),
                        ("owner", c.c_uint32), ("type", c.c_uint32), ("flags", c.c_uint32)]
        lib = c.CDLL(None)
        func = getattr(lib, "fstatfs$INODE64", None) or getattr(lib, "fstatfs64", None)
        if func is None:
            return False
        func.argtypes, func.restype = [c.c_int, c.c_void_p], c.c_int
        buffer = c.create_string_buffer(4096)
        return func(fd, buffer) == 0 and bool(Prefix.from_buffer(buffer).flags & 0x1000)
    if sys.platform.startswith("linux"):
        info = os.fstat(fd)
        device = f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
        with open("/proc/self/mountinfo", "rb") as f:
            raw = f.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return False
        types = set()
        for line in raw.decode("utf-8", "replace").splitlines():
            left, sep, right = line.partition(" - ")
            fields = left.split()
            if sep and len(fields) > 2 and fields[2] == device:
                types.add(right.split()[0])
        return bool(types) and types <= {"ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs", "ramfs", "overlay", "zfs", "f2fs", "bcachefs"}
    return False


class Store:
    def __init__(self, settings, cancel=None):
        self.settings, self.cancel = settings, cancel
        self.deadline = time.monotonic() + 5
        self.fd = self.parent = None

    def check(self):
        if (self.cancel is not None and self.cancel.is_set()) or time.monotonic() >= self.deadline:
            raise OSError("Store interrupted")

    def safe(self, info, folder=False):
        if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if folder else 0o600)
                or not (stat.S_ISDIR(info.st_mode) if folder else stat.S_ISREG(info.st_mode))
                or (not folder and info.st_nlink != 1) or getattr(info, "st_flags", 0) & core.SF_DATALESS):
            raise OSError("Store permissions or type unavailable")

    @contextmanager
    def open(self, create=False):
        if os.name != "posix":
            raise OSError("Store backend unavailable")
        self.check()
        if not _lock.acquire(False):
            raise OSError("Store busy")
        lockfd = None
        try:
            self.path = directory(self.settings)
            if not self.path.name or not self.path.is_absolute() or ".." in self.path.parts:
                raise OSError("Invalid store directory")
            self.parent = os.open(self.path.anchor, os.O_RDONLY | os.O_DIRECTORY)
            current = Path(self.path.anchor)
            for part in self.path.parts[1:-1]:
                self.check()
                current /= part
                # Known cloud roots are refused without opening/hydrating their contents.
                if part in {"CloudStorage", "Mobile Documents"} or part.lower().startswith("onedrive") or core.cloud_placeholder(current):
                    raise OSError("Store must be local")
                try:
                    fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.parent)
                except FileNotFoundError:
                    # No store can exist below a missing folder; saving names the cause instead of creating it.
                    if not create:
                        yield None
                        return
                    raise MissingParent("Store parent folder does not exist") from None
                info = os.fstat(fd)
                if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
                    os.close(fd)
                    raise OSError("Writable store ancestor")
                os.close(self.parent)
                self.parent = fd
            if core.cloud_placeholder(self.path) or self.path.name in {"CloudStorage", "Mobile Documents"} or self.path.name.lower().startswith("onedrive"):
                raise OSError("Store must be local")
            if not local_filesystem(self.parent):
                raise OSError("Local parent filesystem could not be verified")
            try:
                self.fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.parent)
            except FileNotFoundError:
                if not create:
                    yield None
                    return
                os.mkdir(self.path.name, 0o700, dir_fd=self.parent)
                self.fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.parent)
            self.info = os.fstat(self.fd)
            self.safe(self.info, True)
            if not local_filesystem(self.fd):
                raise OSError("Local filesystem could not be verified")
            import fcntl
            lockfd = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
            self.safe(os.fstat(lockfd))
            until = min(self.deadline, time.monotonic() + 1)
            while True:
                self.check()
                try:
                    fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= until:
                        raise OSError("Store busy") from None
                    time.sleep(.01)
            self.unchanged()
            yield self
        finally:
            for fd in (lockfd, self.fd, self.parent):
                if fd is not None:
                    os.close(fd)
            self.fd = self.parent = None
            _lock.release()

    def unchanged(self):
        self.check()
        info = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        self.safe(info, True)
        if (info.st_dev, info.st_ino) != (self.info.st_dev, self.info.st_ino):
            raise OSError("Store directory changed")

    def names(self):
        self.unchanged()
        names = []
        with os.scandir(self.fd) as items:
            for item in items:
                self.check()
                names.append(item.name)
                if len(names) > ENTRY_LIMIT:
                    raise OSError("Store enumeration limit")
        return names

    def read(self, name, limit=JSON_LIMIT):
        self.unchanged()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            self.safe(info)
            if info.st_size > limit:
                raise OSError("Store file limit")
            data = bytearray()
            while len(data) <= limit:
                self.check()
                block = os.read(fd, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            after = os.fstat(fd)
            if len(data) > limit or (info.st_size, info.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise OSError("Store file changed")
            return bytes(data), info
        finally:
            os.close(fd)

    def unlink(self, name, revision=None):
        raw, info = self.read(name, HTML_LIMIT if name == "dashboard.html" or name.endswith(".tmp") else JSON_LIMIT)
        if revision is not None and hashlib.sha256(raw).hexdigest() != revision:
            raise OSError("Store revision changed")
        self.unchanged()
        current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns):
            raise OSError("Store file changed")
        os.unlink(name, dir_fd=self.fd)
        self.sync()

    def sync(self):
        # Make a rename or deletion itself durable. Best effort: the change is already visible,
        # so a failure here must not turn a published record into "not saved".
        try:
            os.fsync(self.fd)
        except OSError:
            pass

    def used(self):
        """Capacity covers the store's own files; an unrelated file (e.g. Finder's .DS_Store) never blocks it."""
        total = 0
        for name in self.names():
            if managed(name):
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                self.safe(info)
                total += info.st_size
        return total

    def unmanaged(self):
        return sum(not managed(name) for name in self.names())

    def atomic(self, name, data, limit):
        self.unchanged()
        if len(data) > limit or self.used() + len(data) > self.settings["max_total_mb"] * 1024 * 1024:
            raise OSError("Store capacity reached")
        try:
            self.read(name, limit)
        except FileNotFoundError:
            pass
        else:
            if name.endswith(".json") and ID.fullmatch(name[:-5]):
                raise OSError("Record ID collision; existing record retained")
        temp = "." + secrets.token_hex(16) + ".tmp"
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        published = False
        try:
            with os.fdopen(fd, "wb") as f:
                for offset in range(0, len(data), 65536):
                    self.check()
                    f.write(data[offset:offset + 65536])
                f.flush()
                os.fsync(f.fileno())
            self.unchanged()
            os.replace(temp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            published = True
            # No cancellation/deadline check after publication: a committed record is saved.
            self.sync()
        finally:
            if not published:
                try:
                    os.unlink(temp, dir_fd=self.fd)
                except FileNotFoundError:
                    pass

    def invalidate(self):
        for name in ("dashboard.html", "dashboard.json"):
            try:
                self.unlink(name)
            except FileNotFoundError:
                pass

    def inventory(self):
        now = clock()
        entries = []
        for name in self.names():
            if not name.endswith(".json") or not ID.fullmatch(name[:-5]):
                continue
            entry = {"record_id": name[:-5], "state": "unavailable", "revision": None}
            try:
                raw, _ = self.read(name)
                entry["revision"] = hashlib.sha256(raw).hexdigest()
                entry["state"] = "invalid"
                obj = decode(raw)
                if not isinstance(obj, dict) or set(obj) != {"schema", "record_id", "run_id", "started_at", "finished_at", "saved_at", "expires_at", "snapshot"}:
                    raise ValueError("invalid record")
                if type(obj["schema"]) is not int or obj["schema"] != 1 or obj["record_id"] != entry["record_id"] or not isinstance(obj["run_id"], str) or not ID.fullmatch(obj["run_id"]):
                    raise ValueError("invalid record")
                started, finished, saved, expires = (date(obj[k]) for k in ("started_at", "finished_at", "saved_at", "expires_at"))
                if not started <= finished <= saved <= now or not saved < expires <= saved + timedelta(days=30):
                    raise ValueError("invalid time")
                snap = obj["snapshot"]
                canonical = snapshot(snap, snap["status"])
                if canonical != snap:
                    raise ValueError("invalid snapshot")
                effective = min(expires, saved + timedelta(days=self.settings["retention_days"]))
                entry.update(state="expired" if now >= effective else "active", record=obj,
                             saved_at=obj["saved_at"], expires_at=stamp(effective))
            except FileNotFoundError:
                continue
            except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
                pass
            entries.append(entry)
        groups = Counter(e["record"]["run_id"] for e in entries if "record" in e)
        for entry in entries:
            if "record" in entry and groups[entry["record"]["run_id"]] > 1:
                entry["state"] = "duplicate"
        return entries

    def manifest(self, entries):
        active = [e for e in entries if e["state"] == "active"]
        return {"schema": 1, "records": {e["record_id"]: e["revision"] for e in active},
                "expires_at": min((e["expires_at"] for e in active), default=None),
                "retention_days": self.settings["retention_days"]}

    def validate_page(self, entries):
        names = self.names()
        if "dashboard.html" not in names and "dashboard.json" not in names:
            return
        valid = False
        try:
            self.read("dashboard.html", HTML_LIMIT)
            raw, _ = self.read("dashboard.json")
            valid = decode(raw) == self.manifest(entries) and not any(e["state"] in {"invalid", "unavailable", "duplicate"} for e in entries)
        except (FileNotFoundError, ValueError, RecursionError):
            pass
        if not valid:
            self.invalidate()

    def prune(self, entries):
        expired = [e for e in entries if e["state"] == "expired"]
        if expired:
            self.invalidate()
        deleted, failed = 0, 0
        for e in expired:
            try:
                self.unlink(e["record_id"] + ".json", e["revision"])
                deleted += 1
            except OSError:
                failed += 1
        return deleted, failed

    def clean_temps(self):
        deleted, failed = 0, 0
        for name in self.names():
            if re.fullmatch(r"\.[0-9a-f]{32}\.tmp", name):
                try:
                    self.unlink(name)
                    deleted += 1
                except OSError:
                    failed += 1
        return deleted, failed


def settings(scanner):
    return scanner.process_review_settings["storage"]


def save(scanner, report, cancel=None):
    """Called once by an explicitly authorized local CLI review, never by MCP/history."""
    if scanner.via != "cli" or not settings(scanner)["enabled"]:
        raise core.ScannerError("Process review detail saving is not authorized")
    data = report["data"]
    cancelled = cancel is not None and cancel.is_set()
    if data.get("stop_reason") or cancelled:
        # A read limit or engine warning is not an interruption, but its result is incomplete, so it is not saved either.
        data["persistence"] = ("not_saved_interrupted" if cancelled or data.get("stop_reason") in {"cancelled", "timeout"}
                               else "not_saved_incomplete")
        return
    try:
        snap = snapshot(data, report["status"])
        run_id = data["run_id"]
        if not isinstance(run_id, str) or not ID.fullmatch(run_id):
            raise ValueError("invalid run")
        with Store(settings(scanner), cancel).open(create=True) as store:
            entries = store.inventory()
            store.validate_page(entries)
            if any(e.get("record", {}).get("run_id") == run_id for e in entries):
                raise ValueError("duplicate run")
            deleted, failed = store.prune(entries)
            if failed:
                raise OSError("Expiry cleanup incomplete")
            entries = store.inventory()
            if len(entries) >= settings(scanner)["max_records"]:
                raise OSError("Record capacity reached")
            store.invalidate()
            saved = clock()
            record_id = secrets.token_hex(16)
            obj = {"schema": 1, "record_id": record_id, "run_id": run_id,
                   "started_at": stamp(datetime.fromisoformat(data["started_at"])),
                   "finished_at": stamp(datetime.fromisoformat(data["finished_at"])),
                   "saved_at": stamp(saved), "expires_at": stamp(saved + timedelta(days=settings(scanner)["retention_days"])),
                   "snapshot": snap}
            if not date(obj["started_at"]) <= date(obj["finished_at"]) <= saved:
                raise ValueError("invalid time")
            store.atomic(record_id + ".json", encode(obj), JSON_LIMIT)
            data.update(persistence="details_saved", record_id=record_id)
    except MissingParent:
        data.update(persistence="save_failed", persistence_reason="store_parent_missing")
        report["warnings"].append("Process review details were not saved: a folder above the private store does not exist; "
                                  "create it or set process_review.storage.directory")
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        data["persistence"] = "save_failed"
        report["warnings"].append("Process review details could not be saved; check the private local store, capacity and permissions")


def render(entries, manifest):
    from .dashboard import STYLE
    def esc(value): return html.escape(core.clean_text(str(value), None), quote=True)
    active = sorted((e for e in entries if e["state"] == "active"), key=lambda e: (e["record"]["finished_at"], e["record_id"]), reverse=True)
    uncertain = sum(e["state"] in {"invalid", "unavailable", "duplicate"} for e in entries)
    style_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    parts = [f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'sha256-{style_hash}\'; base-uri \'none\'; form-action \'none\'"><title>Private process reviews</title><style>{STYLE}</style><main><h1>Private process reviews</h1>',
             f'<p class="notice">{esc(NOTICE)}</p><p>Generated (UTC): {esc(stamp(clock()))} · Earliest expiry: {esc(manifest["expires_at"] or "none")}</p>',
             f'<p>Stored active runs: {len(active)} · Invalid/unavailable/duplicate records: {uncertain} · Expired records: {sum(e["state"] == "expired" for e in entries)}</p>']
    if uncertain:
        parts.append('<p class="notice">Latest result cannot be established: invalid, unavailable or duplicate records exist. Older valid records below are historical, not a substitute.</p>')
    if not active:
        parts.append('<p>No active saved details. Empty, expired, deleted and unavailable results do not prove safety.</p>')
    for entry in active:
        obj, rid = entry["record"], entry["record_id"]
        snap = obj["snapshot"]
        counts = Counter(p["identity"] for p in snap["processes"])
        parts.append(f'<a href="#record-{rid}">Review {esc(rid)}</a><details id="record-{rid}" class="panel"><summary>{esc(obj["finished_at"])} · {esc(snap["status"])} · {snap["reviewed_count"]}/{snap["target_count"]} targets</summary><p>Collected: {esc(obj["started_at"])} — {esc(obj["finished_at"])}; saved: {esc(obj["saved_at"])}; expires: {esc(entry["expires_at"])}</p><p>Identity states: {esc(dict(counts))}</p>')
        for row in snap["processes"]:
            # Preserve JSON formatter newlines while escaping every line's untrusted text.
            details = "\n".join(esc(line) for line in json.dumps(row["details"], ensure_ascii=False, indent=2).split("\n"))
            parts.append(f'<details><summary>{esc(row["label"])} · {esc(row["runtime"])} · {esc(LABELS[row["identity"]])} · {esc(LABELS[row["launch"]])}</summary><p>Unconfirmed/attention: {esc(", ".join(row["attention"]) or "No flagged attention; safety still unassessed")}</p><p>Owner-selected files are not proven loaded; dependency metadata is not proven resolution.</p><pre>{details}</pre></details>')
        parts.append(f'<p>Limitations: {esc(", ".join(snap["limitations"]))}</p></details>')
    return "".join(parts) + "</main></html>"


def manage(scanner, action, record_id=None, revision=None, show_details=False, dry_run=False):
    if scanner.via != "cli":
        raise core.ScannerError("Process review records are local CLI only")
    if action not in {"list", "delete", "prune", "dashboard"}:
        raise core.ScannerError("Invalid process review record operation")
    if action == "delete" and (not isinstance(record_id, str) or not ID.fullmatch(record_id)
                               or not isinstance(revision, str) or not REV.fullmatch(revision)):
        raise core.ScannerError("Use the exact record ID and revision from the local list")
    try:
        with Store(settings(scanner)).open() as store:
            if store is None:
                return core.result("process_review", "completed", data={"records": [], "store_exists": False})
            entries = store.inventory()
            store.validate_page(entries)
            if action == "delete":
                store.invalidate()
                store.unlink(record_id + ".json", revision)
                return core.result("process_review", "completed", data={"deleted": True, "record_id": record_id})
            if action == "prune":
                deleted, failed = (0, 0) if dry_run else store.prune(entries)
                temps, temp_failures = (0, 0) if dry_run else store.clean_temps()
                return core.result("process_review", "partial" if failed or temp_failures else "completed", data={
                    "expired_count": sum(e["state"] == "expired" for e in entries), "deleted_count": deleted,
                    "failed_count": failed + temp_failures, "temporary_files_removed": temps, "dry_run": dry_run})
            if action == "dashboard":
                _, failed = store.prune(entries)
                if failed:
                    raise OSError("Expiry cleanup incomplete")
                entries = store.inventory()
                manifest = store.manifest(entries)
                data = render(entries, manifest).encode("utf-8")
                store.invalidate()
                store.atomic("dashboard.json", encode(manifest), JSON_LIMIT)
                store.atomic("dashboard.html", data, HTML_LIMIT)
                uncertain = any(e["state"] in {"invalid", "unavailable", "duplicate"} for e in entries)
                return core.result("process_review", "partial" if uncertain else "completed", data={"page": str(store.path / "dashboard.html"),
                    "record_count": len(manifest["records"]), "latest_uncertain": uncertain, "private_page": True})
            rows = []
            for entry in sorted(entries, key=lambda e: (e.get("saved_at", ""), e["record_id"]), reverse=True):
                row = {k: v for k, v in entry.items() if k != "record"}
                if entry["state"] == "active":
                    snap = entry["record"]["snapshot"]
                    row.update(status=snap["status"], target_count=snap["target_count"], reviewed_count=snap["reviewed_count"])
                    if show_details:
                        row["details"] = snap
                rows.append(row)
            uncertain = any(e["state"] in {"invalid", "unavailable", "duplicate"} for e in entries)
            return core.result("process_review", "partial" if uncertain else "completed", data={
                "records": rows, "store_exists": True, "latest_uncertain": uncertain,
                "unmanaged_count": store.unmanaged()})
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise core.ScannerError("Process review store operation failed; check local permissions, limits and revision") from None
