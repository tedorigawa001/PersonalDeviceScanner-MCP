"""Restricted operations shared by the CLI and MCP server."""
from __future__ import annotations

import base64
import difflib
import http.client
import json
import locale
import math
import os
import platform
import re
import signal
import socket
import ssl
import stat
import subprocess
import threading
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (HTTPSHandler, HTTPRedirectHandler, ProxyHandler,
                            Request, build_opener)


class ScannerError(Exception):
    """Safe, user-facing operation failure."""


MAX_DIRECTORY_LEVELS = 16
PAGE_SIZE = 500
# Inventory offsets stay bounded; real inventories are far smaller.
MAX_OFFSET = 10000 - PAGE_SIZE
REPORT_LINES = 60
CANCEL_POLL_SECONDS = 0.1
REPORT_LINE_CHARS = 500
REPORTED_DIRECTORIES = 20
# stat defines this only on Windows; the value is fixed by the Windows SDK.
JUNCTION_TAG = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
FOUND = re.compile(r"(.+): (.+) FOUND")
# Characters that can hide or reorder text for a reader: C0/C1 controls, bidi controls,
# zero-width characters and the byte order mark.
HIDDEN_CHARACTERS = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
NAME_CHARS, PATH_CHARS = 256, 1024
# Sort values can be long package paths; cursors stay bounded for the AI's context.
SORT_VALUE_CHARS, CURSOR_CHARS = 4096, 65536
# Far beyond any agent's inventory (500 records a page); keeps the page number in cursors bounded.
MAX_PAGES = 1000000
SOURCES = {"status": "bridge", "inventory": "osquery", "malware": "clamav", "vulnerabilities": "wazuh",
           "android": "adb", "android_check": "adb", "router_check": "router", "router_products": "router"}

# Metadata only: opening placeholder contents can download them from the provider.
SF_DATALESS = 0x40000000
WINDOWS_RECALL_ATTRIBUTES = 0x1000 | 0x40000 | 0x400000
MAX_EXCLUSION_CHARS = 8000  # keep the engine command bounded, including on Windows
# clamscan matches an exclusion against the first 512 bytes (UTF-8) of a path (match_regex in
# ClamAV's common/misc.c), so a longer path would be read, and downloaded, despite its exclusion.
CLAMAV_MATCH_BYTES = 512


def cloud_placeholder(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        # Removed since the folder was listed, or its metadata cannot be read: ClamAV cannot open
        # it either, and reports what it could not scan.
        return False
    return (bool(getattr(info, "st_flags", 0) & SF_DATALESS)
            or bool(getattr(info, "st_file_attributes", 0) & WINDOWS_RECALL_ATTRIBUTES)
            # Legacy iCloud stores an unmaterialized file as .<name>.icloud.
            or (platform.system() == "Darwin" and path.name.startswith(".")
                and path.name.endswith(".icloud")))


def exclusion_pattern(path: str, directory: bool) -> str:
    """Literal path in ClamAV's POSIX extended regex, not a user-supplied regex."""
    escaped = re.sub(r'([\\.\[\]{}()*+?^$|])', r'\\\1', path)
    return "^" + escaped + (r"($|[/\\])" if directory else "$")


def is_link(path: Path) -> bool:
    """Symlink or Windows junction; scans never follow either."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or getattr(info, "st_reparse_tag", 0) == JUNCTION_TAG


def clean_text(value, limit: int | None = NAME_CHARS) -> str:
    """Untrusted text (file, app or package names) made safe to show to the AI or a terminal.

    Hidden characters are escaped as \\uXXXX, file-name bytes that are not UTF-8 as
    \\xNN, and the length is capped.
    """
    text = value if isinstance(value, str) else str(value)
    try:
        # surrogateescape restores undecodable file-name bytes; backslashreplace then shows them.
        text = text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    except UnicodeEncodeError:
        text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    text = HIDDEN_CHARACTERS.sub(lambda match: f"\\u{ord(match.group()):04x}", text)
    return text if limit is None or len(text) <= limit else text[:limit] + "...(truncated)"


def check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise ScannerError("Scan cancelled; scan was not completed")


def inspect_directories(target: Path, deadline: float,
                        cancel: threading.Event | None = None,
                        cloud_excluded: list[tuple[str, bool]] | None = None) -> tuple[bool, list[str], list[str]]:
    """Find directories ClamAV silently skips or cannot read, and names with line breaks,
    without following links.

    ClamAV counts the target directory as level 1. Stop at the last scanned
    level; only the presence of a real child directory is needed there.
    clamscan reports one line per file, so a line break in a name can make a
    detection read as if it named another file.
    """
    line_breaks = [str(target)] if "\n" in str(target) or "\r" in str(target) else []
    if cloud_excluded is not None and cloud_placeholder(target):
        cloud_excluded.append((str(target), target.is_dir()))
        return False, [], line_breaks
    if not target.is_dir():
        return False, [], line_breaks
    limit_reached, unreadable = False, []

    def record(error):
        unreadable.append(error.filename or str(target))

    for directory, children, files in os.walk(target, followlinks=False, onerror=record):
        check_cancel(cancel)
        if time.monotonic() >= deadline:
            raise ScannerError("Directory coverage check timed out; scan was not completed")
        line_breaks += [str(Path(directory) / name) for name in children + files if "\n" in name or "\r" in name]
        # os.walk only skips symlinks, so junctions must be pruned here.
        children[:] = [name for name in children if not is_link(Path(directory) / name)]
        if cloud_excluded is not None:
            retained = []
            for name in children:
                check_cancel(cancel)
                if cloud_placeholder(Path(directory) / name):
                    cloud_excluded.append((str(Path(directory) / name), True))
                else:
                    retained.append(name)
            children[:] = retained
            for name in files:
                check_cancel(cancel)
                entry = Path(directory) / name
                if not is_link(entry) and cloud_placeholder(entry):
                    cloud_excluded.append((str(entry), False))
        level = len(Path(directory).relative_to(target).parts) + 1
        if level >= MAX_DIRECTORY_LEVELS:
            limit_reached = limit_reached or bool(children)
            children.clear()
    return limit_reached, unreadable, line_breaks


def check_offset(offset) -> None:
    if type(offset) is not int or not 0 <= offset <= MAX_OFFSET:
        raise ScannerError(f"offset must be an integer 0..{MAX_OFFSET}")


def next_page(offset: int, returned: int, more: bool) -> tuple[int | None, list[str]]:
    if not more or not returned:
        return None, []
    if offset + returned > MAX_OFFSET:
        return None, ["Paging limit reached; remaining rows cannot be retrieved"]
    return offset + returned, [f"More rows exist; call again with offset={offset + returned}"]


# Most severe first, then every field Wazuh uses to identify a package (name, version,
# architecture, format, location) plus the CVE, so no two records of an agent tie and
# search_after can page past the 10000-result window without skipping any. Missing
# values sort as fixed numbers or strings, so cursors never carry null.
WAZUH_SORT = [{"vulnerability.score.base": {"order": "desc", "unmapped_type": "float", "missing": -1}}] + [
    {field: {"order": "asc", "unmapped_type": "keyword", "missing": ""}}
    for field in ("vulnerability.id", "package.name", "package.version", "package.architecture",
                  "package.type", "package.path")]


def decode_cursor(cursor) -> tuple[int, list | None]:
    """The page a cursor leads to and the sort values of the last record already returned.

    The cursor comes from the AI, so check it. The page number lets the owner's history tell a
    page fetched again from the next one, without keeping anything about the records.
    """
    if cursor == "":
        return 1, None
    if not isinstance(cursor, str) or len(cursor) > CURSOR_CHARS:
        raise ScannerError("Invalid cursor; pass data.next_cursor unchanged")
    try:
        values = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except ValueError:
        raise ScannerError("Invalid cursor; pass data.next_cursor unchanged") from None
    if not (isinstance(values, list) and len(values) == len(WAZUH_SORT) + 1
            and type(values[0]) is int and 2 <= values[0] <= MAX_PAGES
            # CVSS base scores are 0..10 and -1 marks a missing score. Comparing, unlike
            # float conversion, cannot overflow on huge integers, and it rejects NaN and infinity.
            and type(values[1]) in (int, float) and -1 <= values[1] <= 10
            and all(isinstance(v, str) and len(v) <= SORT_VALUE_CHARS for v in values[2:])):
        raise ScannerError("Invalid cursor; pass data.next_cursor unchanged")
    return values[0], values[1:]


def encode_cursor(page: int, values: list) -> str | None:
    """A cursor to `page`, after the record with these sort values; None when it cannot be carried.

    UTF-8 rather than JSON escapes keeps non-ASCII package names compact. Values of the
    wrong shape raise ValueError, since they mean an unexpected index schema.
    """
    if not isinstance(values, list):
        raise ValueError("unexpected sort values")
    if page > MAX_PAGES or any(isinstance(v, str) and len(v) > SORT_VALUE_CHARS for v in values):
        return None
    text = json.dumps([page, *values], ensure_ascii=False, separators=(",", ":"))
    cursor = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    if len(cursor) > CURSOR_CHARS:
        return None
    try:
        decode_cursor(cursor)  # never hand out a cursor that would be refused
    except ScannerError:
        raise ValueError("unexpected sort values") from None
    return cursor


def excerpt(text: str) -> tuple[str, bool]:
    """Keep engine text small enough for an AI context; head and tail carry errors and summary."""
    rows, cut = [], False
    for row in text.splitlines():
        row = clean_text(row, None)
        if len(row) > REPORT_LINE_CHARS:
            # Long paths come first and the error reason last, so keep both ends.
            half = REPORT_LINE_CHARS // 2
            row, cut = f"{row[:half]} ... {row[-half:]}", True
        rows.append(row)
    if len(rows) <= REPORT_LINES:
        return "\n".join(rows), cut
    half = REPORT_LINES // 2
    omitted = f"... {len(rows) - 2 * half} lines omitted ..."
    return "\n".join(rows[:half] + [omitted] + rows[-half:]), True


# Settings each section understands; None means free-form keys (scan root aliases).
SETTINGS = {"local": {"osquery_binary", "clamav_binary", "timeout_seconds", "max_output_bytes",
                      "max_signature_age_days"},
            "scan_roots": None,
            "wazuh": {"url", "agent_id", "ca_file", "agent_name"},
            "android": {"adb_binary", "indicators_file", "max_indicator_age_days", "max_patch_age_days"},
            "android_devices": None,
            "history": {"enabled", "file", "details", "details_max_mb"},
            "router": {"jvn_lookup", "kev_file", "max_kev_age_days", "max_check_age_days"},
            "routers": None,
            "updates": {"lookup"}}


def unknown_settings(config: dict) -> list[str]:
    """Warn about settings that would otherwise be ignored silently, such as a misspelt section."""
    everywhere = [*SETTINGS, *(f"{section}.{key}" for section, keys in SETTINGS.items() for key in keys or ())]
    warnings = []

    def warn(name, hint):
        warnings.append(f"Unknown setting {name[:80]!r} is ignored" + (f"; {hint}" if hint else ""))

    def did_you_mean(word, candidates, prefix=""):
        guess = difflib.get_close_matches(word, candidates, n=1)
        return f"did you mean {prefix + guess[0]!r}?" if guess else None

    for section in config:
        if section not in SETTINGS:
            # A key outside its section is a likely slip too, so every known name is a candidate.
            warn(section, did_you_mean(section, everywhere))
    for section, keys in SETTINGS.items():
        for key in config.get(section, {}) if keys is not None else ():
            if key in keys:
                continue
            if section == "wazuh" and key in {"user", "username", "password"}:
                warn(f"{section}.{key}", "Wazuh credentials are read only from PC_SCANNER_WAZUH_USER and "
                                         "PC_SCANNER_WAZUH_PASSWORD; remove them from the file")
            else:
                # Only the section's own keys: the shared prefix would make anything look close.
                warn(f"{section}.{key}", did_you_mean(key, sorted(keys), f"{section}."))
    return warnings


def result(source: str, status: str, **fields) -> dict:
    return {"schema_version": 1, "source": source, "status": status,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "findings": [], "warnings": [], **fields}


class NoRedirect(HTTPRedirectHandler):
    def __init__(self, service: str = "Wazuh"):
        super().__init__()
        self.service = service

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.service == "Wazuh":
            raise ScannerError("Wazuh redirect rejected; configure the final HTTPS origin")
        raise ScannerError(f"{self.service} redirect rejected")


class TrackedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, sockets: list[socket.socket], **kwargs):
        super().__init__(*args, **kwargs)
        self.sockets = sockets

    def connect(self) -> None:
        super().connect()
        self.sockets.append(self.sock)


class TrackedHTTPSHandler(HTTPSHandler):
    """Keeps the sockets it opens, so a request that was given up on can be cut off.

    The socket itself is kept: once the headers are in, urllib drops the connection's
    reference to it, while the response goes on reading the body from it.
    """

    def __init__(self, context: ssl.SSLContext):
        super().__init__(context=context)
        self.context = context
        self.sockets: list[socket.socket] = []

    def https_open(self, req):
        return self.do_open(TrackedHTTPSConnection, req, context=self.context, sockets=self.sockets)

    def cut_off(self) -> None:
        for sock in self.sockets:
            try:
                # The plain socket call: wakes a read blocked in another thread without
                # touching the TLS state that thread is using. Windows does not wake it, so
                # there the abandoned request ends when data arrives or at its socket timeout;
                # closing the handle under it instead could let it read a reused handle.
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass  # already closed


def fetch_bounded(opener, handler: TrackedHTTPSHandler, request: Request, budget: int, limit: int,
                  cancel: threading.Event | None = None, service: str = "Wazuh") -> bytes:
    """Read the whole answer within budget seconds, stopping promptly on cancel.

    A blocking read cannot be interrupted, and each byte that arrives restarts the socket
    timeout, so a slow server could hold the read far past the budget. The request runs in
    a helper thread instead; this thread keeps the deadline and cuts the connection off.
    """
    deadline = time.monotonic() + budget
    done, abandoned, outcome = threading.Event(), threading.Event(), {}

    def fetch() -> None:
        try:
            # A little longer than the budget, so the deadline below decides when to give up and
            # what to report; the socket timeout only ends a cut-off request Windows does not wake.
            with opener.open(request, timeout=budget + 1) as response:
                raw = bytearray()
                # read1 returns what has arrived instead of waiting for a full block.
                while not abandoned.is_set() and (chunk := response.read1(65536)):
                    raw += chunk
                    if len(raw) > limit:
                        raise ScannerError(f"{service} response exceeded size limit")
            outcome["body"] = bytes(raw)
        except Exception as exc:  # handed over to the caller
            outcome["error"] = exc
        finally:
            done.set()

    threading.Thread(target=fetch, name=f"{service.lower()}-request", daemon=True).start()
    while not done.wait(max(0.0, min(CANCEL_POLL_SECONDS, deadline - time.monotonic()))):
        if (cancel is not None and cancel.is_set()) or time.monotonic() >= deadline:
            abandoned.set()
            handler.cut_off()
            check_cancel(cancel)
            raise ScannerError(f"{service} did not finish answering within {budget} seconds; search was not completed")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["body"]


def decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Windows engines may print paths in the ANSI code page (cp932 on Japanese Windows).
        return data.decode(locale.getpreferredencoding(False) or "utf-8", errors="replace")


MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
DATABASE_STAMP = re.compile(r"/(\d+)/\w{3} (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})")


def clamav_signatures(binary: str, deadline: float, limit: int,
                      cancel: threading.Event | None = None) -> dict:
    """Engine version and newest daily signature database from `clamscan --version`.

    clamscan prints "ClamAV <engine>/<daily version>/<build time>", the time in
    local ctime() format, or only "ClamAV <engine>" when no daily database exists.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ScannerError("Time budget used before the signature check; scan was not completed")
    code, output, _ = run_bounded([binary, "--version"], min(remaining, 30), limit, cancel=cancel)
    info = {"engine": None, "version": None, "built_at": None}
    engine = re.match(r"ClamAV ([^/\s]+)", output) if code == 0 else None
    if not engine:
        return info
    info["engine"] = engine.group(1)
    database = DATABASE_STAMP.match(output, engine.end())
    if not database or database.group(2) not in MONTHS:
        return info
    version, month, day, hour, minute, second, year = database.groups()
    try:
        built = datetime(int(year), MONTHS.index(month) + 1, int(day), int(hour), int(minute), int(second))
    except ValueError:
        return info
    # astimezone() reads the naive ctime() value as local time, as clamscan printed it.
    info.update(version=int(version), built_at=built.astimezone(timezone.utc))
    return info


def windows_job(pid: int):
    """Put a process in a new job object; None if Windows refuses.

    Its descendants join the job automatically, and closing the job handle kills
    them all, even if this process dies first. A child started in the moment
    before assignment would escape, but engines do not start children that early.
    """
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    limits.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    process = kernel32.OpenProcess(0x0101, False, pid)  # PROCESS_SET_QUOTA | PROCESS_TERMINATE
    assigned = bool(process) and kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(limits), ctypes.sizeof(limits)) and kernel32.AssignProcessToJobObject(job, process)
    if process:
        kernel32.CloseHandle(process)
    if not assigned:
        kernel32.CloseHandle(job)
        return None
    return SimpleNamespace(stop=lambda: kernel32.TerminateJobObject(job, 1),
                           close=lambda: kernel32.CloseHandle(job))


# Engines running now, so a server asked to terminate can stop them. Reentrant locks:
# the SIGTERM handler may run on a thread that is already inside one of these blocks.
LIVE_TREES: set = set()
LIVE_TREES_LOCK = threading.RLock()


class ProcessTree:
    """An engine and every process it starts, stopped together.

    POSIX: the engine leads its own process group. Windows: it is placed in a job
    object; if that is refused, only the engine itself can be stopped.
    """

    def __init__(self, process: subprocess.Popen):
        self.process = process
        self.lock = threading.RLock()
        self.closed = False
        self.job = windows_job(process.pid) if os.name == "nt" else None
        with LIVE_TREES_LOCK:
            LIVE_TREES.add(self)

    def stop(self) -> None:
        with self.lock:
            if self.closed:
                return
            if self.job:
                self.job.stop()
            elif os.name != "nt":
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # macOS answers EPERM when the group holds only the exited, not yet
                    # reaped engine; the engine itself is handled below.
                    pass
            if self.process.poll() is None:
                self.process.kill()

    def close(self) -> None:
        with self.lock:
            self.closed = True
            if self.job:
                self.job.close()
        with LIVE_TREES_LOCK:
            LIVE_TREES.discard(self)


def stop_all_engines() -> None:
    with LIVE_TREES_LOCK:
        trees = list(LIVE_TREES)
    for tree in trees:
        tree.stop()


def stop_engines_on_terminate() -> None:
    """Stop running engines when this process receives SIGTERM, then terminate as before.

    Engines lead their own process groups, so a signal sent to this process alone would
    leave them running. SIGKILL cannot be caught; Windows jobs already end with the process.
    """
    if os.name == "nt" or threading.current_thread() is not threading.main_thread():
        return
    previous = signal.getsignal(signal.SIGTERM)
    if previous == signal.SIG_IGN:
        return

    def terminate(signum, frame):
        stop_all_engines()
        if callable(previous):
            previous(signum, frame)
        else:
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)

    signal.signal(signal.SIGTERM, terminate)


def engine_argument(text: str) -> str:
    """Untrusted text (a scan target path) to put on an engine command line.

    Windows hands an ANSI program its command line converted to the system code page
    with best-fit mapping, so a character such as U+FF02 (fullwidth quotation mark)
    can turn into '"' and split the path into extra options (--remove, --log=...).
    Strict "mbcs" encoding refuses anything the code page cannot represent exactly.
    """
    if os.name == "nt":
        try:
            text.encode("mbcs")
        except UnicodeEncodeError:
            raise ScannerError("The scan target's name cannot be passed safely to the engine on this system; "
                               "scan its parent folder or rename it") from None
    return text


def engine_environment() -> dict:
    # Never inherit cloud/API credentials into third-party engines; only locations.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "HOME",
               "SYSTEMDRIVE", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "PROGRAMDATA",
               "PROGRAMFILES", "LOCALAPPDATA", "APPDATA", "TZ"}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update({"LC_ALL": "C", "LANG": "C"})
    return env


def run_bounded(argv: list[str], timeout: float, limit: int,
                cancel: threading.Event | None = None) -> tuple[int, str, str]:
    check_cancel(cancel)
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, env=engine_environment(),
                                   start_new_session=os.name != "nt")
    except OSError:
        raise ScannerError("Configured engine could not be started") from None
    tree = ProcessTree(process)
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
                        tree.stop()
                        break
        finally:
            stream.close()

    threads = [threading.Thread(target=drain, args=(stream, i), daemon=True)
               for i, stream in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.start()
    # Wait in short slices so a cancel request stops the engine promptly.
    deadline = time.monotonic() + timeout
    stopped = None
    try:
        while stopped is None:
            try:
                process.wait(timeout=CANCEL_POLL_SECONDS)
                break
            except subprocess.TimeoutExpired:
                if cancel is not None and cancel.is_set():
                    stopped = "Scan cancelled; engine stopped before completing"
                elif time.monotonic() >= deadline:
                    stopped = "Engine timed out; scan was not completed"
    finally:
        # Also after a normal exit or an unexpected error such as Ctrl+C: stop the
        # engine if it still runs and anything it left behind.
        tree.stop()
        process.wait()
        tree.close()
    for thread in threads:
        thread.join(timeout=2)
    if stopped:
        raise ScannerError(stopped)
    if exceeded.is_set():
        raise ScannerError("Engine output exceeded limits; scan was not completed")
    if any(t.is_alive() for t in threads):
        raise ScannerError("Engine output stayed open after exit; a child process that left the engine's "
                           "process group may still be running")
    return process.returncode, *(decode(bytes(b)) for b in buffers)


class Scanner:
    def __init__(self, config: dict):
        if not isinstance(config, dict):
            raise ScannerError("Configuration must be a table")
        self.config = config
        self.local = config.get("local", {})
        self.roots = config.get("scan_roots", {})
        self.wazuh = config.get("wazuh", {})
        self.android = config.get("android", {})
        self.android_devices = config.get("android_devices", {})
        self.history_settings = config.get("history", {})
        self.update_settings = config.get("updates", {})
        if not all(isinstance(v, dict) for v in (self.local, self.roots, self.wazuh, self.android,
                                                  self.android_devices, self.history_settings,
                                                  self.update_settings)):
            raise ScannerError("Configuration sections must be tables")
        self.config_warnings = unknown_settings(config)
        self.timeout = self.local.get("timeout_seconds", 600)
        self.limit = self.local.get("max_output_bytes", 1048576)
        if type(self.timeout) is not int or not 1 <= self.timeout <= 3600:
            raise ScannerError("timeout_seconds must be 1..3600")
        if type(self.limit) is not int or not 1024 <= self.limit <= 8388608:
            raise ScannerError("max_output_bytes must be 1024..8388608")
        # ClamAV itself warns once its database is older than 7 days.
        self.max_signature_age = self.local.get("max_signature_age_days", 7)
        if type(self.max_signature_age) is not int or not 1 <= self.max_signature_age <= 365:
            raise ScannerError("max_signature_age_days must be 1..365")
        for key in ("osquery_binary", "clamav_binary"):
            value = self.local.get(key, "")
            if not isinstance(value, str) or (value and not Path(value).is_absolute()):
                raise ScannerError("Engine paths must be absolute strings")
        for alias, value in self.roots.items():
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", alias):
                raise ScannerError("Invalid scan root alias")
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise ScannerError("Scan roots must be absolute paths")
        for key in ("url", "agent_id", "ca_file", "agent_name"):
            if not isinstance(self.wazuh.get(key, ""), str):
                raise ScannerError("Wazuh settings must be strings")
        for key in ("adb_binary", "indicators_file"):
            value = self.android.get(key, "")
            if not isinstance(value, str) or (value and not Path(value).is_absolute()):
                raise ScannerError("Android paths must be absolute strings")
        self.max_indicator_age = self.android.get("max_indicator_age_days", 30)
        if type(self.max_indicator_age) is not int or not 1 <= self.max_indicator_age <= 365:
            raise ScannerError("max_indicator_age_days must be 1..365")
        self.max_patch_age = self.android.get("max_patch_age_days", 90)
        if type(self.max_patch_age) is not int or not 1 <= self.max_patch_age <= 3650:
            raise ScannerError("max_patch_age_days must be 1..3650")
        for alias, serial in self.android_devices.items():
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", alias):
                raise ScannerError("Invalid Android device alias")
            # Printable ASCII without spaces, as adb prints serials; the connection type is
            # checked when the device is used, never inferred from the serial.
            if not isinstance(serial, str) or not re.fullmatch(r"[\x21-\x7e]{1,128}", serial):
                raise ScannerError("Android device serials must be printable text without spaces")
        self.history_enabled = self.history_settings.get("enabled", True)
        if type(self.history_enabled) is not bool:
            raise ScannerError("history.enabled must be true or false")
        self.history_file = self.history_settings.get("file", "")
        if not isinstance(self.history_file, str) or (self.history_file
                                                      and not Path(self.history_file).is_absolute()):
            raise ScannerError("History file must be an absolute path")
        self.history_details = self.history_settings.get("details", False)
        if type(self.history_details) is not bool:
            raise ScannerError("history.details must be true or false")
        self.history_details_mb = self.history_settings.get("details_max_mb", 50)
        if type(self.history_details_mb) is not int or not 1 <= self.history_details_mb <= 1024:
            raise ScannerError("history.details_max_mb must be 1..1024")
        if self.history_details and not self.history_enabled:
            self.config_warnings.append("history.details has no effect while history.enabled = false")
        # Off unless the owner turns it on: the lookup reaches GitHub and Google.
        self.update_lookup = self.update_settings.get("lookup", False)
        if type(self.update_lookup) is not bool:
            raise ScannerError("updates.lookup must be true or false")
        # Latest releases this process looked up, for when they cannot be saved beside the history.
        self.release_info: dict = {}
        from . import router
        self.router_settings, self.routers, router_warnings = router.load(config)
        self.config_warnings += router_warnings
        # Set by the CLI ("cli") or the MCP server ("mcp"); scans are recorded only then.
        self.via = None
        ca_file = self.wazuh.get("ca_file", "")
        if ca_file and not Path(ca_file).is_absolute():
            raise ScannerError("Wazuh ca_file must be an absolute path")
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
            # Only a warning: a missing CA file must not stop the local engines from working.
            if ca_file and not Path(ca_file).is_file():
                self.config_warnings.append(f"Wazuh ca_file not found ({Path(ca_file).name}); "
                                            "Wazuh requests will fail until it exists")

    @classmethod
    def load(cls, path: str):
        try:
            with open(path, "rb") as f:
                return cls(tomllib.load(f))
        except (OSError, ValueError):
            raise ScannerError("Cannot read valid TOML configuration") from None

    def history_path(self) -> Path:
        from . import history
        if self.history_file:
            return Path(self.history_file)
        try:
            return history.default_file()
        except RuntimeError:
            raise ScannerError("Cannot find the home folder; set history.file") from None

    def binary(self, key: str, section: dict | None = None) -> str:
        value = (self.local if section is None else section).get(key, "")
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
            "android_configured": bool(self.android.get("adb_binary")),
            "scan_root_aliases": list(self.roots),
            "android_device_aliases": list(self.android_devices),
            "router_aliases": list(self.routers),
            "router_jvn_lookup": self.router_settings["jvn_lookup"],
            "router_kev_configured": bool(self.router_settings["kev_file"]),
            "update_lookup": self.update_lookup,
            "note": "Configuration status only; engines, signatures, connectivity and PC safety are unverified"})

    def inventory(self, query_id: str, offset: int = 0, cancel: threading.Event | None = None) -> dict:
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
        # Names come from whatever is installed, so only known columns pass, as cleaned text.
        columns = {"os_version": ("name", "version", "major", "minor", "patch", "platform"),
                   "listening_ports": ("pid", "process", "address", "port", "protocol", "family"),
                   "applications": ("name", "version", "bundle_short_version")}[query_id]
        code, output, diagnostic = run_bounded(
            # Official macOS osqueryi resolves to osqueryd; force shell mode.
            [self.binary("osquery_binary"), "-S", "--json", "--disable_extensions=true",
             f"{query} LIMIT {PAGE_SIZE + 1} OFFSET {offset};"],
            self.timeout, self.limit, cancel=cancel)
        if code != 0:
            raise ScannerError("osquery failed; table may be unsupported or permission denied")
        try:
            rows = json.loads(output)
        except ValueError:
            raise ScannerError("osquery returned invalid JSON") from None
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise ScannerError("Unexpected osquery result schema")
        page = [{key: clean_text(row[key]) for key in columns if key in row} for row in rows[:PAGE_SIZE]]
        next_offset, page_warnings = next_page(offset, len(page), len(rows) > PAGE_SIZE)
        partial = len(rows) > PAGE_SIZE or offset > 0 or bool(diagnostic.strip()) or not rows
        return result("osquery", "partial" if partial else "completed",
                      data={"query_id": query_id, "offset": offset, "next_offset": next_offset, "rows": page},
                      warnings=["Inventory only; this does not confirm vulnerabilities or malware"]
                      + (["Standard-user runs may omit sockets owned by other users or the system"]
                         if query_id == "listening_ports" else [])
                      + page_warnings
                      + (["One page, engine warning, or no observable rows; coverage incomplete"] if partial else []))

    def malware(self, root_alias: str, relative_path: str = ".",
                cancel: threading.Event | None = None) -> dict:
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

        def shown(path: str) -> str:
            # Paths relative to the alias, so owner paths are not passed onward.
            try:
                return clean_text(Path(path).relative_to(root).as_posix(), PATH_CHARS)
            except ValueError:
                return clean_text(Path(path).name, PATH_CHARS)

        def attributed(location: str) -> str | None:
            # Only an existing file inside the root counts; a line break in a name can turn
            # the text before ": <signature> FOUND" into a fragment naming another file.
            path = Path(location)
            if line_breaks or not (path.is_absolute() and path.is_relative_to(root) and os.path.lexists(path)):
                return None
            return shown(location)

        def mask(text: str) -> str:
            return text.replace(str(root), f"<{root_alias}>")

        # A missing engine is a configuration error, reported before any folder is walked.
        binary = self.binary("clamav_binary")
        # Signature check, coverage check and engine share one time budget.
        deadline = time.monotonic() + self.timeout
        check_cancel(cancel)
        cloud_excluded: list[tuple[str, bool]] = []
        directory_limit, unreadable, line_breaks = inspect_directories(target, deadline, cancel, cloud_excluded)
        exclusions = [("--exclude-dir=" if directory else "--exclude=") + exclusion_pattern(path, directory)
                      for path, directory in cloud_excluded]
        unsafe_exclusions = False
        try:
            exclusions = [engine_argument(option) for option in exclusions]
        except ScannerError:
            unsafe_exclusions = True
        cloud_paths = [shown(path) for path, _ in cloud_excluded[:REPORTED_DIRECTORIES]]
        cloud_warnings = ([f"{len(cloud_excluded)} cloud placeholder files or directories were excluded to avoid "
                           "downloading their contents; scan coverage is incomplete"] if cloud_excluded else [])
        target_excluded = any(path == str(target) for path, _ in cloud_excluded)
        exclusion_overflow = sum(len(option) for option in exclusions) > MAX_EXCLUSION_CHARS
        too_long = sum(len(os.fsencode(path)) > CLAMAV_MATCH_BYTES for path, _ in cloud_excluded)
        if target_excluded or exclusion_overflow or unsafe_exclusions or too_long:
            return result("clamav", "partial", data={
                "root_alias": root_alias, "relative_path": clean_text(relative_path, PATH_CHARS),
                "exit_code": None, "scan_started": False,
                "cloud_excluded_count": len(cloud_excluded), "cloud_excluded_paths": cloud_paths},
                warnings=cloud_warnings + (["Cloud exclusions cannot be passed safely to the engine; no scan was started. "
                                            "Select a smaller local folder"] if unsafe_exclusions else [])
                + (["Cloud exclusions exceed the command-size limit; no scan was started. "
                                            "Select a smaller local folder"] if exclusion_overflow else [])
                + ([f"{too_long} cloud placeholders have paths longer than ClamAV can match for exclusion "
                    f"({CLAMAV_MATCH_BYTES} bytes); no scan was started, so they are not downloaded. "
                    "Shorten the folder names or scan a folder without them"] if too_long else []))
        signatures = clamav_signatures(binary, deadline, self.limit, cancel=cancel)
        age_seconds = age_days = None
        if signatures["built_at"]:
            age_seconds = (datetime.now(timezone.utc) - signatures["built_at"]).total_seconds()
            # Decide on the exact age; show it rounded up to 0.1 day so a shown value
            # never sits at or under the limit while the age is over it.
            age_days = math.ceil(age_seconds / 8640) / 10
        signature_warnings = (
            ["Signature database date could not be determined; run freshclam and check the database directory"]
            if age_seconds is None else
            [f"Signatures are {age_days} days old (limit {self.max_signature_age} days); update them with freshclam"]
            if age_seconds > self.max_signature_age * 86400 else [])
        target_argument = engine_argument(str(target))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ScannerError("Directory coverage check used the time budget; scan was not completed")
        code, output, diagnostic = run_bounded([
            binary, "--recursive=yes", "--infected",
            "--follow-dir-symlinks=0", "--follow-file-symlinks=0",
            f"--max-dir-recursion={MAX_DIRECTORY_LEVELS}",
            "--max-filesize=100M", "--max-scansize=200M", "--max-recursion=16",
            # The target stays last, so a mis-parsed quote cannot place options after it.
            "--alert-exceeds-max=yes", *exclusions, target_argument], remaining, self.limit, cancel=cancel)
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
                             "path": attributed(location), "signature": clean_text(signature)})
        findings.sort(key=lambda f: f["kind"] != "malware")
        findings_capped = len(findings) > PAGE_SIZE
        engine_report, report_truncated = excerpt(mask("\n".join(messages)))
        engine_diagnostic, diagnostic_truncated = excerpt(mask(diagnostic))

        def summary(label: str) -> int | None:
            match = re.search(rf"^{label}:\s*(\d+)\s*$", output, re.MULTILINE)
            return int(match.group(1)) if match else None

        # The summary is the engine's own account; detections read from the report must match it.
        scanned, infected, errors = summary("Scanned files"), summary("Infected files"), summary("Total errors") or 0
        detections = sum(f["kind"] == "malware" for f in findings)
        unattributed = sum(f["path"] is None for f in findings)
        miscounted = infected != detections
        partial = (bool(cloud_excluded) or directory_limit or bool(unreadable) or findings_capped or bool(signature_warnings)
                   or bool(line_breaks) or bool(unattributed) or miscounted or errors > 0
                   or code not in (0, 1) or bool(diagnostic.strip()) or "ERROR" in output
                   or not scanned
                   or any(f["kind"] == "scan_limit" for f in findings)
                   or (code == 1 and not findings))
        return result("clamav", "partial" if partial else "completed", findings=findings[:PAGE_SIZE],
                      data={"root_alias": root_alias, "relative_path": clean_text(relative_path, PATH_CHARS),
                            "exit_code": code, "findings_total": len(findings),
                            "engine_counts": {"scanned": scanned, "infected": infected, "errors": errors},
                            "unreadable_directories": [shown(p) for p in unreadable[:REPORTED_DIRECTORIES]],
                            "cloud_excluded_count": len(cloud_excluded), "cloud_excluded_paths": cloud_paths,
                            "line_break_names": [shown(p) for p in line_breaks[:REPORTED_DIRECTORIES]],
                            "engine_report": engine_report, "diagnostic": engine_diagnostic,
                            "engine_text_truncated": report_truncated or diagnostic_truncated,
                            "signatures": {"engine": signatures["engine"], "version": signatures["version"],
                                           "built_at": signatures["built_at"] and signatures["built_at"].isoformat(),
                                           "age_days": age_days, "max_age_days": self.max_signature_age}},
                      warnings=["Signature-based detection only; no detection does not prove safety",
                                "Symlinks excluded; file/archive limits apply"]
                      + signature_warnings
                      + cloud_warnings
                      + (["Directory depth limit reached; deeper directories were not scanned"] if directory_limit else [])
                      + ([f"{len(unreadable)} directories could not be read and were not scanned"] if unreadable else [])
                      + ([f"The engine reported {errors} errors; some files were not scanned"] if errors else [])
                      + ([f"{len(line_breaks)} names contain line breaks, so detections cannot be matched to files; "
                          "see data.line_break_names"] if line_breaks else
                         [f"{unattributed} detections could not be matched to a file in the scanned folder"]
                         if unattributed else [])
                      + ([f"The engine counted {infected} infected files but {detections} detections were read; "
                          "the report may be incomplete"] if miscounted else [])
                      + ([f"Findings capped at {PAGE_SIZE}; malware findings are listed first"] if findings_capped else [])
                      + (["Scan coverage incomplete or engine error; do not report this PC as safe"] if partial else []))

    def vulnerabilities(self, cursor: str = "", cancel: threading.Event | None = None) -> dict:
        page, search_after = decode_cursor(cursor)
        origin = self.wazuh.get("url", "")
        if not origin:
            raise ScannerError("Wazuh indexer is not configured")
        user = os.environ.get("PC_SCANNER_WAZUH_USER", "")
        password = os.environ.get("PC_SCANNER_WAZUH_PASSWORD", "")
        if not user or not password or ":" in user:
            raise ScannerError("Valid Wazuh credentials must be set in environment variables")
        # One extra record shows whether another page follows.
        body = {"size": PAGE_SIZE + 1, "track_total_hits": True,
                "query": {"term": {"agent.id": self.agent_id}}, "sort": WAZUH_SORT,
                **({"search_after": search_after} if search_after else {}),
                "_source": ["agent.id", "agent.name", "host.os.full", "package.name", "package.version", "vulnerability.id",
                            "vulnerability.severity", "vulnerability.score.base",
                            "vulnerability.detected_at"]}
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        request = Request(origin.rstrip("/") + "/wazuh-states-vulnerabilities-*/_search",
                          data=json.dumps(body).encode(), method="GET",
                          headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"})
        ca_file = self.wazuh.get("ca_file", "")
        if ca_file and not Path(ca_file).is_file():
            raise ScannerError("Wazuh ca_file cannot be read; check the path and permissions")
        try:
            context = ssl.create_default_context(cafile=ca_file or None)
        except ssl.SSLError:
            raise ScannerError("Wazuh ca_file is not a valid PEM CA certificate") from None
        except OSError:
            raise ScannerError("Wazuh ca_file cannot be read; check the path and permissions") from None
        if ca_file:
            # Python 3.13 made the strict RFC 5280 checks the default, and the CA that Wazuh's own certificate
            # tool makes has no key usage extension. The owner chose this CA, so the chain, its dates and the
            # host name are still verified, as before 3.13; the system certificates keep the strict checks.
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        handler = TrackedHTTPSHandler(context)
        opener = build_opener(ProxyHandler({}), handler, NoRedirect())
        check_cancel(cancel)
        try:
            payload = json.loads(fetch_bounded(opener, handler, request, min(self.timeout, 30), self.limit, cancel))
        except HTTPError as exc:
            raise ScannerError(f"Wazuh HTTP error {exc.code}; access or index may be unavailable") from None
        except (URLError, TimeoutError, OSError) as exc:
            reason = exc.reason if isinstance(exc, URLError) else exc
            if isinstance(reason, ssl.SSLCertVerificationError):
                # OpenSSL's own words, such as "Hostname mismatch" or "unable to get local issuer certificate".
                why = clean_text(reason.verify_message or reason.reason or "unknown reason", 200)
                raise ScannerError(f"Wazuh TLS certificate verification failed ({why}); check wazuh.ca_file "
                                   "and the host name in wazuh.url") from None
            raise ScannerError("Wazuh connection or TLS verification failed") from None
        except http.client.HTTPException:
            # Truncated bodies, malformed status or header lines: not OSError subclasses.
            raise ScannerError("Wazuh response could not be read; the connection may have been cut") from None
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
            findings, names, systems = [], set(), set()
            for hit in hits[:PAGE_SIZE]:
                source = hit["_source"]
                if source["agent"]["id"] != self.agent_id:
                    raise ScannerError("Wazuh returned data for an unauthorized agent")
                name = source["agent"].get("name")
                names.add(clean_text(name, 128) if isinstance(name, str) and name.strip() else None)
                system = source.get("host", {}).get("os", {}).get("full")
                if isinstance(system, str):
                    systems.add(clean_text(system, 128))
                # Index data is untrusted too: fixed fields, checked types, cleaned text.
                vulnerability, package = source["vulnerability"], source.get("package", {})
                if not isinstance(vulnerability["id"], str) or not isinstance(package, dict):
                    raise ValueError()
                severity = str(vulnerability.get("severity", "unknown")).lower()
                score = vulnerability.get("score")
                base = score.get("base") if isinstance(score, dict) else None
                detected_at = vulnerability.get("detected_at")
                findings.append({"kind": "vulnerability", "id": clean_text(vulnerability["id"], 128),
                                 "severity": severity if severity in {"critical", "high", "medium", "low"} else "unknown",
                                 "score": base if type(base) in (int, float) and 0 <= base <= 10 else None,
                                 "package": {key: clean_text(package[key]) for key in ("name", "version") if key in package},
                                 "detected_at": clean_text(detected_at, 64) if isinstance(detected_at, str) else None})
            more = len(hits) > PAGE_SIZE
            next_cursor = encode_cursor(page + 1, hits[PAGE_SIZE - 1]["sort"]) if more else None
            stuck = more and next_cursor is None
            incomplete = (relation != "eq" or search_after is not None or more or len(findings) != total_value
                          or payload.get("timed_out", False)
                          or payload.get("_shards", {}).get("failed", 0) > 0)
            no_records = total_value == 0
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ScannerError("Unexpected Wazuh vulnerability result schema") from None
        identity, expected = self.device_identity(names)
        known_names = sorted(n for n in names if n)
        identity_warnings = (
            [f"Wazuh agent {self.agent_id} is named {', '.join(known_names)}, but this PC is {expected}; "
             "the results may belong to another device"] if identity == "mismatch" else
            ["The agent name is missing from the index; device identity could not be verified"]
            if identity == "unknown" and names else [])
        return result("wazuh", "partial" if incomplete or no_records or identity != "matched" else "completed",
                      findings=findings,
                      data={"agent_id": self.agent_id, "total": total_value, "continued": search_after is not None,
                            "next_cursor": next_cursor, "freshness": "unverified", "live_scan_triggered": False,
                            "device": {"identity": identity, "expected_name": expected,
                                       "agent_names": known_names, "os": sorted(systems)}},
                      warnings=["Existing index inventory; the index records no scan time, so freshness cannot be verified",
                                "Zero findings can mean no inventory; this is not a safety verdict"]
                      + identity_warnings
                      + (["No vulnerability records for this agent_id; it may be wrong, unregistered or never scanned"]
                         if no_records else [])
                      + (["More results exist, but a sort value of the last record is too long to continue from; "
                          "later pages cannot be requested"] if stuck else
                         ["More results exist; call again with cursor set to data.next_cursor"] if more else [])
                      + (["One page of results or index search incomplete"] if incomplete else []))

    def device_identity(self, names: set) -> tuple[str, str]:
        """Compare the agent names in the index with this PC: matched, mismatch or unknown.

        A configured agent_name must match exactly (ignoring case). Otherwise the
        host name is compared without its domain, as Wazuh names agents after it.
        """
        configured = self.wazuh.get("agent_name", "").strip()
        expected = clean_text(configured or socket.gethostname(), 128)
        if not names or None in names:
            return "unknown", expected
        if configured:
            same = {name.lower() for name in names} == {configured.lower()}
        else:
            def short(name):
                return name.strip().lower().split(".")[0]
            same = {short(name) for name in names} == {short(expected)}
        return ("matched" if same else "mismatch"), expected

    def android_collect(self, device_alias: str, query_id: str, cancel: threading.Event | None = None) -> dict:
        from . import android
        return android.collect(self, device_alias, query_id, cancel)

    def android_check(self, device_alias: str, cancel: threading.Event | None = None) -> dict:
        from . import android
        return android.check(self, device_alias, cancel)

    def router_check(self, router_alias: str, cancel: threading.Event | None = None) -> dict:
        from . import router
        return router.check(self, router_alias, cancel)

    def router_products(self, maker: str, keyword: str, cancel: threading.Event | None = None) -> dict:
        from . import router
        return router.products(self, maker, keyword, cancel)

    def invoke(self, operation: str, **kwargs) -> dict:
        operations = {"status": self.status, "inventory": self.inventory,
                      "malware": self.malware, "vulnerabilities": self.vulnerabilities,
                      "android": self.android_collect, "android_check": self.android_check,
                      "router_check": self.router_check, "router_products": self.router_products}
        source = SOURCES.get(operation, "bridge")
        started, clock = datetime.now(timezone.utc), time.perf_counter()
        try:
            if operation not in operations:
                raise ScannerError("Unknown operation")
            report = operations[operation](**kwargs)
        except ScannerError as exc:
            report = result(source, "error", error=str(exc))
        except (OSError, ValueError, TypeError, RuntimeError):
            report = result(source, "error", error="Operation could not complete; check configuration and input")
        except Exception as exc:
            # Whatever slipped through still becomes a result, never a crash of the CLI or server.
            report = result(source, "error",
                            error=f"Unexpected internal error ({type(exc).__name__}); the operation was not completed")
        if self.update_lookup and report["status"] != "error":
            from . import updates
            if operation in updates.ENGINES:
                try:
                    updates.check(self, operation, report, kwargs.get("cancel"))
                except Exception:
                    # Never at the cost of the result: the scan itself already finished.
                    report["warnings"].append("The engine version could not be compared with the latest release; "
                                              "the scan itself is unaffected")
        # Every result carries them, as a misspelt setting can change any operation.
        report["warnings"] = self.config_warnings + report["warnings"]
        if self.via and self.history_enabled:
            from . import history
            if operation in history.OPERATIONS:
                try:
                    history.append(self.history_path(), history.entry(
                        operation, kwargs, report, started, time.perf_counter() - clock, self.via),
                        report if self.history_details else None, self.history_details_mb * 1024 * 1024)
                except Exception:
                    # Never at the cost of the result: the scan itself already finished.
                    report["warnings"].append("Scan history could not be written; the scan itself is unaffected")
        return report
