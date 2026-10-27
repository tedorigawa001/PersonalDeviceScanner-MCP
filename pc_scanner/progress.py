"""Per-call, thread-safe progress. Counters describe parts, not an estimated percentage.

No file names or raw engine output enter notifications. Saved counts change only after an
atomic checkpoint write, independently of the number of parts observed in memory.
"""
import threading
import time
import signal
import sys

CLI_INTERVAL_SECONDS = 1.0


class ScanProgress:
    def __init__(self, on_signature_check=None):
        self._lock = threading.Lock()
        self._start = time.monotonic()
        self._end = None
        self._deadline = None
        self._on_signature_check = on_signature_check
        self._state = {"stage": "waiting", "finished": None, "pending": None, "reused": None,
                       "checkpoint": "not_started", "saved_parts": None}

    def update(self, **fields):
        with self._lock:
            if self._end is None:
                self._state.update(fields)

    def set_deadline(self, deadline):
        with self._lock:
            self._deadline = deadline

    def signature_check(self, info):
        self.update(signature_check=info)
        if self._on_signature_check:
            try:
                self._on_signature_check()
            except Exception:
                pass  # Advice delivery must not prevent scanning or checkpoint preservation.

    def finish(self, stage, cancel=None):
        with self._lock:
            if self._end is None:
                if stage in {"partial", "error"}:
                    if cancel is not None and cancel.is_set():
                        stage = "cancelled"
                    elif self._deadline is not None and time.monotonic() >= self._deadline:
                        stage = "timed_out"
                self._state["stage"] = stage
                self._end = time.monotonic()

    def snapshot(self):
        with self._lock:
            return {**self._state, "elapsed_seconds": round(max(0.0,
                    (self._end if self._end is not None else time.monotonic()) - self._start), 3)}


def message(state):
    def count(key):
        return "unknown" if state[key] is None else str(state[key])
    return (f"stage={state['stage']} elapsed={state['elapsed_seconds']:.1f}s "
            f"finished={count('finished')} pending={count('pending')} reused={count('reused')} "
            f"checkpoint={state['checkpoint']} saved_parts={count('saved_parts')}"
            + (f" scan_id={state['scan_id']}" if state.get("scan_id") else "")
            + signature_message(state.get("signature_check")))


def signature_message(info):
    if not info:
        return ""
    return (f" definitions={info['freshness']} engine={info['engine']} signature_version={info['version']} "
            f"built_at={info['built_at']} age_days={info['age_days']} max_age_days={info['max_age_days']} "
            "update=owner-configured_freshclam;ask_administrator_if_denied;recheck_after_update;no_update_run")


class CLIProgress:
    """stderr only; Ctrl+C requests cancellation and lets the worker preserve its checkpoint."""
    def __init__(self):
        self.progress = ScanProgress(on_signature_check=self._write)
        self.cancel = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True)
        self._previous = None

    def _write(self):
        try:
            print("pc-scanner progress: " + message(self.progress.snapshot()), file=sys.stderr, flush=True)
        except (OSError, ValueError):
            self._stop.set()  # Losing the display must not lose the scan.

    def _watch(self):
        while not self._stop.wait(CLI_INTERVAL_SECONDS):
            self._write()

    def __enter__(self):
        if threading.current_thread() is threading.main_thread():
            self._previous = signal.getsignal(signal.SIGINT)
            def interrupt(signum, frame):
                if self.cancel.is_set():
                    raise KeyboardInterrupt
                self.cancel.set()
            signal.signal(signal.SIGINT, interrupt)
        self._write()
        self._thread.start()
        return self

    def __exit__(self, kind, value, traceback):
        if kind is not None:
            self.progress.finish("cancelled" if issubclass(kind, KeyboardInterrupt) else "error")
        self._stop.set()
        self._thread.join(timeout=0.2)
        self._write()
        if self._previous is not None:
            signal.signal(signal.SIGINT, self._previous)
