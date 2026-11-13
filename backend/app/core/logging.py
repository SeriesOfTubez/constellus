"""
Root log handlers. Hooks into Python's logging system so all existing log
calls throughout the codebase are captured automatically:

  stderr  — every record at `settings.log_level` and above, so container
            tooling (`docker compose logs`, `kubectl logs`) sees the app
            (planning#326). Installed first, so it also covers a DB outage.
  DB      — INFO and above into `system_logs`, which the Logs page reads.
            Queued and written in batches by one thread (planning#328), so
            a slow or dead DB never blocks a caller.

Both share one skip-list filter. It is a secrets guard as well as noise
control: httpx logs every request URL at INFO, and some connectors carry
their API key in the query string (Shodan's `?key=`).

Source classification:
  app.connectors.*          → connector name  (e.g. "cloudflare", "mailtrap")
  app.services.discovery.*  → discovery tool name (e.g. "cert_transparency")
  app.services.scan_executor → "scan_executor"
  everything else            → "system"
"""

import logging
import queue
import sys
import threading
import time
import uuid
from datetime import datetime, timezone

_SKIP_PREFIXES = (
    "sqlalchemy", "alembic", "uvicorn", "asyncio",
    "multipart", "httpx", "httpcore", "watchfiles",
)
_MIN_LEVEL = logging.INFO


def _extract_source(logger_name: str) -> str:
    if logger_name.startswith("app.connectors."):
        return logger_name.split(".")[-1]
    if logger_name.startswith("app.services.discovery."):
        return logger_name.split(".")[-1]
    if "scan_executor" in logger_name:
        return "scan_executor"
    if "target_service" in logger_name:
        return "target_service"
    return "system"


class _SkipFilter(logging.Filter):
    """Drops records from library loggers in `_SKIP_PREFIXES`."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not record.name.startswith(_SKIP_PREFIXES)


_skip_filter = _SkipFilter()


# Defaults. Admin settings override them (planning#335; keys and bounds in
# `app.services.log_settings`). The queue bound is read once at startup;
# the writer re-reads the other two while it runs.
DEFAULT_QUEUE_MAX = 10_000        # records held before new ones are dropped
DEFAULT_BATCH_MAX = 200           # records per commit
DEFAULT_FLUSH_INTERVAL_S = 1.0    # longest a partial batch waits
# Guards, not settings.
_STOP_JOIN_TIMEOUT_S = 5.0   # shutdown never waits longer on a dead DB
_TUNING_REREAD_S = 30.0      # the writer re-reads the settings this often


def _stderr(line: str) -> None:
    # The DB writer's own reporting. Never through `logging`: that would
    # feed its failures back into its own queue.
    print(f"[DBLogHandler] {line}", file=sys.stderr, flush=True)


def _read_tuning():
    """The admin tuning, read with a short-lived session. Raises on any
    failure; callers keep what they had. Never logs."""
    from app.core.database import SessionLocal
    from app.services import log_settings
    db = SessionLocal()
    try:
        return log_settings.tuning(db)
    finally:
        try:
            db.rollback()
        finally:
            db.close()


class DBLogHandler(logging.Handler):
    """Queues log records for `system_logs` (planning#328).

    `emit` runs on the logging thread and never touches the DB or the
    connection pool: it formats the record and does a non-blocking put. On
    a full queue the record is dropped and counted (newest dropped, so the
    queued lead-up to an outage survives). `_DBLogWriter` drains the queue.
    """

    def __init__(self):
        super().__init__(level=_MIN_LEVEL)
        self._enabled = False
        self.addFilter(_skip_filter)
        self.queue: queue.Queue[dict] = queue.Queue(maxsize=DEFAULT_QUEUE_MAX)
        self._dropped = 0
        self._dropped_lock = threading.Lock()

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False

    def resize(self, maxsize: int) -> bool:
        """Give the queue a new bound. Only while disabled and empty (i.e. at
        startup), so no record is ever in flight; otherwise a no-op."""
        if self._enabled or not self.queue.empty():
            return False
        if self.queue.maxsize != maxsize:
            self.queue = queue.Queue(maxsize=maxsize)
        return True

    def take_dropped(self) -> int:
        """Return and reset the queue-full drop count."""
        with self._dropped_lock:
            n, self._dropped = self._dropped, 0
        return n

    def emit(self, record: logging.LogRecord) -> None:
        if not self._enabled:
            return
        try:
            row = {
                "created_at": datetime.fromtimestamp(record.created, tz=timezone.utc),
                "level": record.levelname,
                "source": _extract_source(record.name),
                "logger_name": record.name,
                "message": self.format(record),
            }
        except Exception:
            self.handleError(record)
            return
        try:
            self.queue.put_nowait(row)
        except queue.Full:
            with self._dropped_lock:
                self._dropped += 1


db_handler = DBLogHandler()


class _DBLogWriter:
    """The one thread that writes queued records to `system_logs`.

    Owns and commits its own session per batch. A failed batch is rolled
    back and retried once, then dropped; stderr gets the exception TYPE and
    a count, never the exception text (it can carry the bound parameters,
    i.e. the log messages).

    Batch size and flush interval are admin settings (planning#335),
    re-read every `_TUNING_REREAD_S`. An unreadable setting keeps the last
    good values and tells stderr once per outage.
    """

    _STOP = object()

    def __init__(self, handler: DBLogHandler):
        self.handler = handler
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self.batch_max = DEFAULT_BATCH_MAX
        self.flush_interval_s = DEFAULT_FLUSH_INTERVAL_S
        self._next_reread = 0.0
        self._tuning_unreadable = False

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._run, name="db-log-writer", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = _STOP_JOIN_TIMEOUT_S) -> None:
        """Stop enqueueing, write what is queued, and join (bounded)."""
        self.handler.disable()
        thread = self._thread
        if thread is None:
            return
        self._stopping.set()
        thread.join(timeout)
        if thread.is_alive():
            _stderr(f"shutdown: writer still busy after {timeout:.0f}s; "
                    f"{self.handler.queue.qsize()} records not written")
        self._thread = None

    def _run(self) -> None:
        while True:
            try:
                if not self._stopping.is_set():
                    self.refresh_tuning()
                batch = self.next_batch(self.flush_interval_s)
                if batch:
                    self.write(batch)
                self.report_dropped()
            except Exception as exc:
                # A dead writer would leave the queue to fill forever.
                _stderr(f"writer error ({type(exc).__name__}); continuing")
            if self._stopping.is_set() and self.handler.queue.empty():
                return

    def refresh_tuning(self) -> None:
        """Re-read batch size and flush interval, at most every `_TUNING_REREAD_S`."""
        now = time.monotonic()
        if now < self._next_reread:
            return
        self._next_reread = now + _TUNING_REREAD_S
        try:
            tuning = _read_tuning()
        except Exception as exc:
            if not self._tuning_unreadable:
                self._tuning_unreadable = True
                _stderr(f"settings unreadable ({type(exc).__name__}); keeping batch "
                        f"{self.batch_max}, flush {self.flush_interval_s}s")
            return
        if self._tuning_unreadable:
            self._tuning_unreadable = False
            _stderr("settings readable again")
        self.batch_max = tuning.batch_max
        self.flush_interval_s = tuning.flush_interval_s

    def next_batch(self, wait_s: float) -> list[dict]:
        """Up to `batch_max` records, waiting at most `wait_s` in total."""
        q = self.handler.queue
        deadline = time.monotonic() + wait_s
        batch: list[dict] = []
        while len(batch) < self.batch_max:
            remaining = deadline - time.monotonic()
            try:
                if self._stopping.is_set() or remaining <= 0:
                    batch.append(q.get_nowait())
                else:
                    batch.append(q.get(timeout=remaining))
            except queue.Empty:
                break
        return batch

    def write(self, batch: list[dict]) -> bool:
        last_exc: Exception | None = None
        for _attempt in range(2):
            try:
                self._insert(batch)
                return True
            except Exception as exc:
                last_exc = exc
        _stderr(f"dropped {len(batch)} records: write failed twice "
                f"({type(last_exc).__name__})")
        return False

    def _insert(self, batch: list[dict]) -> None:
        from app.core.database import SessionLocal
        from app.models.system_log import SystemLog
        db = SessionLocal()
        try:
            db.add_all(SystemLog(id=uuid.uuid4(), **row) for row in batch)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def report_dropped(self) -> None:
        n = self.handler.take_dropped()
        if n:
            _stderr(f"queue full: dropped {n} records")


db_writer = _DBLogWriter(db_handler)

_STDERR_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_stderr_handler: logging.Handler | None = None


def _ensure_root_level(level: int) -> None:
    root = logging.getLogger()
    if root.level == logging.NOTSET or root.level > level:
        root.setLevel(level)


def setup_stderr_logging(level: str) -> None:
    """Attach the stderr handler to the root logger at `level`. Idempotent."""
    global _stderr_handler
    if _stderr_handler is None:
        formatter = logging.Formatter(_STDERR_FORMAT, datefmt="%Y-%m-%dT%H:%M:%SZ")
        formatter.converter = time.gmtime
        _stderr_handler = logging.StreamHandler(sys.stderr)
        _stderr_handler.setFormatter(formatter)
        _stderr_handler.addFilter(_skip_filter)
    _stderr_handler.setLevel(level)
    _ensure_root_level(_stderr_handler.level)
    root = logging.getLogger()
    if _stderr_handler not in root.handlers:
        root.addHandler(_stderr_handler)


def _size_queue() -> None:
    """Apply the admin queue bound. Startup only: a later change waits for
    the next restart, because `resize` refuses a handler that is in use."""
    try:
        bound = _read_tuning().queue_max
    except Exception as exc:
        bound = DEFAULT_QUEUE_MAX
        _stderr(f"settings unreadable at startup ({type(exc).__name__}); "
                f"queue bound {bound}")
    db_handler.resize(bound)


def setup_db_logging() -> None:
    """Attach the DB handler to the root logger, start its writer, enable it."""
    root = logging.getLogger()
    # Ensure root logger is at INFO so records reach our handler
    _ensure_root_level(_MIN_LEVEL)
    if db_handler not in root.handlers:
        db_handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(db_handler)
    _size_queue()
    db_writer.start()
    db_handler.enable()


def stop_db_logging() -> None:
    """Flush queued records and stop the writer. Call after the scheduler stops."""
    db_writer.stop()
