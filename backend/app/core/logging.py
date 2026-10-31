"""
Root log handlers. Hooks into Python's logging system so all existing log
calls throughout the codebase are captured automatically:

  stderr  — every record at `settings.log_level` and above, so container
            tooling (`docker compose logs`, `kubectl logs`) sees the app
            (planning#326). Installed first, so it also covers a DB outage.
  DB      — INFO and above into `system_logs`, which the Logs page reads.

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
import sys
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


class DBLogHandler(logging.Handler):
    """Writes log records to the system_logs table."""

    def __init__(self):
        super().__init__(level=_MIN_LEVEL)
        self._enabled = False
        self.addFilter(_skip_filter)

    def enable(self):
        self._enabled = True

    def emit(self, record: logging.LogRecord) -> None:
        if not self._enabled:
            return
        try:
            from app.core.database import SessionLocal
            from app.models.system_log import SystemLog
            db = SessionLocal()
            try:
                db.add(SystemLog(
                    id=uuid.uuid4(),
                    created_at=datetime.fromtimestamp(record.created, tz=timezone.utc),
                    level=record.levelname,
                    source=_extract_source(record.name),
                    logger_name=record.name,
                    message=self.format(record),
                ))
                db.commit()
            finally:
                db.close()
        except Exception as exc:
            print(f"[DBLogHandler] Failed to write log: {exc}", file=sys.stderr)


db_handler = DBLogHandler()

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


def setup_db_logging() -> None:
    """Attach the DB handler to the root logger and enable it."""
    root = logging.getLogger()
    # Ensure root logger is at INFO so records reach our handler
    _ensure_root_level(_MIN_LEVEL)
    if db_handler not in root.handlers:
        db_handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(db_handler)
    db_handler.enable()
