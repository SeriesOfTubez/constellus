"""
DB-backed log handler. Hooks into Python's logging system so all existing
log calls throughout the codebase are captured automatically.

Source classification:
  app.connectors.*          → connector name  (e.g. "cloudflare", "mailtrap")
  app.services.discovery.*  → discovery tool name (e.g. "cert_transparency")
  app.services.scan_executor → "scan_executor"
  everything else            → "system"
"""

import logging
import sys
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


class DBLogHandler(logging.Handler):
    """Writes log records to the system_logs table."""

    def __init__(self):
        super().__init__(level=_MIN_LEVEL)
        self._enabled = False

    def enable(self):
        self._enabled = True

    def emit(self, record: logging.LogRecord) -> None:
        if not self._enabled:
            return
        if record.name.startswith(_SKIP_PREFIXES):
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


def setup_db_logging() -> None:
    """Attach the DB handler to the root logger and enable it."""
    root = logging.getLogger()
    # Ensure root logger is at INFO so records reach our handler
    if root.level == logging.NOTSET or root.level > logging.INFO:
        root.setLevel(logging.INFO)
    if db_handler not in root.handlers:
        db_handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(db_handler)
    db_handler.enable()
