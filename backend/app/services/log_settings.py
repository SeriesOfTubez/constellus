"""DB log queue tuning as admin settings (planning#335).

Keys, bounds and the read. Defaults live with the queue in
`app.core.logging`. A stored value that is missing, unparsable or out of
bounds reads as the default.

Key names stay clear of `audit.SECRET_KEY_HINTS`, so the audit row keeps
its from/to values.
"""
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.logging import DEFAULT_BATCH_MAX, DEFAULT_FLUSH_INTERVAL_S, DEFAULT_QUEUE_MAX
from app.services import app_settings

QUEUE_MAX_KEY = "logs.queue_max_records"
BATCH_MAX_KEY = "logs.batch_max_records"
FLUSH_INTERVAL_S_KEY = "logs.flush_interval_s"

QUEUE_MAX_MIN, QUEUE_MAX_MAX = 1_000, 100_000
BATCH_MAX_MIN, BATCH_MAX_MAX = 10, 1_000
FLUSH_INTERVAL_S_MIN, FLUSH_INTERVAL_S_MAX = 0.2, 10.0


@dataclass(frozen=True)
class LogQueueTuning:
    queue_max: int
    batch_max: int
    flush_interval_s: float


def _int_in(db: Session, key: str, lo: int, hi: int, default: int) -> int:
    value = app_settings.get_int(db, key)
    if value is not None and lo <= value <= hi:
        return value
    return default


def _float_in(db: Session, key: str, lo: float, hi: float, default: float) -> float:
    try:
        value = float(app_settings.get(db, key))
    except (ValueError, TypeError):
        return default
    # NaN fails both comparisons, so it reads as the default too.
    return value if lo <= value <= hi else default


def tuning(db: Session) -> LogQueueTuning:
    return LogQueueTuning(
        queue_max=_int_in(db, QUEUE_MAX_KEY, QUEUE_MAX_MIN, QUEUE_MAX_MAX, DEFAULT_QUEUE_MAX),
        batch_max=_int_in(db, BATCH_MAX_KEY, BATCH_MAX_MIN, BATCH_MAX_MAX, DEFAULT_BATCH_MAX),
        flush_interval_s=_float_in(db, FLUSH_INTERVAL_S_KEY, FLUSH_INTERVAL_S_MIN,
                                   FLUSH_INTERVAL_S_MAX, DEFAULT_FLUSH_INTERVAL_S),
    )
