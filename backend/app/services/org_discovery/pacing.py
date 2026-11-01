"""Admin-settable pacing of the rolling re-discovery tick (planning#320).

`read(db)` is called ONCE at the start of each hourly run and the frozen result
is held for that run, so a changed setting takes effect on the next run with no
restart and one run never sees two values. A stored value that is not an int or
is out of range falls back to the default. The guards (serial execution, the
root Re-check slot, rate-limited-is-not-failed) are code, not settings.

Imports only app_settings: neither `runner` nor `rolling` may be imported here.
"""

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.orm import Session

from app.services import app_settings

TIME_LIMIT_KEY = "discovery.rediscovery_time_limit_seconds"
UNIT_PAUSE_KEY = "discovery.rediscovery_unit_pause_seconds"
DUE_BATCH_KEY = "discovery.rediscovery_due_batch"
REFRESH_INTERVAL_KEY = "discovery.rediscovery_refresh_interval_days"
FAILED_RETRY_KEY = "discovery.rediscovery_failed_retry_days"

DEFAULT_TIME_LIMIT_S, TIME_LIMIT_MIN, TIME_LIMIT_MAX = 600, 60, 3000
DEFAULT_UNIT_PAUSE_S, UNIT_PAUSE_MIN, UNIT_PAUSE_MAX = 2, 1, 60
DEFAULT_DUE_BATCH, DUE_BATCH_MIN, DUE_BATCH_MAX = 200, 10, 1000
DEFAULT_REFRESH_INTERVAL_DAYS, REFRESH_INTERVAL_MIN, REFRESH_INTERVAL_MAX = 7, 1, 90
DEFAULT_FAILED_RETRY_DAYS, FAILED_RETRY_MIN, FAILED_RETRY_MAX = 1, 1, 30


@dataclass(frozen=True)
class RollingPacing:
    time_limit_s: int
    unit_pause_s: int
    due_batch: int
    refresh_interval: timedelta  # a refreshed unit is due again after this
    failed_retry_after: timedelta  # a failed unit is due again after this (never longer than refresh_interval)


def _bounded_int(db: Session, key: str, default: int, lo: int, hi: int) -> int:
    value = app_settings.get_int(db, key)
    return value if value is not None and lo <= value <= hi else default


def read(db: Session) -> RollingPacing:
    refresh_days = _bounded_int(
        db, REFRESH_INTERVAL_KEY, DEFAULT_REFRESH_INTERVAL_DAYS, REFRESH_INTERVAL_MIN, REFRESH_INTERVAL_MAX
    )
    failed_days = _bounded_int(db, FAILED_RETRY_KEY, DEFAULT_FAILED_RETRY_DAYS, FAILED_RETRY_MIN, FAILED_RETRY_MAX)
    return RollingPacing(
        time_limit_s=_bounded_int(db, TIME_LIMIT_KEY, DEFAULT_TIME_LIMIT_S, TIME_LIMIT_MIN, TIME_LIMIT_MAX),
        unit_pause_s=_bounded_int(db, UNIT_PAUSE_KEY, DEFAULT_UNIT_PAUSE_S, UNIT_PAUSE_MIN, UNIT_PAUSE_MAX),
        due_batch=_bounded_int(db, DUE_BATCH_KEY, DEFAULT_DUE_BATCH, DUE_BATCH_MIN, DUE_BATCH_MAX),
        refresh_interval=timedelta(days=refresh_days),
        failed_retry_after=timedelta(days=min(failed_days, refresh_days)),
    )
