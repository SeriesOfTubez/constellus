"""Admin-settable pacing of the rolling CVE refresh (planning#360).

`read(db)` is called ONCE at the start of each hourly run and the frozen result
is held for that run, so a changed setting takes effect on the next run with no
restart and one run never sees two values. A stored value that is not an int or
is out of range falls back to the default. The guards (the consecutive-failure
stop) are code, not settings. There is no unit pause: VulnCheck allows 1000
requests a minute and one CVE costs three calls.

Imports only app_settings.
"""

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.orm import Session

from app.services import app_settings

TIME_LIMIT_KEY = "cve.refresh_time_limit_seconds"
DUE_BATCH_KEY = "cve.refresh_due_batch"
REFRESH_INTERVAL_KEY = "cve.refresh_interval_hours"
FAILED_RETRY_KEY = "cve.refresh_failed_retry_hours"

DEFAULT_TIME_LIMIT_S, TIME_LIMIT_MIN, TIME_LIMIT_MAX = 300, 60, 3000
DEFAULT_DUE_BATCH, DUE_BATCH_MIN, DUE_BATCH_MAX = 500, 10, 5000
DEFAULT_REFRESH_INTERVAL_HOURS, REFRESH_INTERVAL_MIN, REFRESH_INTERVAL_MAX = 24, 1, 720
DEFAULT_FAILED_RETRY_HOURS, FAILED_RETRY_MIN, FAILED_RETRY_MAX = 6, 1, 720


@dataclass(frozen=True)
class CveRefreshPacing:
    time_limit_s: int
    due_batch: int
    refresh_interval: timedelta  # a refreshed CVE is due again after this
    failed_retry_after: timedelta  # a failed CVE is due again after this (never longer than refresh_interval)


def _bounded_int(db: Session, key: str, default: int, lo: int, hi: int) -> int:
    value = app_settings.get_int(db, key)
    return value if value is not None and lo <= value <= hi else default


def read(db: Session) -> CveRefreshPacing:
    refresh_hours = _bounded_int(
        db, REFRESH_INTERVAL_KEY, DEFAULT_REFRESH_INTERVAL_HOURS, REFRESH_INTERVAL_MIN, REFRESH_INTERVAL_MAX
    )
    failed_hours = _bounded_int(db, FAILED_RETRY_KEY, DEFAULT_FAILED_RETRY_HOURS, FAILED_RETRY_MIN, FAILED_RETRY_MAX)
    return CveRefreshPacing(
        time_limit_s=_bounded_int(db, TIME_LIMIT_KEY, DEFAULT_TIME_LIMIT_S, TIME_LIMIT_MIN, TIME_LIMIT_MAX),
        due_batch=_bounded_int(db, DUE_BATCH_KEY, DEFAULT_DUE_BATCH, DUE_BATCH_MIN, DUE_BATCH_MAX),
        refresh_interval=timedelta(hours=refresh_hours),
        failed_retry_after=timedelta(hours=min(failed_hours, refresh_hours)),
    )
