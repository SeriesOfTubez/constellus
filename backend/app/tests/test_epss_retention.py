"""Tests for the epss_history rolling-window boundary.

epss_history was a TimescaleDB hypertable whose 84-day window was enforced by
`add_retention_policy`. That call was removed so the schema runs on stock
PostgreSQL, and `epss_history_service.prune_expired` replaces it.

The regression these guard is a real one, caught during that swap: the cutoff
was first derived from `date.today()` (local) while rows are stored at midnight
UTC. On a host west of UTC that leaves a full day of expired rows behind on
every pass — silently, because pruning still "works", just never quite far
enough.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_epss_retention          (from /app)
       or: pytest app/tests/test_epss_retention.py          (if pytest installed)
"""

from datetime import datetime, timedelta, timezone

from app.services.epss_history_service import _RETENTION_DAYS, retention_cutoff


def test_cutoff_is_timezone_aware_utc():
    cutoff = retention_cutoff()
    assert cutoff.tzinfo is not None, "naive cutoff compares wrongly against timestamptz"
    assert cutoff.utcoffset() == timedelta(0)


def test_cutoff_is_midnight():
    cutoff = retention_cutoff()
    assert (cutoff.hour, cutoff.minute, cutoff.second, cutoff.microsecond) == (0, 0, 0, 0)


def test_cutoff_derives_from_utc_date_not_local():
    """The regression guard. Under the local-date bug this fails on any host
    whose local date trails UTC, which is every US timezone for part of the day."""
    expected_date = (datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS)).date()
    assert retention_cutoff().date() == expected_date


def test_sample_older_than_window_is_pruned():
    """A row one day beyond the window must fall strictly before the cutoff."""
    cutoff = retention_cutoff()
    too_old = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS + 1)
    assert too_old < cutoff


def test_sample_inside_window_is_kept():
    cutoff = retention_cutoff()
    recent = datetime.now(timezone.utc) - timedelta(days=_RETENTION_DAYS - 1)
    assert recent >= cutoff


def test_window_covers_the_backfill_depth():
    """Retention must outlast the 12 weekly points cve_enrichment backfills,
    or a freshly backfilled CVE loses its history on the next prune."""
    from app.services.epss_history_service import _BACKFILL_WEEKS

    assert _RETENTION_DAYS >= _BACKFILL_WEEKS * 7


def test_custom_retention_days_respected():
    assert retention_cutoff(30).date() == (
        datetime.now(timezone.utc) - timedelta(days=30)
    ).date()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("all passed")
