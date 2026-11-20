"""Fix-due clock (planning#381): the clock starts at first seen, never at the
CISA KEV listing, whichever came first. Being in KEV still picks the window.

Pure unit tests, no database: `compute_sla` reads attributes only.
"""

from datetime import date, datetime, time, timedelta, timezone
from types import SimpleNamespace

from app.services.bod_sla import compute_sla


def _finding(*, seen_days_ago: int, kev_days_ago: int | None):
    today = date.today()
    return SimpleNamespace(
        cve_id="CVE-2026-0001",
        ssvc_source="vulnrichment",
        kev=kev_days_ago is not None,
        kev_date_added=None if kev_days_ago is None else today - timedelta(days=kev_days_ago),
        ssvc_automatable=True,
        ssvc_technical_impact="partial",
        first_seen_at=datetime.combine(today - timedelta(days=seen_days_ago), time(12, 0), tzinfo=timezone.utc),
    )


# An address asset is exposed without a port projection.
_ASSET = SimpleNamespace(asset_type="ip_address")


def test_found_after_the_kev_listing_counts_from_first_seen():
    # Listed 20 days ago, found 2 days ago: the listing's clock would have made
    # it overdue before we knew of it.
    sla = compute_sla(_finding(seen_days_ago=2, kev_days_ago=20), _ASSET)
    assert sla["window"] == "3d"
    assert sla["due_date"] == (date.today() + timedelta(days=1)).isoformat()
    assert sla["days_remaining"] == 1
    assert sla["overdue"] is False


def test_found_before_the_kev_listing_still_counts_from_first_seen():
    # Found 10 days ago, listed yesterday: not the later listing, and not
    # reset by it either.
    sla = compute_sla(_finding(seen_days_ago=10, kev_days_ago=1), _ASSET)
    assert sla["window"] == "3d"
    assert sla["due_date"] == (date.today() - timedelta(days=7)).isoformat()
    assert sla["days_remaining"] == -7
    assert sla["overdue"] is True


def test_not_listed_counts_from_first_seen_with_the_longer_window():
    # Same axes as above apart from KEV: the window lengthens, the clock is unchanged.
    sla = compute_sla(_finding(seen_days_ago=5, kev_days_ago=None), _ASSET)
    assert sla["window"] == "14d"
    assert sla["due_date"] == (date.today() + timedelta(days=9)).isoformat()
    assert sla["days_remaining"] == 9
    assert sla["overdue"] is False
