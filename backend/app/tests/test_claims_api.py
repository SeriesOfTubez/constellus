"""API tests for the claims-layer query endpoints (planning#145, L4).

No `TestClient` pattern exists anywhere in this suite (checked before
writing this file — see e.g. `test_third_party_capture.py`'s
`list_assets(db=db, _=None)`), so these tests follow that same convention:
call the router functions directly with a real `SessionLocal` session,
passing `_=None` for the `get_current_user` dependency FastAPI would
otherwise inject. `HTTPException` is asserted via try/except rather than
`pytest.raises` so this file stays runnable standalone (see the
`if __name__ == "__main__":` block), matching every other file here.

Run with:  python -m app.tests.test_claims_api
       or: pytest app/tests/test_claims_api.py
"""

import uuid

from fastapi import HTTPException

from app.api.claims import get_absence, get_surface
from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import ClaimHistory
from app.services.asset_writer import write_assets


def _cleanup(values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _assert_http_error(fn, expected_status: int, *args, **kwargs) -> HTTPException:
    try:
        fn(*args, **kwargs)
    except HTTPException as exc:
        assert exc.status_code == expected_status, (
            f"expected {expected_status}, got {exc.status_code}: {exc.detail}"
        )
        return exc
    raise AssertionError(f"expected HTTPException({expected_status}) from {fn.__name__}")


# ── GET /api/claims/surface/{asset_id} ───────────────────────────────────────

def test_get_surface_returns_shape_for_a_real_asset():
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{170 + (int(suffix[:2], 16) % 20)}"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="ip_address", value=ip,
            asset_metadata={
                "sources": ["naabu"],
                "open_ports": [{"port": 22, "protocol": "tcp", "sources": ["naabu"]}],
            },
        )])
        row = db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()

        result = get_surface(row.id, db=db, _=None)

        assert result == {"asset_id": str(row.id), "surface": "unknown"}, result
    finally:
        db.close()
        _cleanup([ip])


def test_get_surface_404s_for_an_id_with_no_canonical_row():
    db = SessionLocal()
    try:
        _assert_http_error(get_surface, 404, uuid.uuid4(), db=db, _=None)
    finally:
        db.close()


# ── GET /api/claims/absence ───────────────────────────────────────────────────

def test_get_absence_returns_rows_shaped_and_surfaced():
    suffix = uuid.uuid4().hex[:10]
    ip_claimed = f"203.0.113.{190 + (int(suffix[:2], 16) % 10)}"
    ip_unclaimed = f"198.51.100.{110 + (int(suffix[2:4], 16) % 60)}"
    db = SessionLocal()
    try:
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="ip_address", value=ip_claimed,
            asset_metadata={
                "sources": ["naabu"],
                "open_ports": [{"port": 22, "protocol": "tcp", "sources": ["naabu"]}],
            },
        )])
        write_assets(db, uuid.uuid4(), [DiscoveredAsset(
            asset_type="ip_address", value=ip_unclaimed, asset_metadata={},
        )])
        unclaimed_row = db.query(AssetCanonical).filter(AssetCanonical.value == ip_unclaimed).one()

        rows = get_absence(
            claim_type="port_observation", observer="naabu", asset_type=None,
            surface=None, include_ignored=False, limit=1000, db=db, _=None,
        )

        by_id = {r["asset_id"]: r for r in rows}
        assert str(unclaimed_row.id) in by_id, "the unclaimed asset must be present"
        row = by_id[str(unclaimed_row.id)]
        assert set(row) == {"asset_id", "asset_type", "value", "last_seen_at", "surface"}, row
        assert row["asset_type"] == "ip_address"
        assert row["value"] == ip_unclaimed
        assert row["surface"] == "unknown"
    finally:
        db.close()
        _cleanup([ip_claimed, ip_unclaimed])


def test_get_absence_422s_on_unknown_claim_type():
    db = SessionLocal()
    try:
        _assert_http_error(
            get_absence, 422,
            claim_type="bogus_claim_type", observer=None, asset_type=None,
            surface=None, include_ignored=False, limit=1000, db=db, _=None,
        )
    finally:
        db.close()


def test_get_absence_422s_on_unknown_observer():
    db = SessionLocal()
    try:
        _assert_http_error(
            get_absence, 422,
            claim_type="port_observation", observer=f"bogus-observer-{uuid.uuid4().hex[:8]}",
            asset_type=None, surface=None, include_ignored=False, limit=1000, db=db, _=None,
        )
    finally:
        db.close()


def test_get_absence_422s_on_unknown_surface():
    db = SessionLocal()
    try:
        _assert_http_error(
            get_absence, 422,
            claim_type="port_observation", observer=None, asset_type=None,
            surface="bogus_surface", include_ignored=False, limit=1000, db=db, _=None,
        )
    finally:
        db.close()


def _run():
    tests = [
        test_get_surface_returns_shape_for_a_real_asset,
        test_get_surface_404s_for_an_id_with_no_canonical_row,
        test_get_absence_returns_rows_shaped_and_surfaced,
        test_get_absence_422s_on_unknown_claim_type,
        test_get_absence_422s_on_unknown_observer,
        test_get_absence_422s_on_unknown_surface,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
