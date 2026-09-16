"""Regression tests for planning#173: `upsert_single_claim`'s race.

Before the fix, `upsert_single_claim` (app/services/claim_emitter.py) did an
unlocked SELECT-then-INSERT against the unique constraint
`uq_asset_claims_asset_observer_type` on
`(asset_canonical_id, observer_id, claim_type)`. Two concurrent callers for
the same (asset, observer, claim_type) — e.g. two enrichment passes
classifying the same IP at once — could both miss the SELECT, both INSERT,
and the loser would take an `IntegrityError` that aborted its caller's WHOLE
transaction, silently losing that pass's claim write.

The fix (already implemented, not touched by this file) switches the insert
to `pg_insert(...).on_conflict_do_nothing(constraint=...).returning(...)`,
and on conflict re-reads the row with `.with_for_update().populate_existing()`
before the read-modify-write, so a losing writer falls through to an UPDATE
under a row lock instead of raising.

These are real two-session tests against the real dev DB (no test DB exists
in this project — see backend/app/tests/test_hosting_classifier.py's
docstring and planning#171): two genuine `threading.Thread`s, each opening
its own `SessionLocal()`, synchronized on a `threading.Barrier(2)` so both
threads are actually racing inside Postgres. A mock or monkeypatched DB
proves nothing here — the entire mechanism being tested is DB-level
(the unique index and row locking), not application logic.

Cleanup discipline (planning#171): every asset this file creates uses an
RFC 5737 documentation IP (192.0.2.0/24) suffixed by `uuid4().hex[:8]`-style
randomness picked from high in the range, so parallel runs don't collide.
`_cleanup(value)` mirrors test_hosting_classifier.py's helper: delete
ClaimHistory by asset_canonical_id.in_(ids) for that one value, then the
asset_canonical rows for that one value — never a table-wide delete.

Run with:  python -m app.tests.test_claim_upsert_concurrency
       or: pytest app/tests/test_claim_upsert_concurrency.py -v
"""

import threading
import uuid
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import AssetClaim, ClaimHistory
from app.services.claim_emitter import get_current_claim, upsert_single_claim

_OBSERVER = "hosting_classifier"
_CLAIM_TYPE = "hosting_class"
_BARRIER_TIMEOUT = 15
_JOIN_TIMEOUT = 30


def _make_ip_asset(db, ip: str) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _cleanup(value: str) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == value).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value == value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _clear_claims(asset_id) -> None:
    """Delete just this asset's asset_claims + claim_history rows, scoped by
    asset_canonical_id — used between race iterations within a single test,
    never a table-wide delete."""
    db = SessionLocal()
    try:
        db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id == asset_id).delete(synchronize_session=False)
        db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == asset_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _claim_rows(asset_id) -> list[AssetClaim]:
    db = SessionLocal()
    try:
        return (
            db.query(AssetClaim)
            .filter(
                AssetClaim.asset_canonical_id == asset_id,
                AssetClaim.claim_type == _CLAIM_TYPE,
            )
            .all()
        )
    finally:
        db.close()


def _history_count(asset_id) -> int:
    db = SessionLocal()
    try:
        return (
            db.query(ClaimHistory)
            .filter(
                ClaimHistory.asset_canonical_id == asset_id,
                ClaimHistory.claim_type == _CLAIM_TYPE,
            )
            .count()
        )
    finally:
        db.close()


def _race(asset_id, barrier, value_a, value_b, results):
    """Run two threads that both read-then-write the same
    (asset, observer, claim_type) claim, synchronized so both writes hit
    Postgres concurrently. Appends one result dict per thread into `results`
    (a shared list — each thread appends its own entry, no shared mutation
    of the same slot)."""

    def _worker(claim_value, slot):
        db = SessionLocal()
        outcome = {"integrity_error": None, "error": None}
        try:
            get_current_claim(db, asset_id, _OBSERVER, _CLAIM_TYPE)
            barrier.wait(timeout=_BARRIER_TIMEOUT)
            upsert_single_claim(db, asset_id, _OBSERVER, _CLAIM_TYPE, claim_value, datetime.now(timezone.utc))
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            outcome["integrity_error"] = repr(exc)
        except Exception as exc:  # noqa: BLE001 — deliberately broad, recorded for diagnosis
            db.rollback()
            outcome["error"] = repr(exc)
        finally:
            db.close()
            results[slot] = outcome

    t_a = threading.Thread(target=_worker, args=(value_a, 0))
    t_b = threading.Thread(target=_worker, args=(value_b, 1))
    t_a.start()
    t_b.start()
    t_a.join(timeout=_JOIN_TIMEOUT)
    t_b.join(timeout=_JOIN_TIMEOUT)
    assert not t_a.is_alive(), "thread A did not finish within the join timeout — possible deadlock"
    assert not t_b.is_alive(), "thread B did not finish within the join timeout — possible deadlock"


# ── Test 1: first write, no existing claim ──────────────────────────────────

def test_concurrent_first_write_does_not_raise_integrity_error():
    suffix = uuid.uuid4().hex[:8]
    ip = f"192.0.2.{200 + (int(suffix[:2], 16) % 50)}"
    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
    finally:
        db.close()

    try:
        for iteration in range(5):
            _clear_claims(asset.id)
            results = [None, None]
            barrier = threading.Barrier(2)
            value_a = {"is_datacenter": True, "company_name": f"A-{iteration}", "asn": 100 + iteration}
            value_b = {"is_datacenter": False, "company_name": f"B-{iteration}", "asn": 200 + iteration}

            _race(asset.id, barrier, value_a, value_b, results)

            integrity_errors = [r["integrity_error"] for r in results if r["integrity_error"]]
            other_errors = [r["error"] for r in results if r["error"]]
            assert not integrity_errors, (
                f"iteration {iteration}: concurrent first write raised IntegrityError: {integrity_errors!r}"
            )
            assert not other_errors, f"iteration {iteration}: unexpected error(s): {other_errors!r}"

            rows = _claim_rows(asset.id)
            assert len(rows) == 1, (
                f"iteration {iteration}: expected exactly one AssetClaim row, found {len(rows)}"
            )
            surviving_value = rows[0].claim_value
            assert surviving_value in (value_a, value_b), (
                f"iteration {iteration}: surviving claim_value {surviving_value!r} matches neither "
                f"thread's value ({value_a!r} / {value_b!r}) — looks like a merge, not a winner-take-all upsert"
            )
    finally:
        _cleanup(ip)


# ── Test 2: concurrent update of an existing claim ──────────────────────────

def test_concurrent_update_of_existing_claim_keeps_one_row_and_history_consistent():
    suffix = uuid.uuid4().hex[:8]
    ip = f"192.0.2.{100 + (int(suffix[:2], 16) % 50)}"
    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
    finally:
        db.close()

    try:
        db = SessionLocal()
        try:
            upsert_single_claim(
                db, asset.id, _OBSERVER, _CLAIM_TYPE,
                {"is_datacenter": True, "company_name": "Initial Co", "asn": 1},
                datetime.now(timezone.utc),
            )
            db.commit()
        finally:
            db.close()

        results = [None, None]
        barrier = threading.Barrier(2)
        value_a = {"is_datacenter": True, "company_name": "Updated-A", "asn": 111}
        value_b = {"is_datacenter": False, "company_name": "Updated-B", "asn": 222}

        _race(asset.id, barrier, value_a, value_b, results)

        integrity_errors = [r["integrity_error"] for r in results if r["integrity_error"]]
        other_errors = [r["error"] for r in results if r["error"]]
        assert not integrity_errors, f"concurrent update raised IntegrityError: {integrity_errors!r}"
        assert not other_errors, f"unexpected error(s): {other_errors!r}"

        rows = _claim_rows(asset.id)
        assert len(rows) == 1, f"expected exactly one AssetClaim row, found {len(rows)}"
        assert rows[0].claim_value in (value_a, value_b), (
            f"surviving claim_value {rows[0].claim_value!r} matches neither thread's value"
        )

        # History bound: 1 (initial create) + at least 1 and at most 2 more.
        # Both threads change the value relative to "Initial Co", so whichever
        # applies first appends a history row for its change; the second
        # thread's read-modify-write happens under the FOR UPDATE lock taken
        # in upsert_single_claim's conflict branch, so it observes the FIRST
        # thread's already-applied value. If the second thread's value differs
        # from that (it does here — "Updated-A" != "Updated-B") it appends its
        # own history row too (3 total); it's only indistinguishable-by-value
        # from the first thread's write (impossible with these distinct
        # literals) that would make it a same-value bump. Hence the range
        # [2, 3], not a single magic number.
        count = _history_count(asset.id)
        assert 2 <= count <= 3, (
            f"expected 2 or 3 ClaimHistory rows (1 initial create + 1-2 concurrent updates), found {count}"
        )
    finally:
        _cleanup(ip)


# ── Test 3: concurrent identical-value writes add no history ───────────────

def test_concurrent_identical_value_writes_add_no_history_rows():
    suffix = uuid.uuid4().hex[:8]
    ip = f"192.0.2.{50 + (int(suffix[:2], 16) % 40)}"
    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
    finally:
        db.close()

    try:
        same_value = {"is_datacenter": True, "company_name": "Same Co", "asn": 999}
        db = SessionLocal()
        try:
            upsert_single_claim(db, asset.id, _OBSERVER, _CLAIM_TYPE, same_value, datetime.now(timezone.utc))
            db.commit()
        finally:
            db.close()

        results = [None, None]
        barrier = threading.Barrier(2)

        # Both threads write the SAME value as what's already stored —
        # _json_equal matching in upsert_single_claim means neither write is
        # a change, so neither appends a ClaimHistory row.
        _race(asset.id, barrier, dict(same_value), dict(same_value), results)

        integrity_errors = [r["integrity_error"] for r in results if r["integrity_error"]]
        other_errors = [r["error"] for r in results if r["error"]]
        assert not integrity_errors, f"concurrent identical-value write raised IntegrityError: {integrity_errors!r}"
        assert not other_errors, f"unexpected error(s): {other_errors!r}"

        rows = _claim_rows(asset.id)
        assert len(rows) == 1, f"expected exactly one AssetClaim row, found {len(rows)}"
        assert rows[0].claim_value == same_value

        count = _history_count(asset.id)
        assert count == 1, (
            f"expected exactly 1 ClaimHistory row (the initial create only — identical concurrent "
            f"writes must not append via _json_equal change-detection), found {count}"
        )
    finally:
        _cleanup(ip)


# ── Test 4: unknown observer guard (not concurrency) ────────────────────────

def test_unknown_observer_still_returns_none_without_writing():
    suffix = uuid.uuid4().hex[:8]
    ip = f"192.0.2.{10 + (int(suffix[:2], 16) % 30)}"
    unknown_observer = uuid.uuid4().hex

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)

        result = upsert_single_claim(
            db, asset.id, unknown_observer, _CLAIM_TYPE,
            {"is_datacenter": True, "company_name": "Nope", "asn": 1},
            datetime.now(timezone.utc),
        )
        db.commit()
        assert result is None, "an unseeded observer name must return None"

        rows = (
            db.query(AssetClaim)
            .filter(AssetClaim.asset_canonical_id == asset.id, AssetClaim.claim_type == _CLAIM_TYPE)
            .all()
        )
        assert not rows, f"unknown observer must not write any AssetClaim row, found {len(rows)}"
    finally:
        db.close()
        _cleanup(ip)


def _run():
    tests = [
        test_concurrent_first_write_does_not_raise_integrity_error,
        test_concurrent_update_of_existing_claim_keeps_one_row_and_history_consistent,
        test_concurrent_identical_value_writes_add_no_history_rows,
        test_unknown_observer_still_returns_none_without_writing,
    ]
    for fn in tests:
        try:
            fn()
            print(f"OK: {fn.__name__}")
        except AssertionError as exc:
            print(f"FAIL: {fn.__name__}: {exc}")
            raise SystemExit(1)
    print("ALL PASS")


if __name__ == "__main__":
    _run()
