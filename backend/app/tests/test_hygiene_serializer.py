"""Serializer coverage for the asset hygiene surface (planning#130, L2 —
issue #151).

`hygiene_scorer.scores_by_asset` / `hygiene_scorer.scanned_by_asset` are the
two new batched read-side helpers `app.api.assets` calls into; `_serialize_asset`
is where their results land on the wire as `hygiene_score` / `hygiene_band` /
`scanned`. This file pins the serializer contract directly (import
`_serialize_asset` and the batched helpers, seed rows by hand, assert on the
returned dict) — the same direct-seeding style as `test_claims_query.py` and
`test_serializer_bridge.py`, since the point here is pinning behaviour at the
serializer boundary, not re-proving the scorer's own dimension logic (that's
`test_hygiene_scorer.py`'s job).

Run with:  python -m app.tests.test_hygiene_serializer
       or: pytest app/tests/test_hygiene_serializer.py
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import event

from app.api.assets import _serialize_asset, load_bridge_sources
from app.core.database import SessionLocal, engine
from app.models.asset_canonical import AssetCanonical
from app.models.asset_hygiene_score import AssetHygieneScore
from app.models.claim import AssetClaim
from app.models.observer import Observer
from app.services import hygiene_scorer


# ── helpers ──────────────────────────────────────────────────────────────

def _mk_asset(db, value: str, asset_type: str = "ip_address") -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type=asset_type, value=value,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _observer_id(db, name: str) -> uuid.UUID:
    return db.query(Observer).filter(Observer.name == name).one().id


def _add_claim(db, asset_id: uuid.UUID, observer_name: str, claim_type: str) -> None:
    now = datetime.now(timezone.utc)
    db.add(AssetClaim(
        asset_canonical_id=asset_id,
        observer_id=_observer_id(db, observer_name),
        claim_type=claim_type,
        claim_value={},
        evidence={},
        first_observed_at=now,
        last_observed_at=now,
    ))
    db.commit()


def _mk_score(db, asset_id: uuid.UUID, score: int = 42, band: str = "fair") -> None:
    db.add(AssetHygieneScore(
        asset_canonical_id=asset_id, score=score, band=band,
        dimensions={"coverage": {"grade": "unknown", "score": 0, "reason_codes": [], "detail": "x"}},
        computed_at=datetime.now(timezone.utc),
    ))
    db.commit()


def _serialize(db, row: AssetCanonical) -> dict:
    """Run the real serializer for one row via the same batched helpers the
    API endpoints call — `hygiene`/`scanned` come from a real query, not a
    hand-built stand-in, so this exercises the actual read path."""
    bridge_sources = load_bridge_sources(db, [row.id])
    scores = hygiene_scorer.scores_by_asset(db, [row.id])
    scanned = hygiene_scorer.scanned_by_asset(db, [row.id])
    return _serialize_asset(
        row, None, bridge_sources.get(row.id), None,
        scores.get(row.id), scanned.get(row.id, False),
    )


def _cleanup(values: list[str]) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(AssetClaim).filter(AssetClaim.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
            db.query(AssetHygieneScore).filter(AssetHygieneScore.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _count_queries(fn) -> int:
    """Number of statements sent to the DBAPI cursor while `fn()` runs —
    same `before_cursor_execute` listener technique as
    `test_hygiene_scorer.py::_count_queries`, reimplemented locally per this
    test suite's own self-contained-helpers convention."""
    count = 0

    def _listener(conn, cursor, statement, parameters, context, executemany):
        nonlocal count
        count += 1

    event.listen(engine, "before_cursor_execute", _listener)
    try:
        fn()
    finally:
        event.remove(engine, "before_cursor_execute", _listener)
    return count


# ── hygiene_score / hygiene_band: top-level, reflect the stored row ────────

def test_hygiene_fields_are_top_level_and_reflect_stored_row():
    suffix = uuid.uuid4().hex[:10]
    value = f"hygsz-scored-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        _mk_score(db, asset.id, score=42, band="fair")

        result = _serialize(db, asset)

        assert result["hygiene_score"] == 42, result
        assert result["hygiene_band"] == "fair", result
    finally:
        db.close()
        _cleanup([value])


def test_no_score_row_serializes_both_fields_null():
    """0 is a real score meaning 'worst'; null means 'not scored'.
    Conflating them is the bug this test guards — an unscored asset must
    come back `null`, never `0` and never an omitted key."""
    suffix = uuid.uuid4().hex[:10]
    value = f"hygsz-unscored-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        # deliberately no AssetHygieneScore row

        result = _serialize(db, asset)

        assert "hygiene_score" in result and result["hygiene_score"] is None, result
        assert "hygiene_band" in result and result["hygiene_band"] is None, result
    finally:
        db.close()
        _cleanup([value])


# ── asset_metadata is unchanged by this slice ───────────────────────────────

def test_asset_metadata_does_not_gain_a_hygiene_key():
    """The bridged `asset_metadata` dict is a byte-compatible bridge to the
    dropped `metadata` column (metadata_bridge.py), pinned against a seeded
    payload by test_serializer_bridge.py — hygiene must stay top-level only,
    never folded in here, even when the asset has a real score row."""
    suffix = uuid.uuid4().hex[:10]
    value = f"hygsz-metadata-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        _mk_score(db, asset.id, score=10, band="critical")

        result = _serialize(db, asset)

        assert "hygiene_score" not in result["asset_metadata"], result["asset_metadata"]
        assert "hygiene_band" not in result["asset_metadata"], result["asset_metadata"]
        assert not any("hygiene" in str(k).lower() for k in result["asset_metadata"]), result["asset_metadata"]
    finally:
        db.close()
        _cleanup([value])


# ── scanned ──────────────────────────────────────────────────────────────

def test_scanned_false_with_only_observation_claim():
    suffix = uuid.uuid4().hex[:10]
    value = f"hygsz-onlyobs-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        _add_claim(db, asset.id, "naabu", "observation")

        result = _serialize(db, asset)

        assert result["scanned"] is False, result
    finally:
        db.close()
        _cleanup([value])


def test_scanned_true_once_any_other_claim_type_exists():
    suffix = uuid.uuid4().hex[:10]
    value = f"hygsz-realclaim-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        _add_claim(db, asset.id, "naabu", "observation")
        _add_claim(db, asset.id, "naabu", "port_observation")

        result = _serialize(db, asset)

        assert result["scanned"] is True, result
    finally:
        db.close()
        _cleanup([value])


def test_scanned_false_with_no_claims_at_all():
    suffix = uuid.uuid4().hex[:10]
    value = f"hygsz-noclaims-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        # no claims of any kind

        result = _serialize(db, asset)

        assert result["scanned"] is False, result
    finally:
        db.close()
        _cleanup([value])


# ── batching: bounded query count regardless of N ───────────────────────────

def test_list_path_batched_helpers_stay_bounded():
    """`scores_by_asset` + `scanned_by_asset` together must not scale with
    the number of assets — seed a handful, call both plus the sources
    loader in one wrapped fn (mirroring what list_assets actually does),
    and assert the query count is a small constant, not one-per-asset."""
    suffix = uuid.uuid4().hex[:10]
    values = [f"hygsz-batch-{suffix}-{i}" for i in range(8)]
    db = SessionLocal()
    try:
        assets = [_mk_asset(db, v) for v in values]
        for i, a in enumerate(assets):
            if i % 2 == 0:
                _mk_score(db, a.id, score=i * 10, band="fair")
            _add_claim(db, a.id, "naabu", "observation")
            if i % 3 == 0:
                _add_claim(db, a.id, "naabu", "port_observation")

        ids = [a.id for a in assets]

        def _load_all():
            load_bridge_sources(db, ids)
            hygiene_scorer.scores_by_asset(db, ids)
            hygiene_scorer.scanned_by_asset(db, ids)

        query_count = _count_queries(_load_all)

        assert query_count < 10, (
            f"expected a small bounded query count for {len(ids)} assets across "
            f"3 batched helpers; got {query_count}"
        )
    finally:
        db.close()
        _cleanup(values)


def _run():
    tests = [
        test_hygiene_fields_are_top_level_and_reflect_stored_row,
        test_no_score_row_serializes_both_fields_null,
        test_asset_metadata_does_not_gain_a_hygiene_key,
        test_scanned_false_with_only_observation_claim,
        test_scanned_true_once_any_other_claim_type_exists,
        test_scanned_false_with_no_claims_at_all,
        test_list_path_batched_helpers_stay_bounded,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
