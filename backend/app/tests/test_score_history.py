"""Unit + DB-driver coverage of score-history capture (planning#131,
temporal layer slice 1).

Two layers of test here, deliberately kept apart (mirrors
`test_hygiene_scorer.py`):

  * Band-rank derivation (`_band_rank`) and promotion detection
    (`_is_promotion`) are PURE — no DB queries inside, over plain band
    strings and bools — so those tests call them directly with no session
    at all. Band order is derived FROM `risk_scorer.BANDS` at test time
    (never a second hardcoded ordered list of band names) so these tests
    keep tracking the real vocabulary if it ever changes.
  * `capture()` itself — the DISTINCT ON prior-row lookup, the
    change-only-append rule, the promotion list it returns — genuinely
    needs a live DB, so those tests (bottom of this file) seed real
    `AssetCanonical`/`FindingCanonical` rows directly, call
    `score_history.capture(db, ...)`, and inspect the resulting
    `score_history` rows.

Run with:  python -m app.tests.test_score_history
       or: pytest app/tests/test_score_history.py
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import text

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.models.score_history import ScoreHistory
from app.services import risk_scorer, score_history

_ORDERED_BANDS = [b for b, _ in sorted(risk_scorer.BANDS.items(), key=lambda kv: kv[1][0])]


# ── helpers ──────────────────────────────────────────────────────────────

def _mk_asset(db, value: str) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=value,
        first_seen_at=now, last_seen_at=now, ignored=False, tags=[],
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _mk_finding(
    db, asset_id: uuid.UUID, fingerprint: str,
    risk_score: int | None, risk_band: str | None,
    building_velocity: bool | None = False,
    state: str = "open", verification: str | None = None,
) -> FindingCanonical:
    now = datetime.now(timezone.utc)
    row = FindingCanonical(
        id=uuid.uuid4(), asset_canonical_id=asset_id, finding_type="cve",
        source="test", fingerprint=fingerprint, severity="high",
        title=f"Test finding {fingerprint}", state=state, category="vulnerability",
        risk_score=risk_score, risk_band=risk_band, building_velocity=building_velocity,
        verification=verification, first_seen_at=now, last_seen_at=now, detail={}, tags=[],
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _cleanup(values: list[str]) -> None:
    db = SessionLocal()
    try:
        assets = db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).all()
        asset_ids = [a.id for a in assets]
        if asset_ids:
            finding_ids = [
                r[0] for r in
                db.query(FindingCanonical.id).filter(FindingCanonical.asset_canonical_id.in_(asset_ids)).all()
            ]
            if finding_ids:
                db.execute(
                    text("DELETE FROM score_history WHERE finding_canonical_id = ANY(:ids)"),
                    {"ids": finding_ids},
                )
            db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _history_rows(db, finding_id: uuid.UUID) -> list[ScoreHistory]:
    return (
        db.query(ScoreHistory)
        .filter(ScoreHistory.finding_canonical_id == finding_id)
        .order_by(ScoreHistory.scored_at)
        .all()
    )


# ── pure: band-rank derivation ──────────────────────────────────────────────

def test_band_rank_matches_risk_scorer_bands():
    """_band_rank must equal BANDS[band][0] for every real band — the ONE
    source of truth this module's docstring insists on."""
    for band, (lo, _hi) in risk_scorer.BANDS.items():
        assert score_history._band_rank(band) == lo


def test_band_rank_unrecognized_band_ranks_lowest():
    lowest_real_rank = min(lo for lo, _hi in risk_scorer.BANDS.values())
    rank = score_history._band_rank("not_a_real_band")
    assert rank < lowest_real_rank


# ── pure: promotion detection ───────────────────────────────────────────────

def test_promotion_true_for_every_adjacent_band_up_transition():
    for lower, higher in zip(_ORDERED_BANDS, _ORDERED_BANDS[1:]):
        assert score_history._is_promotion(lower, False, higher, False) is True, (lower, higher)


def test_promotion_false_for_every_adjacent_band_down_transition():
    for lower, higher in zip(_ORDERED_BANDS, _ORDERED_BANDS[1:]):
        assert score_history._is_promotion(higher, False, lower, False) is False, (higher, lower)


def test_promotion_false_for_unchanged_band():
    for band in _ORDERED_BANDS:
        assert score_history._is_promotion(band, False, band, False) is False, band


def test_promotion_true_when_velocity_starts():
    assert score_history._is_promotion("low", False, "low", True) is True


def test_promotion_false_when_velocity_already_true():
    assert score_history._is_promotion("low", True, "low", True) is False


# ── DB: capture() ────────────────────────────────────────────────────────

def test_capture_writes_baseline_and_returns_no_promotion():
    """A finding with no prior score_history row gets a baseline row on
    first capture — and a baseline is NEVER a promotion, even though this
    finding's very first band could be the worst one (module docstring:
    otherwise the first-ever run would page everyone about the whole
    backlog)."""
    suffix = uuid.uuid4().hex[:10]
    value = f"score-history-baseline-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        finding = _mk_finding(db, asset.id, "fp-1", risk_score=10, risk_band="low")

        promotions = score_history.capture(db, {finding.id}, datetime.now(timezone.utc))

        assert promotions == []
        rows = _history_rows(db, finding.id)
        assert len(rows) == 1
        assert rows[0].risk_score == 10
        assert rows[0].risk_band == "low"
        assert rows[0].building_velocity is False
    finally:
        db.close()
        _cleanup([value])


def test_capture_unchanged_recapture_writes_no_second_row():
    """The idempotence test: calling capture() again with nothing changed
    must write ZERO new rows (assert the row COUNT) and return no
    promotion — this is what makes capture() safe to call from both
    scan_executor and nightly_rescore without double-booking."""
    suffix = uuid.uuid4().hex[:10]
    value = f"score-history-idempotent-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        finding = _mk_finding(db, asset.id, "fp-1", risk_score=20, risk_band="low")

        first = score_history.capture(db, {finding.id}, datetime.now(timezone.utc))
        assert first == []
        assert len(_history_rows(db, finding.id)) == 1

        second = score_history.capture(db, {finding.id}, datetime.now(timezone.utc))
        assert second == []
        assert len(_history_rows(db, finding.id)) == 1, "unchanged re-capture must not write a second row"
    finally:
        db.close()
        _cleanup([value])


def test_capture_band_bump_writes_one_row_and_one_promotion():
    suffix = uuid.uuid4().hex[:10]
    value = f"score-history-bump-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        finding = _mk_finding(db, asset.id, "fp-1", risk_score=10, risk_band="low")

        score_history.capture(db, {finding.id}, datetime.now(timezone.utc))
        assert len(_history_rows(db, finding.id)) == 1

        finding.risk_score = 30
        finding.risk_band = "elevated"
        db.commit()

        promotions = score_history.capture(db, {finding.id}, datetime.now(timezone.utc))

        rows = _history_rows(db, finding.id)
        assert len(rows) == 2, "a band bump must write exactly one new row"
        assert len(promotions) == 1
        p = promotions[0]
        assert p.finding_canonical_id == finding.id
        assert p.asset_canonical_id == asset.id
        assert p.previous_band == "low"
        assert p.new_band == "elevated"
        assert p.previous_score == 10
        assert p.new_score == 30
        assert p.velocity_started is False
    finally:
        db.close()
        _cleanup([value])


def test_capture_score_change_inside_band_writes_row_no_promotion():
    """A score change that stays inside the same band is recorded in
    history but must NOT be reported as a promotion."""
    suffix = uuid.uuid4().hex[:10]
    value = f"score-history-intraband-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        finding = _mk_finding(db, asset.id, "fp-1", risk_score=10, risk_band="low")

        score_history.capture(db, {finding.id}, datetime.now(timezone.utc))

        finding.risk_score = 15  # still within the "low" band (1-24)
        db.commit()

        promotions = score_history.capture(db, {finding.id}, datetime.now(timezone.utc))

        rows = _history_rows(db, finding.id)
        assert len(rows) == 2, "an intra-band score change must still be recorded"
        assert rows[-1].risk_score == 15
        assert rows[-1].risk_band == "low"
        assert promotions == [], "an intra-band score change must not be reported as a promotion"
    finally:
        db.close()
        _cleanup([value])


def test_capture_skips_null_scored_findings():
    """A finding that has never been scored (risk_score/risk_band still
    NULL) is skipped entirely — nothing to record yet."""
    suffix = uuid.uuid4().hex[:10]
    value = f"score-history-nullscore-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        finding = _mk_finding(db, asset.id, "fp-1", risk_score=None, risk_band=None)

        promotions = score_history.capture(db, {finding.id}, datetime.now(timezone.utc))

        assert promotions == []
        assert _history_rows(db, finding.id) == []
    finally:
        db.close()
        _cleanup([value])


def _run():
    tests = [
        test_band_rank_matches_risk_scorer_bands,
        test_band_rank_unrecognized_band_ranks_lowest,
        test_promotion_true_for_every_adjacent_band_up_transition,
        test_promotion_false_for_every_adjacent_band_down_transition,
        test_promotion_false_for_unchanged_band,
        test_promotion_true_when_velocity_starts,
        test_promotion_false_when_velocity_already_true,
        test_capture_writes_baseline_and_returns_no_promotion,
        test_capture_unchanged_recapture_writes_no_second_row,
        test_capture_band_bump_writes_one_row_and_one_promotion,
        test_capture_score_change_inside_band_writes_row_no_promotion,
        test_capture_skips_null_scored_findings,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
