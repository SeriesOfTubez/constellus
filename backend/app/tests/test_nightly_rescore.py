"""DB-driver coverage of the nightly full-scope re-scoring job
(planning#131, temporal layer slice 1).

`nightly_rescore.run()` operates over the FULL `findings_canonical` scope
(every `state == "open"` row in the database), not a scan's touched set —
unlike `test_hygiene_scorer.py`'s pure/DB split, there is no pure layer
here worth separating out (the module has no standalone computation; it's
entirely a driver over `risk_scorer.score_scan_findings` +
`score_history.capture`, both already covered by their own test files).
Every test below therefore asserts on the SPECIFIC assets/findings it
creates (their own risk_score/risk_band, their own score_history row
count, their own presence/absence in a captured dispatch call) rather than
on `run()`'s aggregate stats numbers — the job legitimately processes
whatever else happens to be `state == "open"` in the database at the same
time, so aggregate counts are not a safe thing to pin in a shared-DB test
(same reasoning `test_hygiene_scorer.py::test_run_is_batched` uses a bound
rather than an exact query count).

`notification_dispatcher.dispatch_promotions` is monkeypatched (raw
attribute assignment, restored by conftest.py's autouse fixture — see
`_GUARDED_MODULES`) to a capturing stub in the promotion-related tests, so
this file can assert exactly which findings nightly_rescore decided to
dispatch without depending on any notification connector being configured.

Requires a live DB connection with migration 0046 applied.

Run with:  python -m app.tests.test_nightly_rescore
       or: pytest app/tests/test_nightly_rescore.py
"""

import uuid
from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.finding_canonical import FindingCanonical
from app.models.notification_rule import NotificationRule
from app.models.score_history import ScoreHistory
from app.services import nightly_rescore, notification_dispatcher, score_history


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
    state: str = "open", verification: str | None = None,
    cve_id: str | None = None, cvss_score: float | None = None, kev: bool | None = None,
) -> FindingCanonical:
    now = datetime.now(timezone.utc)
    row = FindingCanonical(
        id=uuid.uuid4(), asset_canonical_id=asset_id, finding_type="cve",
        source="test", fingerprint=fingerprint, severity="high",
        title=f"Test finding {fingerprint}", state=state, category="vulnerability",
        cve_id=cve_id, cvss_score=cvss_score, kev=kev,
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
                db.query(ScoreHistory).filter(ScoreHistory.finding_canonical_id.in_(finding_ids)).delete(synchronize_session=False)
            db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(asset_ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _mk_state(db, asset_id: uuid.UUID, estate: str | None = None) -> None:
    db.add(AssetState(
        asset_canonical_id=asset_id, estate=estate, open_ports=[],
        attributes={}, projected_at=datetime.now(timezone.utc),
    ))
    db.commit()


def _history_count(db, finding_id: uuid.UUID) -> int:
    return db.query(ScoreHistory).filter(ScoreHistory.finding_canonical_id == finding_id).count()


# ── full-scope scoring ───────────────────────────────────────────────────

def test_run_scores_findings_across_assets_with_no_scan_run():
    """No ScanRun ever touched these findings — run() must still score and
    history-capture them, proving scope is the full open-finding table,
    not a scan's touched set."""
    suffix = uuid.uuid4().hex[:10]
    value_a = f"nightly-scope-a-{suffix}"
    value_b = f"nightly-scope-b-{suffix}"
    db = SessionLocal()
    try:
        asset_a = _mk_asset(db, value_a)
        asset_b = _mk_asset(db, value_b)
        finding_a = _mk_finding(db, asset_a.id, "fp-1")
        finding_b = _mk_finding(db, asset_b.id, "fp-1")

        nightly_rescore.run(db)

        db.refresh(finding_a)
        db.refresh(finding_b)
        assert finding_a.risk_score is not None
        assert finding_a.risk_band is not None
        assert finding_b.risk_score is not None
        assert finding_b.risk_band is not None
        assert _history_count(db, finding_a.id) == 1
        assert _history_count(db, finding_b.id) == 1
    finally:
        db.close()
        _cleanup([value_a, value_b])


def test_resolved_findings_are_not_rescored():
    suffix = uuid.uuid4().hex[:10]
    value = f"nightly-resolved-{suffix}"
    db = SessionLocal()
    try:
        asset = _mk_asset(db, value)
        finding = _mk_finding(db, asset.id, "fp-1", state="resolved")

        nightly_rescore.run(db)

        db.refresh(finding)
        assert finding.risk_score is None, "a resolved finding must never be scored by the nightly job"
        assert finding.risk_band is None
        assert _history_count(db, finding.id) == 0
    finally:
        db.close()
        _cleanup([value])


# ── the issue's own verification case: forced band promotion ────────────────

def test_run_detects_promotion_on_forced_band_change():
    """Run once to establish a baseline, mutate KEV directly in the DB
    (the issue's own scenario) to force a band promotion, run again, and
    assert exactly one promotion is returned for this finding and a second
    history row exists."""
    suffix = uuid.uuid4().hex[:10]
    value = f"nightly-promo-{suffix}"
    db = SessionLocal()
    captured: list = []
    notification_dispatcher.dispatch_promotions = lambda promotions: captured.append(list(promotions))
    try:
        asset = _mk_asset(db, value)
        finding = _mk_finding(db, asset.id, "fp-1", cve_id="CVE-2024-90001", cvss_score=5.0, kev=False)

        nightly_rescore.run(db)
        db.refresh(finding)
        assert finding.risk_band == "elevated", finding.risk_band  # cvss 5.0, no exploitation signal
        assert _history_count(db, finding.id) == 1

        finding.kev = True  # CISA KEV addition — HARD imminent trigger
        db.commit()

        nightly_rescore.run(db)

        db.refresh(finding)
        assert finding.risk_band == "imminent_compromise", finding.risk_band
        assert _history_count(db, finding.id) == 2, "the promotion must write exactly one new row"

        dispatched_ids = {p.finding_canonical_id for call in captured for p in call}
        assert finding.id in dispatched_ids, "the forced promotion must be dispatched"
    finally:
        db.close()
        _cleanup([value])


# ── verification exclusion ───────────────────────────────────────────────

def test_rejected_shared_infra_finding_rescored_but_not_dispatched():
    """A rejected_shared_infra finding IS re-scored (so its score stays
    correct if verification is later cleared) but must never appear in the
    dispatched promotion list — while an ordinary finding promoted in the
    same run DOES appear, proving the exclusion is selective, not a
    dispatch-never-fires artifact."""
    suffix = uuid.uuid4().hex[:10]
    value_excluded = f"nightly-excluded-{suffix}"
    value_normal = f"nightly-normal-{suffix}"
    db = SessionLocal()
    captured: list = []
    notification_dispatcher.dispatch_promotions = lambda promotions: captured.append(list(promotions))
    try:
        asset_excluded = _mk_asset(db, value_excluded)
        asset_normal = _mk_asset(db, value_normal)
        excluded_finding = _mk_finding(
            db, asset_excluded.id, "fp-1",
            verification="rejected_shared_infra",
            cve_id="CVE-2024-90002", cvss_score=5.0, kev=False,
        )
        normal_finding = _mk_finding(
            db, asset_normal.id, "fp-1",
            cve_id="CVE-2024-90003", cvss_score=5.0, kev=False,
        )

        nightly_rescore.run(db)  # baseline pass — both start at "elevated"
        db.refresh(excluded_finding)
        db.refresh(normal_finding)
        assert excluded_finding.risk_band == "elevated"
        assert normal_finding.risk_band == "elevated"

        excluded_finding.kev = True
        normal_finding.kev = True
        db.commit()

        nightly_rescore.run(db)

        db.refresh(excluded_finding)
        db.refresh(normal_finding)
        assert excluded_finding.risk_band == "imminent_compromise", "must still be re-scored"
        assert normal_finding.risk_band == "imminent_compromise"

        dispatched_ids = {p.finding_canonical_id for call in captured for p in call}
        assert excluded_finding.id not in dispatched_ids, "rejected_shared_infra must never be dispatched"
        assert normal_finding.id in dispatched_ids, "an ordinary finding's promotion must still be dispatched"
    finally:
        db.close()
        _cleanup([value_excluded, value_normal])


def test_promotion_on_not_ours_asset_is_suppressed():
    """A promotion on an asset whose estate is `not_ours` must not page
    anyone, even when the finding's own `verification` is NULL.

    This is the second, independent ownership gate
    (`notification_dispatcher._drop_not_ours`) rather than the
    finding-level `EXCLUDED_VERIFICATIONS` filter the test above covers.
    They close different routes to `estate = "not_ours"` and neither
    subsumes the other: `rejected_shared_infra` stamps BOTH the asset
    estate and the finding, so the filter above catches it — but a
    `third_party_dependency` claim (a captured CNAME boundary target,
    planning#147) sets the estate on a NAME asset, and
    `shared_infra_verifier.verify_findings` only ever classifies
    `asset_type == "ip_address"`, so findings there keep
    `verification = NULL` and sail straight through. `verification=None`
    below is the whole point of the test — it reproduces exactly that
    shape.

    Asserts on `_drop_not_ours` directly rather than through
    `dispatch_promotions`, because the promotion tests in this file stub
    `dispatch_promotions` out wholesale (see the module docstring) and
    would therefore bypass the very gate under test. The `not_ours` estate
    is set straight onto `asset_state` rather than by emitting a
    `third_party_dependency` claim and projecting it: the gate reads
    `claims_query.surface()`, which reads that column, so this exercises
    the real predicate regardless of which route wrote it.

    `ours_finding` is the positive control — without it, a bug that
    dropped every promotion would pass this test silently.
    """
    suffix = uuid.uuid4().hex[:10]
    value_third_party = f"rescore-notours-{suffix}"
    value_ours = f"rescore-ours-{suffix}"
    db = SessionLocal()
    try:
        asset_third_party = _mk_asset(db, value_third_party)
        asset_ours = _mk_asset(db, value_ours)
        _mk_state(db, asset_third_party.id, estate="not_ours")
        _mk_state(db, asset_ours.id, estate="claimed_ours")

        not_ours_finding = _mk_finding(
            db, asset_third_party.id, "fp-1",
            verification=None,  # never stamped — the hole this gate closes
            cve_id="CVE-2024-90004", cvss_score=5.0, kev=False,
        )
        ours_finding = _mk_finding(
            db, asset_ours.id, "fp-1",
            verification=None,
            cve_id="CVE-2024-90005", cvss_score=5.0, kev=False,
        )

        kept = notification_dispatcher._drop_not_ours(db, [not_ours_finding, ours_finding])
        kept_ids = {f.id for f in kept}

        assert not_ours_finding.id not in kept_ids, (
            "a promotion on a not_ours asset must be suppressed even with verification=NULL"
        )
        assert ours_finding.id in kept_ids, "an owned asset's promotion must still be dispatched"
    finally:
        db.close()
        _cleanup([value_third_party, value_ours])


def test_unknown_estate_still_dispatches():
    """`unknown` (no ownership signal at all) is NOT `not_ours` and must
    still page — only an affirmative `not_ours` suppresses.

    Deliberately the opposite asymmetry from hygiene scoring, where
    unknown ranks WORST of all. Both are right: for hygiene, "nobody is
    watching this" is the finding. For notification, silence is not a
    verdict — an asset nobody has established isn't ours should still
    reach a human. Pinning it here so a future edit doesn't "tidy" unknown
    in with not_ours and quietly mute the majority of the estate, since
    `estate` is NULL for any asset with no ownership signal.
    """
    suffix = uuid.uuid4().hex[:10]
    value_no_state = f"rescore-nostate-{suffix}"
    value_null_estate = f"rescore-nullestate-{suffix}"
    db = SessionLocal()
    try:
        asset_no_state = _mk_asset(db, value_no_state)          # no asset_state row at all
        asset_null_estate = _mk_asset(db, value_null_estate)
        _mk_state(db, asset_null_estate.id, estate=None)        # row exists, estate NULL

        f_no_state = _mk_finding(db, asset_no_state.id, "fp-1", cve_id="CVE-2024-90006", cvss_score=5.0)
        f_null_estate = _mk_finding(db, asset_null_estate.id, "fp-1", cve_id="CVE-2024-90007", cvss_score=5.0)

        kept_ids = {f.id for f in notification_dispatcher._drop_not_ours(db, [f_no_state, f_null_estate])}

        assert f_no_state.id in kept_ids, "no asset_state row -> unknown, not not_ours"
        assert f_null_estate.id in kept_ids, "NULL estate -> unknown, not not_ours"
    finally:
        db.close()
        _cleanup([value_no_state, value_null_estate])


def test_dispatch_promotions_actually_applies_the_not_ours_gate():
    """End-to-end through `_dispatch_promotions`, all the way to what a
    connector would be handed.

    The two tests above call `_drop_not_ours` directly, which proves the
    predicate is right but NOT that anything calls it — deleting the one
    line that wires it into `_dispatch_promotions` would leave both of them
    passing while the hole reopened. This test is what pins the wiring:
    it stubs only `_enabled_notification_connectors` (so no real
    notification connector needs configuring) and asserts on the rendered
    body the fake connector receives.
    """
    suffix = uuid.uuid4().hex[:10]
    value_not_ours = f"rescore-e2e-notours-{suffix}"
    value_ours = f"rescore-e2e-ours-{suffix}"
    rule_name = f"test-promotions-{suffix}"

    sent: list[dict] = []

    class _CapturingConnector:
        def send(self, subject, body_text, recipients, config, body_html=None):
            sent.append({"subject": subject, "text": body_text, "html": body_html})
            return True

    notification_dispatcher._enabled_notification_connectors = (
        lambda db: [("test-connector", _CapturingConnector(), {})]
    )

    db = SessionLocal()
    rule = NotificationRule(
        id=uuid.uuid4(), name=rule_name, enabled=True,
        severity_threshold="high", categories=[], recipients=["alerts@example.com"],
    )
    db.add(rule)
    db.commit()
    try:
        asset_not_ours = _mk_asset(db, value_not_ours)
        asset_ours = _mk_asset(db, value_ours)
        _mk_state(db, asset_not_ours.id, estate="not_ours")
        _mk_state(db, asset_ours.id, estate="claimed_ours")

        f_not_ours = _mk_finding(db, asset_not_ours.id, "fp-1", cve_id="CVE-2024-90008", cvss_score=5.0)
        f_ours = _mk_finding(db, asset_ours.id, "fp-1", cve_id="CVE-2024-90009", cvss_score=5.0)

        promotions = [
            score_history.Promotion(
                finding_canonical_id=f.id, asset_canonical_id=f.asset_canonical_id,
                previous_band="elevated", new_band="high",
                previous_score=30, new_score=60, velocity_started=False,
            )
            for f in (f_not_ours, f_ours)
        ]

        notification_dispatcher._dispatch_promotions(db, promotions)

        assert sent, "the capturing connector should have received one send"
        body = " ".join(m["text"] + (m["html"] or "") for m in sent)
        assert "CVE-2024-90009" in body, "the owned asset's promotion must reach the connector"
        assert "CVE-2024-90008" not in body, (
            "a not_ours asset's promotion reached the connector — the gate is not wired in"
        )
    finally:
        db.query(NotificationRule).filter(NotificationRule.id == rule.id).delete(synchronize_session=False)
        db.commit()
        db.close()
        _cleanup([value_not_ours, value_ours])


def test_new_finding_dispatch_applies_the_not_ours_gate_too():
    """The NEW-FINDING path (`_dispatch`) applies the same asset-level gate
    as the promotion path.

    Both notification channels must answer "is this asset ours" the same
    way; two channels with different answers is the divergence this gate
    exists to remove. `_dispatch` shipped before the gate existed and
    carried the same hole — a new finding on a captured CNAME boundary
    target (`verification` never stamped, because
    `shared_infra_verifier.verify_findings` only classifies
    `asset_type == "ip_address"`) would page someone about infrastructure
    we observed falls outside every declared target domain.

    Same fake-connector shape as the promotion test above, against
    `_dispatch` instead. `ours_finding` is again the positive control.
    """
    suffix = uuid.uuid4().hex[:10]
    value_not_ours = f"newfinding-notours-{suffix}"
    value_ours = f"newfinding-ours-{suffix}"
    rule_name = f"test-newfindings-{suffix}"

    sent: list[dict] = []

    class _CapturingConnector:
        def send(self, subject, body_text, recipients, config, body_html=None):
            sent.append({"subject": subject, "text": body_text, "html": body_html})
            return True

    notification_dispatcher._enabled_notification_connectors = (
        lambda db: [("test-connector", _CapturingConnector(), {})]
    )

    db = SessionLocal()
    rule = NotificationRule(
        id=uuid.uuid4(), name=rule_name, enabled=True,
        severity_threshold="high", categories=[], recipients=["alerts@example.com"],
    )
    db.add(rule)
    db.commit()
    try:
        asset_not_ours = _mk_asset(db, value_not_ours)
        asset_ours = _mk_asset(db, value_ours)
        _mk_state(db, asset_not_ours.id, estate="not_ours")
        _mk_state(db, asset_ours.id, estate="claimed_ours")

        f_not_ours = _mk_finding(db, asset_not_ours.id, "fp-1", cve_id="CVE-2024-90010", cvss_score=5.0)
        f_ours = _mk_finding(db, asset_ours.id, "fp-1", cve_id="CVE-2024-90011", cvss_score=5.0)

        notification_dispatcher._dispatch(db, [f_not_ours.id, f_ours.id])

        assert sent, "the capturing connector should have received one send"
        body = " ".join(m["text"] + (m["html"] or "") for m in sent)
        assert "CVE-2024-90011" in body, "the owned asset's new finding must reach the connector"
        assert "CVE-2024-90010" not in body, (
            "a not_ours asset's new finding reached the connector — the gate is not wired "
            "into the new-finding path"
        )
    finally:
        db.query(NotificationRule).filter(NotificationRule.id == rule.id).delete(synchronize_session=False)
        db.commit()
        db.close()
        _cleanup([value_not_ours, value_ours])


def _run():
    tests = [
        test_run_scores_findings_across_assets_with_no_scan_run,
        test_resolved_findings_are_not_rescored,
        test_run_detects_promotion_on_forced_band_change,
        test_rejected_shared_infra_finding_rescored_but_not_dispatched,
        test_promotion_on_not_ours_asset_is_suppressed,
        test_unknown_estate_still_dispatches,
        test_dispatch_promotions_actually_applies_the_not_ours_gate,
        test_new_finding_dispatch_applies_the_not_ours_gate_too,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
