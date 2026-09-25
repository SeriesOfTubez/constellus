"""Unit coverage of the shared posture policy (planning#196 step 2) —
`app.services.posture` and its two callers,
`probe_authorisation._posture_cap` (asset-shaped) and
`probe_authorisation.authorise_discovery` (domain-shaped, new in this
step).

This is a REFACTOR pin, not a new-policy pin. Step 1 (migration 0055)
seeded `observers.noise_class` but nothing read it; step 2 wires it up to
reproduce planning#193's shipped pre-close-M&A denial set EXACTLY —
`test_seeded_observers_reproduce_planning_193s_shipped_denial_set` below is
the load-bearing assertion for that claim, checked against the LIVE seeded
`observers` table rather than a hand-copied list, so a future edit to
`OBSERVER_NOISE` or the seed data that silently changes the denial set
fails loudly here instead of drifting unnoticed.

Dev-DB caveat (same as `test_probe_authorisation.py` /
`test_scan_executor_pre_close.py`): no dedicated test database, no
rollback. Every row this file creates is synthetic, prefixed `pa196-` plus
a `uuid.uuid4().hex[:10]` suffix, and deleted by id in a `finally` block.
Domain-shaped values use `.example.test` (RFC 2606 reserved TLD), never a
real registered domain. `test_a_new_noisy_discovery_tool_is_denied_
without_touching_the_discovery_phase` writes to `authorisation_decisions`
and is therefore registered in `test_zz_decision_log_hygiene.py`'s
`_DECISION_WRITING_TESTS`.

Run with:  python -m app.tests.test_posture_policy
       or: pytest app/tests/test_posture_policy.py
"""

import uuid
from types import SimpleNamespace

from app.core.database import SessionLocal
from app.models.authorisation_decision import AuthorisationDecision
from app.models.engagement import EngagementPosture
from app.models.observer import OBSERVER_NOISE, Observer
from app.models.target import Target
from app.services import posture
from app.services import probe_authorisation as pa
from app.services.discovery import bruteforce, cert_transparency, dns_records, dns_resolve, dnsrecon, subfinder
from app.tests import _decision_log
from app.tests._engagement import cleanup_engagement, make_engagement

_DISCOVERY_MODULES = (subfinder, dns_resolve, dns_records, dnsrecon, bruteforce, cert_transparency)

# The exact planning#193 shipped denial set, restated here as a literal so
# the assertion in test 3 has something independent to compare the LIVE
# seeded table against — see that test's docstring.
_PLANNING_193_DENIAL_SET = {
    "naabu", "banner_grab", "httpx", "tlsx", "nuclei",
    "tenancy_tls", "domain_affinity", "shared_infra_verifier",
    "dnsrecon", "bruteforce",
}


# ── 1. the decision function's truth table ─────────────────────────────────

def test_observer_permitted_truth_table():
    """`posture.observer_permitted` over all four noise classes, both
    posture states, plus the fail-closed cases (`None` and an unseeded
    string) that only matter under passive-only."""
    for noise_class in OBSERVER_NOISE:
        expected_passive = noise_class in {"silent", "third_party_infra"}
        assert posture.observer_permitted(passive_only=True, noise_class=noise_class) is expected_passive, noise_class
        # Not passive-only: every noise class is permitted, unconditionally.
        assert posture.observer_permitted(passive_only=False, noise_class=noise_class) is True, noise_class

    # Fail-closed: a NULL or unseeded noise class is denied under
    # passive-only (no positive membership to grant it), but permitted
    # when posture has nothing to say at all.
    for unknown in (None, "pa196-not-a-real-noise-class"):
        assert posture.observer_permitted(passive_only=True, noise_class=unknown) is False, unknown
        assert posture.observer_permitted(passive_only=False, noise_class=unknown) is True, unknown


# ── 2. the two sets partition the vocabulary ────────────────────────────────

def test_permitted_and_denied_noise_classes_partition_the_vocabulary():
    """`PASSIVE_ONLY_DENIED_NOISE` is derived by subtraction (see
    `app.services.posture`'s module docstring) specifically so it and
    `PASSIVE_ONLY_PERMITTED_NOISE` can never drift out of partition with
    `OBSERVER_NOISE` or with each other. Assert the partition property
    directly rather than trusting the derivation."""
    union = posture.PASSIVE_ONLY_PERMITTED_NOISE | posture.PASSIVE_ONLY_DENIED_NOISE
    intersection = posture.PASSIVE_ONLY_PERMITTED_NOISE & posture.PASSIVE_ONLY_DENIED_NOISE
    assert union == OBSERVER_NOISE
    assert intersection == frozenset()


# ── 3. the load-bearing refactor property ───────────────────────────────────

def test_seeded_observers_reproduce_planning_193s_shipped_denial_set():
    """This is what makes planning#196 step 2 a REFACTOR of planning#193's
    behaviour rather than a policy change. Before step 2, the discovery
    phase and `_posture_cap` each hardcoded "deny dnsrecon and bruteforce
    outright" / "deny every asset unconditionally". After step 2, both
    compose `posture.observer_permitted` against `observers.noise_class`.
    For that substitution to be behaviour-preserving, applying the new
    noise-class rule to the LIVE 23 seeded `observers` rows must produce
    the exact same denial set planning#193 shipped: the eight `target_host`
    observers plus the two `target_infra` observers (dnsrecon, bruteforce)
    — nothing else, nothing missing.
    """
    db = SessionLocal()
    try:
        rows = db.query(Observer.name, Observer.noise_class).all()
    finally:
        db.close()
    assert len(rows) == 23, f"expected 23 seeded observers, got {len(rows)}"

    denied = {name for name, noise_class in rows if not posture.observer_permitted(passive_only=True, noise_class=noise_class)}
    assert denied == _PLANNING_193_DENIAL_SET, (
        f"denial set drifted from planning#193's shipped behaviour: "
        f"missing={_PLANNING_193_DENIAL_SET - denied}, extra={denied - _PLANNING_193_DENIAL_SET}"
    )


# ── 4. SQL and Python renderings of the predicate agree ────────────────────

def test_sql_and_python_renderings_of_the_predicate_agree():
    """The anti-drift guard for `posture.passive_only_filter()` (SQL) vs.
    `posture.is_passive_only()` (Python) — two renderings of ONE predicate,
    per that module's docstring. planning#211 turned posture into a real
    four-value enum; this fixture now covers a target in EACH of the four
    postures plus one with NO engagement at all, so "agree" is asserted
    over the whole new keyspace rather than the old boolean's two states —
    a change to only one rendering makes this fail on whichever row
    exercises the state nobody touched.
    """
    suffix = uuid.uuid4().hex[:10]
    db = SessionLocal()
    target_ids: dict[str, uuid.UUID] = {}
    engagement_ids: list[uuid.UUID] = []
    try:
        # day_0/integrated need a satisfied CHECK constraint (authorised_at
        # + authorisation_reference both non-null) — see migration 0059.
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        postures_and_auth = {
            EngagementPosture.PRE_CLOSE.value: {},
            EngagementPosture.DAY_0.value: {"authorised_at": now, "authorisation_reference": "pa196-ref"},
            EngagementPosture.INTEGRATED.value: {"authorised_at": now, "authorisation_reference": "pa196-ref"},
            EngagementPosture.ABANDONED.value: {},
        }
        for posture_value, extra in postures_and_auth.items():
            engagement = make_engagement(db, posture_value, **extra)
            engagement_ids.append(engagement.id)
            t = Target(
                id=uuid.uuid4(), type="domain",
                value=f"pa196-{posture_value}-{suffix}.example.test",
                engagement_id=engagement.id,
            )
            db.add(t)
            db.commit()
            target_ids[posture_value] = t.id

        no_engagement = Target(
            id=uuid.uuid4(), type="domain", value=f"pa196-none-{suffix}.example.test",
        )
        db.add(no_engagement)
        db.commit()
        target_ids["none"] = no_engagement.id

        all_ids = list(target_ids.values())
        matched_ids = {
            r[0] for r in db.query(Target.id)
            .filter(Target.id.in_(all_ids))
            .filter(posture.passive_only_filter())
            .all()
        }
        expected_restricting = {target_ids["pre_close"], target_ids["abandoned"]}
        assert matched_ids == expected_restricting, matched_ids

        rows_by_posture = {
            key: db.get(Target, tid) for key, tid in target_ids.items()
        }
        assert posture.is_passive_only(rows_by_posture["pre_close"]) is True
        assert posture.is_passive_only(rows_by_posture["abandoned"]) is True
        assert posture.is_passive_only(rows_by_posture["day_0"]) is False
        assert posture.is_passive_only(rows_by_posture["integrated"]) is False
        assert posture.is_passive_only(rows_by_posture["none"]) is False
        assert posture.is_passive_only(None) is False
    finally:
        ids = list(target_ids.values())
        if ids:
            db.query(Target).filter(Target.id.in_(ids)).delete(synchronize_session=False)
            db.commit()
        for eid in engagement_ids:
            cleanup_engagement(db, eid)
        db.close()


# ── 5. every discovery module declares a seeded observer slug ──────────────

def test_every_discovery_module_declares_a_seeded_observer_slug():
    """`probe_authorisation.authorise_discovery` learns which `observers`
    row describes a bare discovery module via its `OBSERVER` constant
    (planning#196 step 2, Part 4). Every module that declares one must
    declare a NON-EMPTY value that resolves to a real seeded row — an
    unseeded slug would silently deny that tool under every pre-close
    target forever (fail-closed, per `observer_permitted`'s docstring),
    which is exactly the kind of defect this guard exists to catch before
    it ships."""
    db = SessionLocal()
    try:
        seeded_names = {r[0] for r in db.query(Observer.name).all()}
    finally:
        db.close()

    for module in _DISCOVERY_MODULES:
        slug = getattr(module, "OBSERVER", None)
        assert slug, f"{module.__name__} has no OBSERVER constant"
        assert slug in seeded_names, f"{module.__name__}.OBSERVER={slug!r} is not a seeded observers.name"


# ── 6. `_posture_cap` does real work with the noise class it's handed ──────

def test_posture_cap_permits_a_pre_close_asset_for_a_silent_observer():
    """Proves the Part 2 signature change (`_posture_cap` gaining
    `noise_class`) does real work rather than just widening a signature
    nobody reads. `_posture_cap` only ever reads `canonical.id`, so a
    lightweight stand-in with just an `.id` attribute is a faithful
    substitute for a real `AssetCanonical` row here."""
    stub_id = uuid.uuid4()
    canonical = SimpleNamespace(id=stub_id)
    passive_ids = frozenset({stub_id})

    silent_cap = pa._posture_cap(
        None, scope={}, asset_ref=None, canonical=canonical,
        passive_ids=passive_ids, noise_class="silent",
    )
    assert silent_cap.allowed is True
    assert silent_cap.rule == "posture:permissive"

    noisy_cap = pa._posture_cap(
        None, scope={}, asset_ref=None, canonical=canonical,
        passive_ids=passive_ids, noise_class="target_host",
    )
    assert noisy_cap.allowed is False
    assert noisy_cap.rule == "posture:passive_only"


# ── 7. the acceptance criterion ─────────────────────────────────────────────

def test_a_new_noisy_discovery_tool_is_denied_without_touching_the_discovery_phase():
    """THE acceptance criterion for planning#196 step 2: a brand-new,
    never-before-seen discovery tool must be denied under a pre-close
    target purely by DECLARING its `noise_class` in `observers` — with
    ZERO edits to `scan_executor.py`'s discovery phase. This test proves
    the axis does real work rather than decorating a hardcoded list: it
    drives `probe_authorisation.authorise_discovery` directly against two
    throwaway `observers` rows this test invents on the spot, never wired
    into `scan_executor` at all.

    `target_row` is a bare `SimpleNamespace(engagement=...)` —
    `authorise_discovery` only ever reads `.engagement.posture`, via
    `posture.is_passive_only`, so a real `Target` row is not needed to
    exercise it here (planning#211 re-key of the old bare-boolean
    stand-in this test used before the engagement object existed).
    """
    suffix = uuid.uuid4().hex[:10]
    noisy_name = f"pa196-newtool-{suffix}"
    silent_name = f"pa196-newtool-silent-{suffix}"
    domain = f"pa196-newtool-{suffix}.example.test"
    run_id = uuid.uuid4()

    db = SessionLocal()
    noisy_id = None
    silent_id = None
    try:
        noisy = Observer(
            id=uuid.uuid4(), name=noisy_name, kind="discovery", trust="observed",
            addressing="none", noise_class="target_infra",
            description="planning#196 test fixture — throwaway noisy discovery tool, never wired into scan_executor",
        )
        silent = Observer(
            id=uuid.uuid4(), name=silent_name, kind="discovery", trust="observed",
            addressing="none", noise_class="silent",
            description="planning#196 test fixture — throwaway silent discovery tool, never wired into scan_executor",
        )
        db.add_all([noisy, silent])
        db.commit()
        noisy_id, silent_id = noisy.id, silent.id

        stub_engagement_id = uuid.uuid4()
        pre_close = SimpleNamespace(engagement=SimpleNamespace(id=stub_engagement_id, posture="pre_close"))
        ordinary = SimpleNamespace(engagement=None)

        # 1) the noisy tool is denied under the pre-close target, and a
        # decision row is written recording it.
        allowed = pa.authorise_discovery(
            db, observer_slug=noisy_name, target_row=pre_close, domain=domain, scan_run_id=run_id,
        )
        assert allowed is False

        rows = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
            .all()
        )
        assert len(rows) == 1, f"expected exactly one decision row for this run id, got {len(rows)}"
        row = rows[0]
        assert row.allowed is False
        assert row.rule_fired == "posture:passive_only"
        assert row.asset_canonical_id is None
        assert row.observer_id == noisy_id
        assert row.evidence_snapshot["scan_run_id"] == str(run_id)
        assert row.evidence_snapshot["decision_scope"] == "domain"
        assert row.evidence_snapshot["observer_noise_class"] == "target_infra"
        assert row.evidence_snapshot["engagements"] == [
            {"id": str(stub_engagement_id), "posture": "pre_close"}
        ]

        # 2) a SECOND throwaway observer, this one silent, is permitted —
        # and writes NO row (permits are never logged, per
        # `authorise_discovery`'s docstring). Row count for this run id
        # must stay at exactly 1.
        allowed_silent = pa.authorise_discovery(
            db, observer_slug=silent_name, target_row=pre_close, domain=domain, scan_run_id=run_id,
        )
        assert allowed_silent is True

        rows_after = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
            .all()
        )
        assert len(rows_after) == 1, "a permit must not write an additional decision row"

        # 3) the ordinary-target control: the SAME noisy slug is permitted
        # (and logs nothing) once posture has nothing to say.
        allowed_ordinary = pa.authorise_discovery(
            db, observer_slug=noisy_name, target_row=ordinary, domain=domain, scan_run_id=run_id,
        )
        assert allowed_ordinary is True

        rows_ordinary = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
            .all()
        )
        assert len(rows_ordinary) == 1, "the ordinary-target permit must not write an additional decision row"
    finally:
        _decision_log.cleanup_for_run(run_id)
        ids = [i for i in (noisy_id, silent_id) if i is not None]
        if ids:
            db.query(Observer).filter(Observer.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_an_undeclared_discovery_tool_is_denied_fail_closed():
    """The `observer_slug=None` path — a discovery module that ships
    without an `OBSERVER` constant at all.

    `scan_executor._run_pipeline`'s `_posture_permits` closure reads the
    slug with `getattr(module, "OBSERVER", None)` rather than
    `module.OBSERVER`, deliberately: a tool that forgets to declare one
    must not raise `AttributeError` mid-scan. That choice is only safe if
    the `None` it produces is then DENIED under passive-only rather than
    waved through, so this pins the other half of it. The test above
    covers an unresolvable slug (a string with no `observers` row); this
    covers no slug at all, which is a different branch in
    `authorise_discovery` (it never reaches the query) and the one an
    actual forgotten constant would take.

    The ordinary-target half matters just as much: an undeclared tool must
    be unaffected when posture has nothing to say, or this fail-closed
    default would silently disable any new discovery tool for every target
    until someone noticed.
    """
    domain = f"pa196-undeclared-{uuid.uuid4().hex[:10]}.example.test"
    run_id = uuid.uuid4()
    db = SessionLocal()
    try:
        assert pa.authorise_discovery(
            db, observer_slug=None,
            target_row=SimpleNamespace(engagement=SimpleNamespace(id=uuid.uuid4(), posture="pre_close")),
            domain=domain, scan_run_id=run_id,
        ) is False, "a tool that declares no OBSERVER must be denied under passive-only"

        rows = (
            db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
            .all()
        )
        assert len(rows) == 1, f"the denial must still be logged, got {len(rows)} row(s)"
        assert rows[0].observer_id is None, "no observers row resolved, so observer_id is NULL"
        assert rows[0].rule_fired == "posture:passive_only"
        assert rows[0].evidence_snapshot["observer_noise_class"] is None
        assert rows[0].evidence_snapshot["decision_scope"] == "domain"

        assert pa.authorise_discovery(
            db, observer_slug=None, target_row=SimpleNamespace(engagement=None),
            domain=domain, scan_run_id=run_id,
        ) is True, "an undeclared tool must be unaffected when posture has nothing to say"
    finally:
        _decision_log.cleanup_for_run(run_id)
        db.close()


def _run():
    tests = [
        test_observer_permitted_truth_table,
        test_permitted_and_denied_noise_classes_partition_the_vocabulary,
        test_seeded_observers_reproduce_planning_193s_shipped_denial_set,
        test_sql_and_python_renderings_of_the_predicate_agree,
        test_every_discovery_module_declares_a_seeded_observer_slug,
        test_posture_cap_permits_a_pre_close_asset_for_a_silent_observer,
        test_a_new_noisy_discovery_tool_is_denied_without_touching_the_discovery_phase,
        test_an_undeclared_discovery_tool_is_denied_fail_closed,
    ]
    for fn in tests:
        fn()
        print(f"ok  {fn.__name__}")
    print("all passed")


if __name__ == "__main__":
    _run()
