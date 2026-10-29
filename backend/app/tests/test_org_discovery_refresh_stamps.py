"""Rolling re-discovery: refresh stamps, lookup outcomes, eligible roots (planning#277 S6b step a).

Offline. The pDNS lookup is reached through its TRANSPORT (`hc.connector_get`)
and the limiter (`hc._spend_reverse_ip_budget`), the RIR collectors through
the runner's two seams. Every outcome case also asserts the stub WAS reached.
Synthetic names and RFC 5737 addresses only.

Run with:  scripts/test.sh app/tests/test_org_discovery_refresh_stamps.py
"""

import dataclasses
import itertools
import logging
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import ClaimHistory
from app.models.engagement import Engagement
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate
from app.services import hosting_classifier as hc
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import generators, runner
from app.services.org_discovery.domain_facts import DomainFacts
from app.tests._org_world import World, hexid
from app.tests.test_org_discovery_schema import _claimed, _insert_candidate, _rejected


# RFC 3849 documentation addresses from a counter, not `_ip()`: the
# IPv4 pool is within a handful of draws of exhaustion in a full run.
_ip_counter = itertools.count(1)


def _ip() -> str:
    return f"2001:db8:277:6::{next(_ip_counter):x}"


@pytest.fixture
def w():
    world = World()
    assets: list[uuid.UUID] = []
    world.stamp_assets = assets
    try:
        yield world
    finally:
        world.close()
        db = SessionLocal()
        try:
            if assets:
                db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(assets)).delete(synchronize_session=False)
                db.query(AssetCanonical).filter(AssetCanonical.id.in_(assets)).delete(synchronize_session=False)
                db.commit()
        finally:
            db.close()


def _dom(tag="") -> str:
    return f"stamp-{tag}{hexid()}.fabrikam.com"


def _claimed_domain(w, root, value=None) -> uuid.UUID:
    return _insert_candidate(w.db, root.id, value=value or _dom("c"), **_claimed(root.id))


def _row(cid) -> ScopeCandidate:
    db = SessionLocal()
    try:
        row = db.get(ScopeCandidate, cid)
        db.expunge(row)
        return row
    finally:
        db.close()


def _root_row(rid) -> OrgEntity:
    db = SessionLocal()
    try:
        row = db.get(OrgEntity, rid)
        db.expunge(row)
        return row
    finally:
        db.close()


def _seed_ip(w, domain, ip):
    """The claimed domain's A record and its ip_address asset (no cached claim)."""
    now = datetime.now(timezone.utc)
    for kw in (
        dict(asset_type="dns_record", value=domain, record_type="A", content=ip),
        dict(asset_type="ip_address", value=ip),
    ):
        row = AssetCanonical(id=uuid.uuid4(), first_seen_at=now, last_seen_at=now, **kw)
        w.db.add(row)
        w.db.commit()
        w.stamp_assets.append(row.id)


class Transport:
    """Replaces `hc.connector_get`: counts calls, answers `payload` or raises."""

    def __init__(self, payload=None, raises=False):
        self.calls = 0
        self.payload = payload if payload is not None else {"count": 0, "size": 0, "limit": 100, "offset": 0, "data": []}
        self.raises = raises

    def __call__(self, url, params=None, timeout=None):
        self.calls += 1
        if self.raises:
            raise RuntimeError("pdns down")
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: self.payload, text="")


def _limiter(monkeypatch, allow: bool):
    asked = {"n": 0}

    def spend():
        asked["n"] += 1
        return allow

    monkeypatch.setattr(hc, "_spend_reverse_ip_budget", spend)
    return asked


# ── due_clause ──────────────────────────────────────────────────────────────


def test_due_clause_against_real_rows(w):
    root = w.ours()
    now = datetime.now(timezone.utc)
    cases = {
        "null": (None, False, True),
        "ok_6d": (now - timedelta(days=6), False, False),
        "ok_8d": (now - timedelta(days=8), False, True),
        "failed_2h": (now - timedelta(hours=2), True, False),
        "failed_25h": (now - timedelta(hours=25), True, True),
    }
    ids = {}
    for name, (at, failed, _) in cases.items():
        ids[name] = _insert_candidate(
            w.db, root.id, value=_dom(name.replace("_", "")), rediscovered_at=at, rediscovery_failed=failed,
        )
    due = set(w.db.execute(
        select(ScopeCandidate.id).where(
            ScopeCandidate.root_entity_id == root.id,
            runner.due_clause(ScopeCandidate.rediscovered_at, ScopeCandidate.rediscovery_failed, now),
        )
    ).scalars())
    assert {n for n, i in ids.items() if i in due} == {n for n, c in cases.items() if c[2]}
    assert len(ids) == 5  # every case was inserted


# ── the CHECK ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("col", ["rediscovery_failed", "reverify_failed"])
def test_candidate_failed_flag_without_a_time_is_refused(w, col):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id, value=_dom("ck"))
    with pytest.raises(IntegrityError) as exc:
        w.db.execute(update(ScopeCandidate).where(ScopeCandidate.id == cid).values({col: True}))
        w.db.commit()
    w.db.rollback()
    assert f"ck_scope_candidates_{col}_needs_time" in str(exc.value)


def test_root_failed_flag_without_a_time_is_refused(w):
    root = w.ours()
    with pytest.raises(IntegrityError) as exc:
        w.db.execute(update(OrgEntity).where(OrgEntity.id == root.id).values(rediscovery_failed=True))
        w.db.commit()
    w.db.rollback()
    assert "ck_org_entities_rediscovery_failed_needs_time" in str(exc.value)


# ── stamping a CLAIMED row (the 0087 guard allows it) ───────────────────────


def test_stamping_a_claimed_row_succeeds(w):
    root = w.ours()
    cid = _claimed_domain(w, root)
    runner._stamp(ScopeCandidate, cid, "rediscovered_at", "rediscovery_failed", True)
    row = _row(cid)
    assert row.status == "claimed" and row.rediscovered_at is not None and row.rediscovery_failed is True


# ── refresh_claimed_domain ──────────────────────────────────────────────────


def _stub_rir(monkeypatch, *, budget=False, fetch_failed=0, raises=False):
    """Replace the ARIN seam; returns the call recorder."""
    calls: list[str] = []

    def rir(db, domain, fresh_since=None):
        calls.append(domain)
        if raises:
            raise RuntimeError("rir exploded")
        return dataclasses.replace(
            runner.arin.ArinCollection(domain=domain, pocs_listed=0, pocs_truncated=False, pocs_not_exact=0, matched=()),
            budget_exhausted=budget, fetch_failed=fetch_failed,
        )

    monkeypatch.setattr(runner, "_rir_collect", rir)
    return calls


def test_refresh_claimed_domain_ok_is_stamped_not_failed(w, monkeypatch):
    root = w.ours()
    domain = _dom("ok")
    cid = _claimed_domain(w, root, domain)
    ip = _ip()
    _seed_ip(w, domain, ip)
    t, rir = Transport(), _stub_rir(monkeypatch)
    asked = _limiter(monkeypatch, True)
    monkeypatch.setattr(hc, "connector_get", t)

    assert runner.refresh_claimed_domain(cid) == runner.UNIT_OK
    assert asked["n"] == 1 and t.calls == 1 and rir == [domain]  # every step was reached
    row = _row(cid)
    assert row.rediscovered_at is not None and row.rediscovery_failed is False


def test_refresh_claimed_domain_lookup_failed_is_stamped_failed(w, monkeypatch):
    root = w.ours()
    domain = _dom("lf")
    cid = _claimed_domain(w, root, domain)
    _seed_ip(w, domain, _ip())
    t, rir = Transport(raises=True), _stub_rir(monkeypatch)
    _limiter(monkeypatch, True)
    monkeypatch.setattr(hc, "connector_get", t)

    assert runner.refresh_claimed_domain(cid) == runner.UNIT_FAILED
    assert t.calls == 1 and rir == [domain]
    row = _row(cid)
    assert row.rediscovered_at is not None and row.rediscovery_failed is True


def test_refresh_claimed_domain_limiter_refusal_is_rate_limited_and_not_stamped(w, monkeypatch):
    root = w.ours()
    domain = _dom("rl")
    cid = _claimed_domain(w, root, domain)
    _seed_ip(w, domain, _ip())
    t, rir = Transport(), _stub_rir(monkeypatch)
    asked = _limiter(monkeypatch, False)
    monkeypatch.setattr(hc, "connector_get", t)

    assert runner.refresh_claimed_domain(cid) == runner.UNIT_RATE_LIMITED
    assert asked["n"] == 1, "the limiter was consulted"
    assert t.calls == 0, "and no HTTP call was made"
    assert rir == [domain], "the RIR step was still reached"
    row = _row(cid)
    assert row.rediscovered_at is None and row.rediscovery_failed is False


def test_refresh_claimed_domain_arin_budget_exhausted_is_rate_limited_and_not_stamped(w, monkeypatch):
    root = w.ours()
    cid = _claimed_domain(w, root)
    rir = _stub_rir(monkeypatch, budget=True)
    assert runner.refresh_claimed_domain(cid) == runner.UNIT_RATE_LIMITED
    assert len(rir) == 1
    assert _row(cid).rediscovered_at is None


def test_refresh_claimed_domain_arin_fetch_failed_is_failed(w, monkeypatch):
    root = w.ours()
    cid = _claimed_domain(w, root)
    rir = _stub_rir(monkeypatch, fetch_failed=2)
    assert runner.refresh_claimed_domain(cid) == runner.UNIT_FAILED
    assert len(rir) == 1
    row = _row(cid)
    assert row.rediscovered_at is not None and row.rediscovery_failed is True


def test_refresh_claimed_domain_rir_step_raising_is_stamped_failed(w, monkeypatch):
    root = w.ours()
    cid = _claimed_domain(w, root)
    rir = _stub_rir(monkeypatch, raises=True)
    assert runner.refresh_claimed_domain(cid) == runner.UNIT_FAILED
    assert len(rir) == 1  # reached, and it raised
    row = _row(cid)
    assert row.rediscovered_at is not None and row.rediscovery_failed is True


def test_refresh_claimed_domain_open_candidate_is_skipped_and_not_stamped(w, monkeypatch):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id, value=_dom("open"), status="open")
    rir = _stub_rir(monkeypatch)
    assert runner.refresh_claimed_domain(cid) == runner.UNIT_SKIPPED
    assert rir == []  # nothing ran
    assert _row(cid).rediscovered_at is None


def test_a_stamp_failure_is_logged_and_does_not_propagate(w, monkeypatch, caplog):
    root = w.ours()
    cid = _claimed_domain(w, root)
    rir = _stub_rir(monkeypatch)
    reached = {"n": 0}

    def boom(*a, **kw):
        reached["n"] += 1
        raise RuntimeError("update exploded")

    monkeypatch.setattr(runner, "update", boom)
    with caplog.at_level(logging.ERROR, logger=runner.log.name):
        assert runner.refresh_claimed_domain(cid) == runner.UNIT_OK
    assert len(rir) == 1 and reached["n"] == 1
    assert any("refresh stamp failed" in r.getMessage() for r in caplog.records)
    assert _row(cid).rediscovered_at is None


# ── verify_after_claim ──────────────────────────────────────────────────────


def test_verify_after_claim_stamps_the_claimed_domain_but_not_the_open_ones(w, monkeypatch):
    root = w.ours()
    cid = _claimed_domain(w, root)
    open_id = _insert_candidate(w.db, root.id, value=_dom("open"), status="open")
    rir = _stub_rir(monkeypatch)
    facts = []

    def collect(db, domain):
        facts.append(domain)
        return DomainFacts(
            domain=domain, ns=(), mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
            registrant_org_folded=None, lookup_errors=(),
        )

    monkeypatch.setattr(runner, "_collect", collect)
    report = runner.verify_after_claim(cid)
    assert report.pairs_checked == 1 and len(facts) == 2  # the pair really ran
    assert len(rir) == 1
    assert _row(cid).rediscovered_at is not None
    open_row = _row(open_id)
    assert open_row.reverified_at is None and open_row.reverify_failed is False


# ── verify_new_candidates ───────────────────────────────────────────────────


def test_verify_new_candidates_stamps_processed_and_failed_per_candidate(w, monkeypatch):
    root = w.ours()
    _claimed_domain(w, root)
    good = _insert_candidate(w.db, root.id, value=_dom("good"), status="open")
    bad_value = _dom("bad")
    bad = _insert_candidate(w.db, root.id, value=bad_value, status="open")
    rejected = _insert_candidate(w.db, root.id, value=_dom("rej"), **_rejected())
    seen = []

    def collect(db, domain):
        seen.append(domain)
        if domain == bad_value:
            raise RuntimeError("lookup exploded")
        return DomainFacts(
            domain=domain, ns=(), mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
            registrant_org_folded=None, lookup_errors=(),
        )

    monkeypatch.setattr(runner, "_collect", collect)
    report = runner.verify_new_candidates([good, bad, rejected])
    assert bad_value in seen  # the failing pair was reached
    assert report.pairs_failed == 1 and report.candidates_skipped == 1

    g, b, r = _row(good), _row(bad), _row(rejected)
    assert g.reverified_at is not None and g.reverify_failed is False
    assert b.reverified_at is not None and b.reverify_failed is True
    assert r.reverified_at is None and r.reverify_failed is False


# ── recheck_root / refresh_root ─────────────────────────────────────────────


@pytest.fixture(autouse=False)
def quiet_rir(monkeypatch):
    runner._recheck_running.clear()
    yield
    runner._recheck_running.clear()


def test_recheck_root_stamps_the_root(w, monkeypatch, quiet_rir):
    root = w.ours()
    _claimed_domain(w, root)
    swept = []
    real = generators.record_rir_dedicated_ip

    def spy(db, **kw):
        swept.append(kw["root_entity_id"])
        return real(db, **kw)

    monkeypatch.setattr(generators, "record_rir_dedicated_ip", spy)
    assert runner.try_begin_recheck(root.id)
    runner.recheck_root(root.id)
    assert swept == [root.id]
    row = _root_row(root.id)
    assert row.rediscovered_at is not None and row.rediscovery_failed is False


def test_recheck_root_dedicated_exception_stamps_failed_and_releases_the_slot(w, monkeypatch, quiet_rir):
    root = w.ours()
    reached = []

    def boom(db, **kw):
        reached.append(kw["root_entity_id"])
        raise RuntimeError("dedicated exploded")

    monkeypatch.setattr(generators, "record_rir_dedicated_ip", boom)
    assert runner.try_begin_recheck(root.id)
    result = runner.recheck_root(root.id)
    assert reached == [root.id]
    assert result.dedicated.error is True
    row = _root_row(root.id)
    assert row.rediscovered_at is not None and row.rediscovery_failed is True
    assert root.id not in runner._recheck_running  # slot released


def test_refresh_root_budget_indeterminate_is_rate_limited_and_not_stamped(w, monkeypatch):
    root = w.ours()
    sweeps = []

    def sweep(rid, *, fresh_since):
        sweeps.append(fresh_since)
        res = runner.ReassignmentSweepResult(candidates=1)
        res.indeterminate["budget"] = 1
        return res

    monkeypatch.setattr(runner, "reassignment_for_root", sweep)
    outcome, _, _ = runner.refresh_root(root.id, fresh_since=None)
    now = datetime.now(timezone.utc)
    assert outcome == runner.UNIT_RATE_LIMITED
    # fresh_since=None became "now - 7 days" (the RIR cache TTL)
    assert len(sweeps) == 1 and abs((now - runner.REFRESH_INTERVAL) - sweeps[0]) < timedelta(minutes=1)
    assert _root_row(root.id).rediscovered_at is None


def test_refresh_root_fetch_error_indeterminate_is_failed(w, monkeypatch):
    root = w.ours()

    def sweep(rid, *, fresh_since):
        res = runner.ReassignmentSweepResult(candidates=1)
        res.indeterminate["fetch_error"] = 1
        return res

    monkeypatch.setattr(runner, "reassignment_for_root", sweep)
    outcome, _, _ = runner.refresh_root(root.id, fresh_since=None)
    assert outcome == runner.UNIT_FAILED
    row = _root_row(root.id)
    assert row.rediscovered_at is not None and row.rediscovery_failed is True


def test_refresh_root_deterministic_indeterminate_reasons_are_ok(w, monkeypatch):
    root = w.ours()

    def sweep(rid, *, fresh_since):
        res = runner.ReassignmentSweepResult(candidates=1)
        res.indeterminate["contact_held"] = 1
        return res

    monkeypatch.setattr(runner, "reassignment_for_root", sweep)
    outcome, _, _ = runner.refresh_root(root.id, fresh_since=None)
    assert outcome == runner.UNIT_OK
    assert _root_row(root.id).rediscovered_at is not None


# ── refreshable_root_clause ─────────────────────────────────────────────────


def _eligible(w, ids):
    return set(w.db.execute(
        select(OrgEntity.id).where(OrgEntity.id.in_(ids), cd.refreshable_root_clause())
    ).scalars())


def test_refreshable_root_clause(w):
    ours = w.ours()
    live, _ = w.deal()
    abandoned, eng = w.deal()
    eng.posture = "abandoned"
    w.db.commit()
    no_eng, eng2 = w.deal()
    w.db.execute(delete(Engagement).where(Engagement.id == eng2.id))
    w.db.commit()
    w.engagements.remove(eng2.id)
    w.db.refresh(no_eng)
    plain = w.entity()
    for e in (live, abandoned, no_eng):
        w.db.refresh(e)
    assert live.relationship == "ma_target" and abandoned.relationship == "ma_target"
    assert no_eng.relationship == "ma_target"  # precondition: ma_target with no engagement at all
    assert plain.relationship is None

    ids = [ours.id, live.id, abandoned.id, no_eng.id, plain.id]
    assert _eligible(w, ids) == {ours.id, live.id}
