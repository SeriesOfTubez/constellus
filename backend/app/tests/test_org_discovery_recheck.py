"""Manual Re-check of an organization's RIR records (planning#278 S3c2).

Offline. Fetch-level tests spy on the TRANSPORT (`rir_fetch.connector_get`);
runner tests replace the two RIR seams and `dedicated_ip_for_root` with
recorders. Synthetic data only.

Run with:  scripts/test.sh app/tests/test_org_discovery_recheck.py
"""

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.database import SessionLocal
from app.models.rir_lookup_cache import RirLookupCache
from app.models.user import UserRole
from app.services.org_discovery import arin, ripe, rir_fetch as rf, runner
from app.services.org_discovery.generators import RirDedicatedIpResult
from app.tests._org_world import World, client, hexid
from app.tests.test_org_discovery_schema import _claimed, _insert_candidate

# Captured at import, before conftest's autouse fixture stubs the seams.
_REAL_RIR_SEAM = runner._rir_collect
_REAL_RIPE_SEAM = runner._ripe_collect

NOW = datetime.now(timezone.utc)


class Resp:
    status_code = 200

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class Transport:
    def __init__(self, body=None):
        self.calls: list[str] = []
        self.body = body if body is not None else {"fresh": True}

    def __call__(self, url, **kw):
        self.calls.append(url)
        return Resp(self.body)


@pytest.fixture
def transport(monkeypatch):
    t = Transport()
    monkeypatch.setattr(rf, "connector_get", t)
    return t


@pytest.fixture
def path():
    p = f"poc/RCHK{hexid().upper()}"
    yield p
    db = SessionLocal()
    try:
        db.query(RirLookupCache).filter(RirLookupCache.path == p).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


@pytest.fixture
def db(path):
    # Depends on `path` so this session closes BEFORE `path`'s cleanup runs:
    # an uncommitted upsert here would otherwise block that DELETE forever.
    s = SessionLocal()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


def _seed(db, path, fetched_at, body=None):
    db.add(RirLookupCache(rir="arin", path=path, status_code=200, body=body or {"old": True}, fetched_at=fetched_at))
    db.commit()


@pytest.fixture(autouse=True)
def _slots():
    runner._recheck_running.clear()
    yield
    runner._recheck_running.clear()


# ── rir_fetch ────────────────────────────────────────────────────────────────


def test_cached_row_older_than_fresh_since_is_refetched(db, path, transport):
    _seed(db, path, NOW - timedelta(hours=2))
    b = rf.Budget(fresh_since=NOW - timedelta(hours=1))
    assert rf.get(db, "arin", path, b) == {"fresh": True}
    db.commit()
    assert len(transport.calls) == 1 and b.used == 1 and b.cache_hits == 0
    row = db.get(RirLookupCache, ("arin", path))
    assert row.body == {"fresh": True} and row.fetched_at >= NOW - timedelta(minutes=1)


def test_cached_row_newer_than_fresh_since_is_a_hit(db, path, transport):
    _seed(db, path, NOW - timedelta(minutes=5))
    b = rf.Budget(fresh_since=NOW - timedelta(hours=1))
    assert rf.get(db, "arin", path, b) == {"old": True}
    assert transport.calls == [] and b.cache_hits == 1 and b.used == 0


def test_cached_row_fetched_exactly_at_fresh_since_is_a_hit(db, path, transport):
    at = NOW - timedelta(minutes=5)
    _seed(db, path, at)
    b = rf.Budget(fresh_since=at)
    assert rf.get(db, "arin", path, b) == {"old": True}
    assert transport.calls == [] and b.cache_hits == 1 and b.used == 0


def test_no_fresh_since_uses_the_cache(db, path, transport):
    _seed(db, path, NOW - timedelta(days=3))
    b = rf.Budget()
    assert rf.get(db, "arin", path, b) == {"old": True}
    assert transport.calls == [] and b.cache_hits == 1


def test_a_key_repeated_in_one_run_is_fetched_once(db, path, transport):
    _seed(db, path, NOW - timedelta(hours=2))
    b = rf.Budget(fresh_since=NOW - timedelta(hours=1))
    first = rf.get(db, "arin", path, b)
    second = rf.get(db, "arin", path, b)
    db.commit()
    assert first == second == {"fresh": True}
    assert len(transport.calls) == 1 and b.used == 1 and b.cache_hits == 1


def test_a_row_older_than_ttl_is_refetched_whatever_fresh_since(db, path, transport):
    _seed(db, path, NOW - rf.CACHE_TTL - timedelta(days=1))
    # fresh_since far in the past: the row is newer than it, but expired by TTL
    b = rf.Budget(fresh_since=NOW - timedelta(days=60))
    assert rf.get(db, "arin", path, b) == {"fresh": True}
    db.commit()
    assert len(transport.calls) == 1 and b.used == 1


# ── runner ───────────────────────────────────────────────────────────────────


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


def _dom(tag):
    return f"recheck-{tag}-{hexid()}.fabrikam.com"


def _claimed_domain(w, root, value):
    return _insert_candidate(w.db, root.id, value=value, **_claimed(root.id))


def _world_with_candidates(w):
    a, b = w.ours(), w.entity()
    d1, d2 = _dom("one"), _dom("two")
    c1 = _claimed_domain(w, a, d1)
    c2 = _claimed_domain(w, a, d2)
    _insert_candidate(w.db, a.id, value=_dom("open"), status="open")
    _claimed_domain(w, b, _dom("other-root"))
    _insert_candidate(w.db, a.id, kind="cidr", value="192.0.2.0/24", rir="arin", rir_handle="EXAMPLE-HOLDINGS-A", **_claimed(a.id))
    return a, {d1, d2}, {c1, c2}


def _recorders(monkeypatch, order):
    seen: list[tuple[str, str, object]] = []

    def rir(db, domain, fresh_since=None):
        order.append("rir")
        seen.append(("arin", domain, fresh_since))
        return arin.ArinCollection(domain=domain, pocs_listed=0, pocs_truncated=False, pocs_not_exact=0, matched=())

    def rip(db, domain, fresh_since=None):
        order.append("ripe")
        seen.append(("ripe", domain, fresh_since))
        return ripe.RipeCollection(
            domain=domain, docs_found=0, docs_seen=0, fulltext_truncated=False, docs_other_type=0,
            contacts_not_exact=0, matched=(), resources=(), orgs_followed=0, fetch_failed=0,
            budget_exhausted=False, invalid_handles=0, invalid=0, skipped_status=0, skipped_source=0,
        )

    monkeypatch.setattr(runner, "_rir_collect", rir)
    monkeypatch.setattr(runner, "_ripe_collect", rip)
    return seen


def test_recheck_root_runs_the_claimed_domains_of_that_root_then_the_sweep(w, monkeypatch):
    root, domains, _ = _world_with_candidates(w)
    order: list = []
    seen = _recorders(monkeypatch, order)
    swept: list = []

    def sweep(root_id):
        order.append("sweep")
        swept.append(root_id)
        return RirDedicatedIpResult()

    monkeypatch.setattr(runner, "dedicated_ip_for_root", sweep)
    runner.try_begin_recheck(root.id)
    before = datetime.now(timezone.utc)
    result = runner.recheck_root(root.id)
    after = datetime.now(timezone.utc)

    assert result.claimed_domains == 2 and result.domains_failed == 0 and len(result.runs) == 2
    assert {d for _, d, _ in seen} == domains and len(seen) == 4  # both registries, two domains
    assert {r for r, _, _ in seen} == {"arin", "ripe"}
    stamps = {f for _, _, f in seen}
    assert len(stamps) == 1
    fs = stamps.pop()
    assert fs is not None and before <= fs <= after
    assert swept == [root.id]
    assert order[-1] == "sweep" and order.count("sweep") == 1 and len(order) == 5


def test_a_failing_domain_does_not_stop_the_rest_or_the_sweep(w, monkeypatch):
    root, _, ids = _world_with_candidates(w)
    first = sorted(ids)[0]
    real = runner.rir_for_claimed
    ran: list = []

    def flaky(cid, *, fresh_since=None):
        ran.append(cid)
        if cid == first:
            raise RuntimeError("boom")
        return real(cid, fresh_since=fresh_since)

    _recorders(monkeypatch, [])
    monkeypatch.setattr(runner, "rir_for_claimed", flaky)
    swept: list = []
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda r: swept.append(r) or RirDedicatedIpResult())
    runner.try_begin_recheck(root.id)
    result = runner.recheck_root(root.id)
    assert ran == sorted(ids)  # the failing one was reached, and so was the next
    assert result.domains_failed == 1 and len(result.runs) == 1
    assert swept == [root.id]


def test_a_seam_that_raises_is_swallowed_per_registry(w, monkeypatch):
    root, _, ids = _world_with_candidates(w)
    reached: list = []

    def boom(db, domain, fresh_since=None):
        reached.append(domain)
        raise RuntimeError("down")

    _recorders(monkeypatch, [])
    monkeypatch.setattr(runner, "_rir_collect", boom)
    swept: list = []
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda r: swept.append(r) or RirDedicatedIpResult())
    runner.try_begin_recheck(root.id)
    result = runner.recheck_root(root.id)
    assert len(reached) == 2 and len(result.runs) == 2 and swept == [root.id]


def test_slot_is_exclusive_and_reclaimable_when_stale():
    rid = uuid.uuid4()
    assert runner.try_begin_recheck(rid) is True
    assert runner.try_begin_recheck(rid) is False
    runner._recheck_running[rid] = time.monotonic() - runner.RECHECK_STALE_AFTER_S - 1
    assert runner.try_begin_recheck(rid) is True  # stale: reclaimed
    assert runner.try_begin_recheck(rid) is False  # and now held afresh
    runner.end_recheck(rid)
    assert runner.try_begin_recheck(rid) is True


def test_recheck_root_releases_the_slot_even_when_the_sweep_raises(w, monkeypatch):
    root, _, _ = _world_with_candidates(w)
    _recorders(monkeypatch, [])
    called: list = []

    def sweep(r):
        called.append(r)
        raise RuntimeError("sweep exploded")

    monkeypatch.setattr(runner, "dedicated_ip_for_root", sweep)
    assert runner.try_begin_recheck(root.id) is True
    runner.recheck_root(root.id)  # does not raise
    assert called == [root.id]
    assert runner.try_begin_recheck(root.id) is True  # released


def test_verify_after_claim_does_not_bypass_the_cache(w, monkeypatch):
    root = w.ours()
    cid = _claimed_domain(w, root, _dom("claim"))
    seen = _recorders(monkeypatch, [])
    monkeypatch.setattr(runner, "reverse_ip_for_claimed", lambda c: None)
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda r: None)
    runner.verify_after_claim(cid)
    assert len(seen) == 2  # both registries reached
    assert {f for _, _, f in seen} == {None}


def test_recheck_fresh_since_reaches_the_real_seams_budget(w, monkeypatch):
    """The real `_rir_collect` / `_ripe_collect` (conftest stubs them, so the
    import-time copies are restored) hand `fresh_since` to the Budget the
    collectors receive."""
    root, domains, _ = _world_with_candidates(w)
    monkeypatch.setattr(runner, "_rir_collect", _REAL_RIR_SEAM)
    monkeypatch.setattr(runner, "_ripe_collect", _REAL_RIPE_SEAM)
    budgets: list = []

    def arin_collect(db, domain, budget):
        budgets.append(("arin", budget.fresh_since))
        return arin.ArinCollection(domain=domain, pocs_listed=0, pocs_truncated=False, pocs_not_exact=0, matched=())

    def ripe_collect(db, domain, budget):
        budgets.append(("ripe", budget.fresh_since))
        return ripe.RipeCollection(
            domain=domain, docs_found=0, docs_seen=0, fulltext_truncated=False, docs_other_type=0,
            contacts_not_exact=0, matched=(), resources=(), orgs_followed=0, fetch_failed=0,
            budget_exhausted=False, invalid_handles=0, invalid=0, skipped_status=0, skipped_source=0,
        )

    monkeypatch.setattr(arin, "collect", arin_collect)
    monkeypatch.setattr(ripe, "collect", ripe_collect)
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda r: RirDedicatedIpResult())
    before = datetime.now(timezone.utc)
    assert runner.try_begin_recheck(root.id)
    runner.recheck_root(root.id)
    assert len(budgets) == 2 * len(domains)
    stamps = {f for _, f in budgets}
    assert len(stamps) == 1
    assert next(iter(stamps)) is not None and next(iter(stamps)) >= before


# ── API ──────────────────────────────────────────────────────────────────────


def _post(org_id, headers):
    return client.post(f"/api/organizations/{org_id}/recheck", headers=headers)


@pytest.fixture
def ran(monkeypatch):
    calls: list = []
    monkeypatch.setattr(runner, "recheck_root", lambda rid: (calls.append(rid), runner.end_recheck(rid)))
    return calls


def test_recheck_api_accepts_counts_and_runs(w, ran):
    root, _, _ = _world_with_candidates(w)
    r = _post(root.id, w.headers())
    assert r.status_code == 202, r.text
    assert r.json() == {"claimed_domains": 2}
    assert ran == [root.id]


def test_recheck_api_with_no_claimed_domains_is_still_accepted(w, ran):
    root = w.ours()
    r = _post(root.id, w.headers())
    assert r.status_code == 202 and r.json() == {"claimed_domains": 0}
    assert ran == [root.id]


def test_recheck_api_403_without_decide_permission(w, ran):
    root = w.ours()
    r = _post(root.id, w.headers(role=UserRole.VIEWER.value))
    assert r.status_code == 403
    assert ran == []
    assert _post(root.id, w.headers()).status_code == 202  # control: the recorder works
    assert ran == [root.id]


def test_recheck_api_404_for_unknown_and_non_root_and_slot_not_taken(w, ran):
    h = w.headers()
    non_root = w.entity()
    assert _post(uuid.uuid4(), h).status_code == 404
    assert _post(non_root.id, h).status_code == 404
    assert ran == []
    assert runner.try_begin_recheck(non_root.id) is True  # nothing took it
    runner.end_recheck(non_root.id)


def test_recheck_api_409_when_the_slot_is_held(w, ran):
    root = w.ours()
    h = w.headers()
    assert runner.try_begin_recheck(root.id) is True
    try:
        r = _post(root.id, h)
        assert r.status_code == 409
        assert ran == []
    finally:
        runner.end_recheck(root.id)
    assert _post(root.id, h).status_code == 202  # control: the same call succeeds once released
    assert ran == [root.id]
