"""Per-instance fan-out in the scan pipeline (planning#284 slice C), plus the
fixes from slice B's review (fail-closed deal stamping, canonical target
values, one failing `list_domains` not 500ing the domains route, no outbound
call for a global type's binding suggestion).

Real DB (the throwaway `constellus_test`), synthetic names only. Stub
connectors RECORD the config they were called with: the connector is the
transport boundary of the executor. Every refusal also proves its path was
REACHED (the same instance IS called before its deal regresses).

Run: backend/scripts/test.sh app/tests/test_connector_fanout.py
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.api.connectors import REGISTRY
from app.connectors.base import DiscoveredAsset, DNSDiscoveryConnector, PhaseResult
from app.connectors.cloudflare import CloudflareConnector
from app.connectors.wiz import WizConnector
from app.core.database import SessionLocal
from app.main import app
from app.models.scan import ScanRun, ScanStatus
from app.models.target import Target
from app.services import connector_instances as svc
from app.services import scan_executor
from app.tests import _decision_log
from app.tests._org_world import hexid
from app.tests.test_connector_instance_api import BASE, ApiEnv, spy_cloudflare

client = TestClient(app)

_NO_TOOLS = {"subfinder": False, "dns_records": False, "dnsrecon": False, "bruteforce": False}


@pytest.fixture
def env():
    e = ApiEnv()
    e.purge()
    yield e
    e.close()


def make(env, type, org=None, token=None, name=None, enabled=True):
    cfg = {"api_token": token} if token else {}
    inst = svc.create(
        env.db, type=type, name=name or f"conn284-{hexid()}", bound_entity_id=org.id if org else None,
        config=cfg, created_by_id=None,
    )
    if not enabled:
        svc.set_enabled(env.db, inst, False)
    env.db.commit()
    return inst


class Driver:
    """Runs `_run_pipeline` once over `domains` with a stub registry. Writers are
    spied (no assets persisted); the spy touches the session so a session left
    in a failed transaction fails the test loudly."""

    def __init__(self, monkeypatch):
        self.mp = monkeypatch
        self.written: list[str] = []
        monkeypatch.setattr(
            "app.services.discovery.dns_resolve.resolve_names", lambda *a, **k: []
        )

        def spy_writer(db, run_id, assets, **kw):
            db.execute(text("select 1"))
            self.written.extend(a.value for a in assets)
            return set()

        monkeypatch.setattr(scan_executor, "write_assets", spy_writer)

    def resolved(self, *values):
        self.mp.setattr(
            "app.services.discovery.dns_resolve.resolve_names",
            lambda *a, **k: [DiscoveredAsset(asset_type="dns_record", value=v) for v in values],
        )

    def run(self, registry, domains, scope_key="estate"):
        db = SessionLocal()
        degraded: list[str] = []
        used: list[str] = []
        run_id = uuid.uuid4()
        try:
            scan_executor._run_pipeline(
                db, run_id, {"domains": domains, "ip_ranges": []}, dict(_NO_TOOLS), "disabled", "standard",
                False, registry, used, frozenset(), degraded=degraded,
                scope_key=scope_key,
            )
        finally:
            db.close()
            _decision_log.cleanup_for_run(run_id)
        return degraded, used


@pytest.fixture
def drv(monkeypatch):
    return Driver(monkeypatch)


def record_discover(monkeypatch, fail_for=None):
    calls: list[tuple[str, str | None]] = []

    def discover(self, domain, config):
        token = config.get("api_token")
        calls.append((domain, token))
        if token == fail_for:
            raise RuntimeError("boom")
        return PhaseResult(assets=[DiscoveredAsset(asset_type="dns_record", value=f"{token}.{domain}")])

    monkeypatch.setattr(CloudflareConnector, "discover", discover)
    return calls


# ── DNS discovery fan-out ───────────────────────────────────────────────────


def test_discovery_called_once_per_instance_per_domain_with_its_own_config(env, drv, monkeypatch):
    org = env.ours()
    make(env, "cloudflare", org, "tok-a")
    make(env, "cloudflare", org, "tok-b")
    calls = record_discover(monkeypatch)
    n = hexid()
    d1, d2 = f"one-{n}.example.com", f"two-{n}.example.com"
    drv.run({"cloudflare": CloudflareConnector()}, [d1, d2])
    assert sorted(calls) == sorted([(d1, "tok-a"), (d1, "tok-b"), (d2, "tok-a"), (d2, "tok-b")])


def capture_session(monkeypatch) -> dict:
    """The executor's own session, captured when it asks for runnable instances."""
    holder: dict = {}
    real = svc.runnable_instances

    def capture(db, type):
        holder["db"] = db
        return real(db, type)

    monkeypatch.setattr(svc, "runnable_instances", capture)
    return holder


def test_first_instance_failing_does_not_stop_the_second_and_session_stays_usable(env, drv, monkeypatch):
    org = env.ours()
    make(env, "cloudflare", org, "tok-bad")
    make(env, "cloudflare", org, "tok-good")
    calls = record_discover(monkeypatch)
    holder = capture_session(monkeypatch)
    ok = CloudflareConnector.discover

    def discover(self, domain, config):
        if config.get("api_token") == "tok-bad":
            calls.append((domain, "tok-bad"))
            holder["db"].execute(text("select 1/0"))  # a database error: aborts the transaction
        return ok(self, domain, config)

    monkeypatch.setattr(CloudflareConnector, "discover", discover)
    d = f"poison-{hexid()}.example.com"
    drv.run({"cloudflare": CloudflareConnector()}, [d])
    assert (d, "tok-bad") in calls and (d, "tok-good") in calls
    assert drv.written == [f"tok-good.{d}"]  # the second instance's assets were written (spy runs select 1)


def test_deal_regression_skips_and_records_once(env, monkeypatch):
    deal, eng = env.deal("day_0")
    inst = make(env, "cloudflare", deal, "tok-deal")
    calls = record_discover(monkeypatch)
    Driver(monkeypatch)
    n = hexid()
    domains = [f"a-{n}.example.com", f"b-{n}.example.com"]
    for d in domains:
        env.target(d, engagement_id=eng.id)

    def run_whole():
        db = SessionLocal()
        run = ScanRun(
            id=uuid.uuid4(), status=ScanStatus.PENDING, scope={"domains": domains, "ip_ranges": []},
            options={"aggressiveness": "standard", **_NO_TOOLS},
        )
        db.add(run)
        db.commit()
        try:
            scan_executor._run(db, run.id, run.scope, {"cloudflare": CloudflareConnector()})
            db.refresh(run)
            return list(run.partial_failures or [])
        finally:
            db.rollback()
            db.query(ScanRun).filter(ScanRun.id == run.id).delete()
            db.commit()
            _decision_log.cleanup_for_run(run.id)
            db.close()

    before = run_whole()
    assert sorted(d for d, _ in calls) == sorted(domains)  # path reached: called while the binding holds
    assert not [m for m in before if str(inst.id) in m]

    calls.clear()
    env.set_posture(eng, "pre_close")
    after = run_whole()
    assert calls == []
    skips = [m for m in after if str(inst.id) in m]
    assert skips == [f"cloudflare instance {inst.id}: skipped, binding no longer allowed (deal_not_closed)"]


def test_disabled_instance_is_neither_called_nor_reported(env, drv, monkeypatch):
    org = env.ours()
    make(env, "cloudflare", org, "tok-on")
    off = make(env, "cloudflare", org, "tok-off", enabled=False)
    calls = record_discover(monkeypatch)
    d = f"dis-{hexid()}.example.com"
    degraded, _ = drv.run({"cloudflare": CloudflareConnector()}, [d])
    assert calls == [(d, "tok-on")]
    assert not [m for m in degraded if str(off.id) in m]


# ── enrichment fan-out ──────────────────────────────────────────────────────


def test_each_enrichment_instance_gets_its_own_config(env, drv, monkeypatch):
    org = env.ours()
    make(env, "wiz", org, "tok-w1")
    make(env, "wiz", org, "tok-w2")
    seen: list[str] = []

    def enrich(self, assets, config):
        seen.append(config.get("api_token"))
        return PhaseResult()

    monkeypatch.setattr(WizConnector, "enrich", enrich)
    drv.resolved(f"host-{hexid()}.example.com")
    _, used = drv.run({"wiz": WizConnector()}, [f"wz-{hexid()}.example.com"])
    assert sorted(seen) == ["tok-w1", "tok-w2"]


# ── index lookup: the missing rollback ──────────────────────────────────────


class _IndexStub:
    """Not a DNSDiscoveryConnector, has index_lookup: the executor's index loop."""

    def __init__(self, db_holder):
        self.db_holder = db_holder
        self.calls = 0

    def index_lookup(self, domain, config):
        self.calls += 1
        if self.calls == 1:
            # Poison the executor's own session through a real DB error: the
            # stub reaches it via the holder set by the test's write spy hook.
            self.db_holder["db"].execute(text("select 1/0"))
        return PhaseResult(assets=[DiscoveredAsset(asset_type="dns_record", value=f"idx.{domain}")])


def test_index_lookup_failure_leaves_the_session_usable(env, drv, monkeypatch):
    make(env, "shodan")
    holder = capture_session(monkeypatch)
    stub = _IndexStub(holder)
    d1, d2 = f"ix1-{hexid()}.example.com", f"ix2-{hexid()}.example.com"
    drv.run({"shodan": stub}, [d1, d2])
    assert stub.calls == 2
    assert drv.written == [f"idx.{d2}"]  # the later write succeeded after the first lookup's DB error


# ── runnable_instances unit ─────────────────────────────────────────────────


def test_runnable_instances_ordering_disabled_and_skip_reason(env):
    deal, eng = env.deal("day_0")
    ours = env.ours()
    first = make(env, "cloudflare", ours, "t1")
    second = make(env, "cloudflare", ours, "t2")
    off = make(env, "cloudflare", ours, "t3", enabled=False)
    dealt = make(env, "cloudflare", deal, "t4")
    runnable, skipped = svc.runnable_instances(env.db, "cloudflare")
    assert [i.id for i, _ in runnable] == [first.id, second.id, dealt.id]
    assert runnable[0][1] == {"api_token": "t1"}
    assert skipped == [] and off.id not in [i.id for i, _ in runnable]
    env.set_posture(eng, "pre_close")
    env.db.expire_all()
    runnable, skipped = svc.runnable_instances(env.db, "cloudflare")
    assert [i.id for i, _ in runnable] == [first.id, second.id]
    assert [(i.id, r) for i, r in skipped] == [(dealt.id, "deal_not_closed")]
    # a global type: runnable when enabled, no binding check
    shodan = make(env, "shodan")
    assert [i.id for i, _ in svc.runnable_instances(env.db, "shodan")[0]] == [shodan.id]


# ── slice B review fixes ────────────────────────────────────────────────────


def _ensure(env, value, inst):
    from app.services.target_service import ensure_connector_verified

    return ensure_connector_verified(env.db, value, inst)


def test_deal_bound_instance_fails_closed_without_a_single_engagement(env):
    deal, eng = env.deal("day_0")
    inst = make(env, "cloudflare", deal, "t")
    second = env.engagement(deal, "pre_close")  # two non-abandoned engagements: ambiguous
    value = f"fc-{hexid()}.example.com"
    env.w.track_target(value)
    with pytest.raises(ValueError):
        _ensure(env, value, inst)
    env.db.rollback()
    assert env.db.query(Target).filter(Target.value == value).count() == 0
    # reached: with exactly one engagement the same call creates a stamped target
    second.posture = "abandoned"
    env.db.commit()
    t = _ensure(env, value, inst)
    env.db.commit()
    assert t.engagement_id == eng.id


def test_connector_target_is_canonical_and_marked_auto_managed(env):
    inst = make(env, "cloudflare", env.ours(), "t")
    n = hexid()
    env.w.track_target(f"canon-{n}.example.com")
    a = _ensure(env, f"Canon-{n}.Example.COM.", inst)
    b = _ensure(env, f"canon-{n}.example.com", inst)
    env.db.commit()
    assert a.id == b.id and a.value == f"canon-{n}.example.com"
    assert a.source_type == "dns_connector" and a.auto_managed is True


def test_domains_route_survives_one_instance_failing(env, monkeypatch):
    org = env.ours()
    bad = make(env, "cloudflare", org, "tok-bad")
    good = make(env, "cloudflare", org, "tok-good")

    def list_domains(self, config):
        if config["api_token"] == "tok-bad":
            raise RuntimeError("provider down")
        return [f"ok-{hexid()}.example.com"]

    monkeypatch.setattr(CloudflareConnector, "list_domains", list_domains)
    r = client.get(f"{BASE}/domains", headers=env.admin)
    assert r.status_code == 200, r.text
    ids = {row["connector_instance_id"] for row in r.json()}
    assert str(good.id) in ids and str(bad.id) not in ids


def test_binding_suggestion_makes_no_call_for_a_global_type(env, monkeypatch):
    calls: list[str] = []

    class GlobalDns(DNSDiscoveryConnector):
        name = "stub"

        def list_domains(self, config):
            calls.append("list_domains")
            return ["x.example.com"]

        def discover(self, domain, config):
            return PhaseResult()

        def is_configured(self, config):
            return True

        def get_config_schema(self):
            return {}

        def test_connection(self, config):
            return True, "ok"

    transport = spy_cloudflare(monkeypatch, ["zone.example.com"])
    monkeypatch.setitem(REGISTRY, "certspotter", GlobalDns())
    r = client.post(f"{BASE}/certspotter/binding-suggestion", headers=env.iadmin, json={"config": {}})
    assert r.status_code == 200
    assert r.json() == {"suggested_entity_id": None, "candidates": [], "zone_count": None}
    assert calls == [] and transport == []
    # reached: an account type with a DNS connector does call out
    r = client.post(f"{BASE}/cloudflare/binding-suggestion", headers=env.iadmin, json={"config": {"api_token": "p"}})
    assert r.status_code == 200 and len(transport) == 1


# ── account instances run only on targets of their own scope (planning#284 E) ──


def run_whole(domains):
    """Drive `_run` (so the scope partition is exercised) over `domains`."""
    db = SessionLocal()
    run = ScanRun(
        id=uuid.uuid4(), status=ScanStatus.PENDING, scope={"domains": domains, "ip_ranges": []},
        options={"aggressiveness": "standard", **_NO_TOOLS},
    )
    db.add(run)
    db.commit()
    try:
        scan_executor._run(db, run.id, run.scope, {"cloudflare": CloudflareConnector(), "wiz": WizConnector()})
    finally:
        db.rollback()
        db.query(ScanRun).filter(ScanRun.id == run.id).delete()
        db.commit()
        _decision_log.cleanup_for_run(run.id)
        db.close()


def record_enrich(monkeypatch):
    seen: list[tuple[str, tuple[str, ...]]] = []

    def enrich(self, assets, config):
        seen.append((config.get("api_token"), tuple(sorted(a.value for a in assets))))
        return PhaseResult()

    monkeypatch.setattr(WizConnector, "enrich", enrich)
    monkeypatch.setattr(
        "app.services.discovery.dns_resolve.resolve_names",
        lambda names, **k: [DiscoveredAsset(asset_type="dns_record", value=v) for v in names],
    )
    return seen


def test_account_instances_see_only_their_own_scope_through_run(env, monkeypatch):
    ours = env.ours()
    deal, eng = env.deal("day_0")
    w1 = make(env, "wiz", ours, "tok-w1")
    w2 = make(env, "wiz", deal, "tok-w2")
    make(env, "cloudflare", ours, "cf-ours")
    make(env, "cloudflare", deal, "cf-deal")
    n = hexid()
    d_estate, d_deal = f"est-{n}.example.com", f"deal-{n}.example.com"
    env.target(d_estate)
    env.target(d_deal, engagement_id=eng.id)
    Driver(monkeypatch)
    seen = record_enrich(monkeypatch)
    calls = record_discover(monkeypatch)
    run_whole([d_estate, d_deal])
    # path reached: every instance ran, each on exactly its own chunk
    # (the chunk's own domain plus what the chunk's own cloudflare instance discovered; nothing of the other chunk)
    assert sorted(seen) == [
        ("tok-w1", (f"cf-ours.{d_estate}", d_estate)),
        ("tok-w2", (f"cf-deal.{d_deal}", d_deal)),
    ]
    assert sorted(calls) == [(d_deal, "cf-deal"), (d_estate, "cf-ours")]
    assert w1.id != w2.id


def test_unknown_scope_runs_no_account_instance_but_still_runs_a_global_one(env, monkeypatch):
    ours = env.ours()
    make(env, "wiz", ours, "tok-w1")
    make(env, "cloudflare", ours, "cf-ours")
    make(env, "shodan")
    stub = _IndexStub({})
    stub.index_lookup = lambda domain, config: (stub_calls.append(domain), PhaseResult())[1]
    stub_calls: list[str] = []
    Driver(monkeypatch)
    seen = record_enrich(monkeypatch)
    calls = record_discover(monkeypatch)
    d = f"notarget-{hexid()}.example.com"  # no target row at all
    scan_executor_registry = {"cloudflare": CloudflareConnector(), "wiz": WizConnector(), "shodan": stub}
    db = SessionLocal()
    run = ScanRun(
        id=uuid.uuid4(), status=ScanStatus.PENDING, scope={"domains": [d], "ip_ranges": []},
        options={"aggressiveness": "standard", **_NO_TOOLS},
    )
    db.add(run)
    db.commit()
    try:
        scan_executor._run(db, run.id, run.scope, scan_executor_registry)
    finally:
        db.rollback()
        db.query(ScanRun).filter(ScanRun.id == run.id).delete()
        db.commit()
        _decision_log.cleanup_for_run(run.id)
        db.close()
    assert seen == [] and calls == []
    assert stub_calls == [d]  # the non-account connector still ran
    # reached: the same instances DO run once the domain has an estate target
    env.target(d)
    run_whole([d])
    assert seen == [("tok-w1", (f"cf-ours.{d}", d))] and calls == [(d, "cf-ours")]


def test_instance_matches_scope_truth_table(env):
    ours = env.ours()
    deal, eng = env.deal("day_0")
    other, other_eng = env.deal("day_0")
    w_ours = make(env, "wiz", ours, "a")
    w_deal = make(env, "wiz", deal, "b")
    shodan = make(env, "shodan")
    m = lambda i, k: svc.instance_matches_scope(env.db, i, k)  # noqa: E731
    assert m(w_ours, "estate") is True
    assert m(w_ours, str(eng.id)) is False and m(w_ours, "unknown") is False
    assert m(w_deal, str(eng.id)) is True
    assert m(w_deal, "estate") is False and m(w_deal, str(other_eng.id)) is False and m(w_deal, "unknown") is False
    assert m(shodan, "unknown") is True and m(shodan, "estate") is True  # global: always
    # a deal that regressed to two engagements is ambiguous: matches nothing
    env.engagement(deal, "pre_close")
    env.db.expire_all()
    assert m(w_deal, str(eng.id)) is False


# ── zone clash on sync: recorded for a person (planning#284 comment 6386279550, #277 S1b) ──


def test_zone_clash_is_recorded_and_does_not_stop_the_rest_of_the_sync(env, monkeypatch):
    from app.api.connectors import _auto_discover_all_domains

    ours = env.ours()
    deal, eng = env.deal("day_0")
    deal_inst = make(env, "cloudflare", deal, "tok-d")
    ours_inst = make(env, "cloudflare", ours, "tok-o")
    n = hexid()
    z_estate, z_free, z_deal, z_same = (f"{k}-{n}.example.com" for k in ("est", "free", "deal", "same"))
    t_estate = env.target(z_estate, verified=False)
    t_deal = env.target(z_deal, verified=False, engagement_id=eng.id)
    t_same = env.target(z_same, verified=False)
    env.w.track_target(z_free)
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: [z_estate, z_free])
    discovered: list[str] = []

    def discover(self, domain, config):
        discovered.append(domain)
        return PhaseResult()

    monkeypatch.setattr(CloudflareConnector, "discover", discover)
    _auto_discover_all_domains(deal_inst.id)
    env.db.expire_all()
    # deal-bound instance vs an estate target: untouched, not discovered; the other zone IS discovered
    assert discovered == [z_free]
    t = env.db.get(Target, t_estate.id)
    assert (t.verified, t.connector_instance_id, t.engagement_id) == (False, None, None)
    assert env.db.query(Target).filter(Target.value == z_free).one().engagement_id == eng.id
    from app.models.connector_zone_clash import ConnectorZoneClash

    (row,) = env.db.query(ConnectorZoneClash).filter(ConnectorZoneClash.instance_id == deal_inst.id).all()
    assert (row.zone, row.reason, row.conflicting_target_id) == (z_estate, "target_in_other_scope", t_estate.id)

    # ours-bound instance vs a deal target: same skip
    discovered.clear()
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: [z_deal, z_same])
    _auto_discover_all_domains(ours_inst.id)
    env.db.expire_all()
    assert discovered == [z_same]  # same scope (estate) adopted as before
    (row,) = env.db.query(ConnectorZoneClash).filter(ConnectorZoneClash.instance_id == ours_inst.id).all()
    assert (row.zone, row.reason, row.conflicting_target_id) == (z_deal, "target_in_other_scope", t_deal.id)
    t = env.db.get(Target, t_deal.id)
    assert (t.verified, t.connector_instance_id, t.engagement_id) == (False, None, eng.id)
    t = env.db.get(Target, t_same.id)
    assert t.verified is True and t.connector_instance_id == ours_inst.id and t.engagement_id is None


def test_child_recheck_inherits_the_scope_of_the_target_it_rolls_up_to(env):
    """A recheck of a child (not a target itself) takes the scope of the
    target its asset parent chain reaches, like the tier partition; with no
    covering target it stays "unknown" (fails closed for account instances)."""
    from app.models.asset_canonical import AssetCanonical

    deal, eng = env.deal("day_0")
    n = hexid()
    apex = f"deal-{n}.example.com"
    child = f"www.{apex}"
    orphan = f"www.orphan-{n}.invalid"
    env.target(apex, engagement_id=eng.id)
    env.db.add(AssetCanonical(id=uuid.uuid4(), asset_type="subdomain", value=child, parent_value=apex))
    env.db.commit()
    try:
        out = scan_executor._partition_scope_by_scope_key(env.db, [apex, child, orphan], [])
        assert sorted(out[str(eng.id)]["domains"]) == sorted([apex, child])
        assert out[svc.SCOPE_UNKNOWN]["domains"] == [orphan]
    finally:
        env.db.query(AssetCanonical).filter(AssetCanonical.value == child).delete(synchronize_session=False)
        env.db.commit()
