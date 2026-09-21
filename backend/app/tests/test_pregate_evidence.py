"""Tests for planning#203 — the probe gate reads THIS run's evidence.

## What was wrong

`probe_class` is projected from claims, and rung 3 ANDs a `tenancy` claim
with an `affinity_confirmation` verdict. Neither existed at the moment the
gate read `probe_class`:

  * `tenancy` was written only by a background drip job on a 60s tick.
  * `affinity_confirmation` was written only by
    `shared_infra_verifier.verify_findings`, at the very END of the run.

`write_assets` does project mid-run, so a freshly discovered asset already
HAS an `asset_state` row when the gate looks — it is just projected from
port claims alone, with neither rung-3 input present, so it lands on
`name_only` and every `ip`-addressing probe is denied.

Measured on planning#148 against a real authorised target: two runs, same
scope, nothing else changed — run 1 denied naabu (`name_only`), run 2
permitted it (`direct_addressable`). The difference was purely WHEN the
evidence existed. Invisible under `log_only`, where the connector scans
anyway; under `enforce` it means a newly discovered asset is never actively
probed on the run that discovered it.

## Why moving the evidence earlier is legitimate

This is the part worth being careful about, because "gather the evidence
that authorises us earlier" is one refactor away from "authorise ourselves".
It is not, because both inputs are obtainable at `name_only` — the state
the asset is already in:

  * tenancy (Tier 0) is a local `cloud_ranges` lookup. No network at all.
  * affinity is `name`-addressed, and `name_only` explicitly licenses
    `name`. It needs no port data from Phase 1.5, only the A/AAAA records
    Phase 1 has already written.

And it is cost-neutral: `classify_ip_ownership` is cache-first on a 14-day
TTL, so this is the same single probe `verify_findings` would have made at
the end of the run, moved earlier within it.

`test_the_gate_would_have_denied_before_this_ran` is the one that would
catch a regression: it asserts the pre-state these tests are meaningful
against, so they cannot all silently pass on an asset that was already
promoted for some other reason.

Network boundary: `domain_affinity.check_affinity` is monkeypatched
throughout, per the test_shared_infra_verifier.py / test_dangling_dns_
routing.py convention. Nothing here reaches the scanner-worker.

Run with:  backend/scripts/test.ps1 app/tests/test_pregate_evidence.py
"""

import ipaddress
import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import text

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset import AssetType
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim, ClaimHistory
from app.models.cloud_range import CloudRange
from app.services import cloud_ranges
from app.services import domain_affinity as da
from app.services import scan_executor
from app.tests._docaddr import alloc_cidr


def _Discovered(asset_type, value):
    """The REAL `DiscoveredAsset`, carrying the REAL `AssetType` enum — not a
    stand-in with a plain string.

    This is not incidental fidelity. The first version of this pass selected
    its addresses with `str(a.asset_type).endswith("ip_address")`, which is
    False for `AssetType.IP_ADDRESS` (`str()` renders it
    `"AssetType.IP_ADDRESS"`, and `(str, Enum)` only compares equal to its
    value). The pass therefore selected NOTHING in production and was
    completely inert — while every test here passed, because the stub they
    used held a plain string that did match.

    Only a live run caught it. Building the batch from the real type is what
    makes these tests able to fail for the reason they exist.
    """
    return DiscoveredAsset(asset_type=asset_type, value=value)


def _affinity(verdict):
    return da.AffinityResult(
        hostname="h", origin_ip="i", verdict=verdict, signals=["stubbed"], matrix={},
    )


@contextmanager
def _stub_affinity(verdict):
    original = da.check_affinity
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity(verdict)
    try:
        yield
    finally:
        da.check_affinity = original


@contextmanager
def _seeded_meta(db):
    """Install a known-good `cloud_ranges_meta` row for the block, then put
    back exactly what was there. Mirrors test_tenancy_enricher.py's helper —
    that table holds the real dataset pointer, so a test that deletes it
    without restoring would disable the enricher for everything after it."""
    snapshot = db.execute(text(
        "SELECT dataset_sha256, generated_at, record_count, refreshed_at, manifest "
        "FROM cloud_ranges_meta WHERE id = true"
    )).first()
    db.execute(text("DELETE FROM cloud_ranges_meta"))
    db.execute(text(
        "INSERT INTO cloud_ranges_meta (id, dataset_sha256, generated_at, record_count, refreshed_at, manifest) "
        "VALUES (true, :sha, :gen, 3, now(), '{}'::jsonb)"
    ), {"sha": "pregate-test-sha", "gen": datetime.now(timezone.utc)})
    db.commit()
    try:
        yield
    finally:
        db.rollback()
        db.execute(text("DELETE FROM cloud_ranges_meta"))
        if snapshot is not None:
            db.execute(text(
                "INSERT INTO cloud_ranges_meta (id, dataset_sha256, generated_at, record_count, refreshed_at, manifest) "
                "VALUES (true, :sha, :gen, :cnt, :ref, CAST(:manifest AS jsonb))"
            ), {
                "sha": snapshot.dataset_sha256, "gen": snapshot.generated_at,
                "cnt": snapshot.record_count, "ref": snapshot.refreshed_at,
                "manifest": json.dumps(snapshot.manifest),
            })
        db.commit()


# ONE /29 for the whole module, drawn once at import rather than per test.
#
# The pool is ten /29s and four modules now draw from it; taking one per test
# here exhausted it outright and failed three OTHER modules, which is how this
# constant came to exist. A range drawn per test bought nothing: the hazard
# `alloc_cidr` exists to prevent is one module's `cloud_ranges` row answering
# ANOTHER module's containment lookup, and a range no other module can be
# handed already prevents that. Tests within this module cannot collide with
# each other because each deletes its own rows, by id, before the next runs.
#
# That last clause is the one to re-read if the suite ever runs in parallel —
# these tests would then share a prefix concurrently. The whole `cloud_ranges`
# containment regime has that property today (planning#199 records it as a
# second, unfixed collision regime), so this module is not the thing that
# would break first, but it would break.
_CIDR, _IP = alloc_cidr()


@contextmanager
def _fixture(service_class="compute"):
    """One `ip_address` asset inside the module's /29 that the mirror calls
    single-tenant compute, plus the A record that makes it an OWNED address —
    `_owned_hostnames_for_ip` matches on `record_type`/`content`, so without
    the A record affinity short-circuits to `unverified` and the promotion
    under test could never happen for the wrong reason.
    """
    cidr, ip = _CIDR, _IP
    host = f"pregate-{uuid.uuid4().hex[:10]}.example.com"
    db = SessionLocal()
    ids: list[uuid.UUID] = []
    range_id = None
    try:
        with _seeded_meta(db):
            row = CloudRange(
                id=uuid.uuid4(), prefix=cidr,
                ip_version=ipaddress.ip_network(cidr, strict=False).version,
                provider="pregate-test", service_raw=None,
                service_class=service_class, region=None, source="test",
            )
            db.add(row)
            db.commit()
            range_id = row.id

            now = datetime.now(timezone.utc)
            ip_asset = AssetCanonical(
                id=uuid.uuid4(), asset_type="ip_address", value=ip,
                first_seen_at=now, last_seen_at=now,
            )
            a_record = AssetCanonical(
                id=uuid.uuid4(), asset_type="dns_record", value=host,
                record_type="A", content=ip, first_seen_at=now, last_seen_at=now,
            )
            db.add_all([ip_asset, a_record])
            db.commit()
            ids = [ip_asset.id, a_record.id]
            yield db, ip_asset.id, ip, host
    finally:
        db.rollback()
        for model in (ClaimHistory, AssetClaim):
            db.query(model).filter(model.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id.in_(ids)).delete(synchronize_session=False)
        if range_id is not None:
            db.query(CloudRange).filter(CloudRange.id == range_id).delete(synchronize_session=False)
        db.commit()
        db.close()


def _probe_class(db, asset_id):
    state = db.get(AssetState, asset_id)
    return None if state is None else (state.attributes or {}).get("probe_class")


def _claim_types(db, asset_id) -> set[str]:
    return {
        c.claim_type for c in
        db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == asset_id).all()
    }


# ── 1. the pre-state these tests are meaningful against ────────────────────

def test_the_gate_would_have_denied_before_this_ran():
    """Guard for every test below: a fresh asset has no rung-3 evidence and
    no projection, so `_probe_class_cap` denies it. If this ever starts
    reporting `direct_addressable`, something else is promoting the asset
    and the promotions asserted below stop proving anything."""
    with _fixture() as (db, asset_id, _ip, _host):
        assert _probe_class(db, asset_id) is None, (
            "a freshly created asset must have no projection yet"
        )
        assert _claim_types(db, asset_id) == set(), (
            "a freshly created asset must carry no rung-3 evidence"
        )


# ── 2. the fix ─────────────────────────────────────────────────────────────

def test_a_first_run_asset_is_promoted_before_the_gate_reads_it():
    """The whole point. One call resolves both rung-3 inputs and re-projects,
    so Phase 1.5 — which runs immediately after — sees
    `direct_addressable` rather than the `name_only` it saw on planning#148's
    run 1."""
    with _fixture() as (db, asset_id, ip, _host):
        with _stub_affinity(da.VERDICT_AFFINE):
            scan_executor._precompute_probe_evidence(
                db, [_Discovered(AssetType.IP_ADDRESS, ip)], set(),
            )

        assert _claim_types(db, asset_id) >= {"tenancy", "affinity_confirmation"}, (
            "both rung-3 inputs must exist after the pass"
        )
        assert _probe_class(db, asset_id) == "direct_addressable", (
            "the asset must be promoted within the same run, not the next one"
        )


def test_it_reports_touched_assets_so_the_run_reprojects_them():
    """The ids go into `touched_asset_ids`, which the final projection and
    the claim/finding bookkeeping downstream both read."""
    with _fixture() as (db, asset_id, ip, _host):
        touched: set = set()
        with _stub_affinity(da.VERDICT_AFFINE):
            scan_executor._precompute_probe_evidence(
                db, [_Discovered(AssetType.IP_ADDRESS, ip)], touched,
            )
        assert asset_id in touched


# ── 3. it must not manufacture a promotion ─────────────────────────────────

def test_a_not_affine_verdict_leaves_the_asset_unpromoted():
    """Tenancy alone must not promote. Rung 3 is an AND, and this pass
    changes WHEN it is evaluated, never what it decides — an address whose
    ownership we cannot show stays `name_only` however single-tenant it is.
    Losing this is the difference between gathering evidence earlier and
    authorising ourselves."""
    with _fixture() as (db, asset_id, ip, _host):
        with _stub_affinity(da.VERDICT_NOT_AFFINE):
            scan_executor._precompute_probe_evidence(
                db, [_Discovered(AssetType.IP_ADDRESS, ip)], set(),
            )

        assert "tenancy" in _claim_types(db, asset_id), "tenancy still resolves"
        assert _probe_class(db, asset_id) == "name_only", (
            "single_tenant without confirmed_ours must NOT reach direct_addressable"
        )


def test_a_non_compute_range_leaves_the_asset_unpromoted():
    """The other half of the AND, from the tenancy side: an affine verdict
    on an address the mirror does not call single-tenant stays `name_only`."""
    with _fixture(service_class="edge") as (db, asset_id, ip, _host):
        with _stub_affinity(da.VERDICT_AFFINE):
            scan_executor._precompute_probe_evidence(
                db, [_Discovered(AssetType.IP_ADDRESS, ip)], set(),
            )
        assert _probe_class(db, asset_id) == "name_only"


# ── 4. it must never break a scan ──────────────────────────────────────────

def test_a_failing_classification_does_not_fail_the_run():
    """This pass is an optimisation of WHEN evidence is gathered. A scan
    must not fail because one address could not be classified — the asset
    simply keeps whatever projection it had, which is the pre-planning#203
    behaviour for every asset."""
    with _fixture() as (db, asset_id, ip, _host):
        original = da.check_affinity

        def _boom(*a, **kw):
            raise RuntimeError("scanner-worker unreachable")

        da.check_affinity = _boom
        try:
            scan_executor._precompute_probe_evidence(
                db, [_Discovered(AssetType.IP_ADDRESS, ip)], set(),
            )
        finally:
            da.check_affinity = original

        # No exception escaped. The asset is simply not promoted.
        assert _probe_class(db, asset_id) != "direct_addressable"


def test_one_unclassifiable_address_does_not_lose_another_ones_evidence():
    """The blast radius of a failure is one address.

    Found by self-review: the first version committed once AFTER the loop, so
    the per-asset `rollback()` discarded every prior address's still-pending
    claims too. `shared_infra_verifier.verify_findings` carries a per-IP
    commit for exactly this reason and says so at its call site.

    ## Why the obvious version of this test proves nothing

    Written the natural way — two fresh addresses, one of them failing — it
    PASSES with the bug reintroduced, which is how this docstring came to
    exist. `upsert_single_claim` only FLUSHES (its docstring is explicit that
    the commit boundary is the caller's), but `classify_ip_ownership` commits
    internally via `_write_cache` whenever it actually computes a verdict. On
    a cache MISS that commit lands the tenancy claim too, so the rollback has
    nothing left to discard and the bug is invisible.

    The window is the cache HIT: `classify_ip_ownership` returns the cached
    claim without committing, so the tenancy claim written moments earlier is
    still only flushed.

    ⚠ THREE preconditions have to hold together, and this test passed
    regardless of the code until all three did. Remove any one and it goes
    back to proving nothing, silently:

      1. the healthy address's affinity claim is pre-seeded, so its
         `classify_ip_ownership` takes the cache-hit path and commits nothing;
      2. the FAILING address has an owned hostname of its own, or
         `classify_ip_ownership` short-circuits on an empty
         `_owned_hostnames_for_ip`, commits via `_write_cache`, and never
         reaches the stub that is meant to raise;
      3. the healthy address sorts BEFORE the failing one, so it is processed
         first — the function orders by value for exactly this reason.

    Verified by reintroducing the commit-after-loop shape and watching this
    fail; it passed under that shape until all three were in place.
    """
    net = ipaddress.ip_network(_CIDR, strict=False)
    good_ip, bad_ip = str(list(net.hosts())[1]), str(list(net.hosts())[2])
    host = f"pregate-blast-{uuid.uuid4().hex[:8]}.example.com"
    db = SessionLocal()
    ids: list[uuid.UUID] = []
    range_id = None
    try:
        with _seeded_meta(db):
            row = CloudRange(
                id=uuid.uuid4(), prefix=_CIDR, ip_version=net.version,
                provider="pregate-test", service_raw=None,
                service_class="compute", region=None, source="test",
            )
            db.add(row)
            db.commit()
            range_id = row.id

            now = datetime.now(timezone.utc)
            good = AssetCanonical(id=uuid.uuid4(), asset_type="ip_address", value=good_ip,
                                  first_seen_at=now, last_seen_at=now)
            bad = AssetCanonical(id=uuid.uuid4(), asset_type="ip_address", value=bad_ip,
                                 first_seen_at=now, last_seen_at=now)
            a_rec = AssetCanonical(id=uuid.uuid4(), asset_type="dns_record", value=host,
                                   record_type="A", content=good_ip,
                                   first_seen_at=now, last_seen_at=now)
            # The failing address needs an owned hostname of its OWN, or
            # `classify_ip_ownership` short-circuits to "unverified" on
            # `_owned_hostnames_for_ip` returning empty — committing via
            # `_write_cache` and never reaching the stub that is supposed to
            # raise. Without this record the injected failure simply does not
            # happen and the test passes whatever the code does.
            bad_host = f"pregate-blast-bad-{uuid.uuid4().hex[:8]}.example.com"
            bad_rec = AssetCanonical(id=uuid.uuid4(), asset_type="dns_record", value=bad_host,
                                     record_type="A", content=bad_ip,
                                     first_seen_at=now, last_seen_at=now)
            db.add_all([good, bad, a_rec, bad_rec])
            db.commit()
            ids = [good.id, bad.id, a_rec.id, bad_rec.id]

            original = da.check_affinity

            def _selective(hostname, origin_ip, apexes, ports=None):
                if origin_ip == bad_ip:
                    raise RuntimeError("unreachable")
                return _affinity(da.VERDICT_AFFINE)

            # Warm the good address's affinity cache, so the run under test
            # takes the cache-HIT path for it — the only path on which the
            # tenancy claim stays uncommitted (see the docstring). Then clear
            # the derived state so the assertions below are about the run
            # under test and not about this warm-up.
            da.check_affinity = _selective
            try:
                scan_executor._precompute_probe_evidence(
                    db, [_Discovered(AssetType.IP_ADDRESS, good_ip)], set(),
                )
            finally:
                da.check_affinity = original
            db.query(ClaimHistory).filter(
                ClaimHistory.asset_canonical_id == good.id,
                ClaimHistory.claim_type == "tenancy",
            ).delete(synchronize_session=False)
            db.query(AssetClaim).filter(
                AssetClaim.asset_canonical_id == good.id,
                AssetClaim.claim_type == "tenancy",
            ).delete(synchronize_session=False)
            db.query(AssetState).filter(
                AssetState.asset_canonical_id == good.id
            ).delete(synchronize_session=False)
            db.commit()
            assert "affinity_confirmation" in _claim_types(db, good.id), (
                "the warm-up must leave the affinity cache populated, or the "
                "run under test takes the cache-miss path and proves nothing"
            )

            da.check_affinity = _selective
            try:
                scan_executor._precompute_probe_evidence(
                    db,
                    [_Discovered(AssetType.IP_ADDRESS, bad_ip),
                     _Discovered(AssetType.IP_ADDRESS, good_ip)],
                    set(),
                )
            finally:
                da.check_affinity = original

            assert "tenancy" in _claim_types(db, good.id), (
                "the healthy address lost its evidence to the failing one"
            )
            assert _probe_class(db, good.id) == "direct_addressable"
    finally:
        db.rollback()
        for model in (ClaimHistory, AssetClaim):
            db.query(model).filter(model.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetState).filter(AssetState.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.id.in_(ids)).delete(synchronize_session=False)
        if range_id is not None:
            db.query(CloudRange).filter(CloudRange.id == range_id).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_no_dataset_writes_no_tenancy_claim():
    """`dataset_state` is None when no mirror has been loaded. Writing
    `undetermined` there would report our own outage as a determination
    about the asset — the guard `tenancy_enricher.tick` already applies, and
    this pass must apply it too rather than reimplementing the tick's
    behaviour differently."""
    with _fixture() as (db, asset_id, ip, _host):
        original = cloud_ranges.dataset_state
        cloud_ranges.dataset_state = lambda _db: None
        try:
            with _stub_affinity(da.VERDICT_AFFINE):
                scan_executor._precompute_probe_evidence(
                    db, [_Discovered(AssetType.IP_ADDRESS, ip)], set(),
                )
        finally:
            cloud_ranges.dataset_state = original

        assert "tenancy" not in _claim_types(db, asset_id), (
            "no mirror means 'not yet enriched', not a verdict"
        )


def test_a_batch_with_no_ip_assets_does_nothing():
    """Domain-only batches must not pay for a query or a probe."""
    with _fixture() as (db, asset_id, _ip, host):
        calls: list = []
        original = da.check_affinity
        da.check_affinity = lambda *a, **kw: calls.append(a) or _affinity(da.VERDICT_AFFINE)
        try:
            scan_executor._precompute_probe_evidence(
                db, [_Discovered(AssetType.DNS_RECORD, host)], set(),
            )
        finally:
            da.check_affinity = original

        assert calls == [], "a dns_record-only batch must probe nothing"
        assert _probe_class(db, asset_id) is None
