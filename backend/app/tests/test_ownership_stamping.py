"""Integration tests for shared_infra_verifier's IP-level stamping —
planning#113, epic#81 Phase D follow-up L1.

Real DB (Target/AssetCanonical/FindingCanonical). Most tests here need a
DECISIVE classify_ip_ownership verdict (confirmed_ours) to demonstrate
stamping actually happening — a plain 'unverified' verdict stamps nothing
at all (planning#113 Fable review, finding 1; see
test_shared_infra_verifier.py's test_unverified_classification_stamps_nothing
for that rule in isolation) — so domain_affinity.check_affinity is
monkeypatched to VERDICT_AFFINE against a real owned A-record, per the
test_dangling_dns_routing.py convention (real DB writes + monkeypatched
network-touching calls, no live I/O). The one test that legitimately wants
a plain-unverified IP (zero owned hostnames — the cheapest way to reach
that branch) tests the "stamps nothing" contract end-to-end instead.

Run with:  python -m app.tests.test_ownership_stamping
       or: pytest app/tests/test_ownership_stamping.py
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.connectors.base import DiscoveredAsset, DiscoveredFinding
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.models.target import Target, TargetType
from app.services import domain_affinity as da
from app.services import shared_infra_verifier as siv
from app.services.asset_writer import write_assets
from app.services.claim_emitter import get_current_claim, upsert_single_claim
from app.services.finding_writer import write_findings
from app.services.shared_infra_verifier import classify_ip_ownership, verify_findings


def _cleanup(db, ip: str, host: str | None, target_ids: list) -> None:
    values = [ip] + ([host] if host else [])
    db.query(FindingCanonical).filter(
        FindingCanonical.asset_canonical_id.in_(
            db.query(AssetCanonical.id).filter(AssetCanonical.value.in_(values))
        )
    ).delete(synchronize_session=False)
    db.query(AssetCanonical).filter(AssetCanonical.value.in_(values)).delete(synchronize_session=False)
    if target_ids:
        db.query(Target).filter(Target.id.in_(target_ids)).delete(synchronize_session=False)
    db.commit()


def _make_ip_with_owned_host(db, ip: str, host: str):
    """A minimal shape _owned_hostnames_for_ip can find: a dns_record A
    row whose content is `ip`, plus the ip_address row itself."""
    write_assets(db, uuid.uuid4(), [
        DiscoveredAsset(asset_type="dns_record", value=host, parent_value=None,
                         asset_metadata={"record_type": "A", "content": ip}),
        DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=host, asset_metadata={}),
    ])
    return db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()


def test_widens_stamping_to_every_finding_type_and_source_on_the_ip():
    """The core planning#113 fix: an exposure_analyzer (source=constellus,
    finding_type=exposed_service) finding on a shared IP previously got
    NONE of Phase D's treatment because VERIFIABLE_SOURCES only ever
    allowed source=shodan through. It must now be stamped identically to a
    real Shodan CVE finding on the same IP — and a dangling_dns finding on
    that same IP must NOT be touched (NON_STAMPABLE_FINDING_TYPES)."""
    suffix = uuid.uuid4().hex[:6]
    ip = f"192.0.2.{10 + int(suffix, 16) % 190}"
    host = f"owned-{suffix}.example.com"

    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: da.AffinityResult(
        hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_AFFINE, signals=[], matrix={},
    )

    db = SessionLocal()
    target_ids: list = []
    try:
        target = Target(id=uuid.uuid4(), type=TargetType.IP, value=ip, verified=True)
        db.add(target)
        db.commit()
        target_ids.append(target.id)

        ip_asset = _make_ip_with_owned_host(db, ip, host)

        write_findings(db, uuid.uuid4(), [
            DiscoveredFinding(
                asset_value=ip, asset_id=ip_asset.id, finding_type="cve", source="shodan",
                severity="medium", title="jQuery XSS", description="d",
                detail={"fingerprint": "cve-1"}, cve_id="CVE-2020-11023",
            ),
            DiscoveredFinding(
                asset_value=ip, asset_id=ip_asset.id, finding_type="exposed_service", source="constellus",
                severity="medium", title="DNS server exposed to the internet (port 53)", description="d",
                detail={"fingerprint": "exposed-53"},
            ),
            DiscoveredFinding(
                asset_value=ip, asset_id=ip_asset.id, finding_type="dangling_dns", source="constellus",
                severity="low", title="Dangling DNS", description="d",
                detail={"fingerprint": "dangling-1"},
            ),
        ])

        touched_ids = verify_findings(db, {"domains": [], "ip_ranges": [ip]}, set())

        rows = db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id == ip_asset.id).all()
        by_type = {r.finding_type: r for r in rows}

        assert by_type["cve"].verification == "confirmed_ours"
        assert by_type["exposed_service"].verification == "confirmed_ours", (
            "planning#113: exposed_service (source=constellus) must get the "
            "same treatment as source=shodan findings on the same IP"
        )
        assert by_type["dangling_dns"].verification is None, (
            "NON_STAMPABLE_FINDING_TYPES: dangling_dns must not be stamped"
        )
        assert by_type["cve"].id in touched_ids
        assert by_type["exposed_service"].id in touched_ids
        assert by_type["dangling_dns"].id not in touched_ids
    finally:
        _cleanup(db, ip, host, target_ids)
        db.close()


def test_verify_once_contract_preserved():
    """A finding that already has a verification value must not be
    re-stamped — Phase A's 'verify once' contract, unchanged by #113
    (re-verification is planning#115, not this). A sibling finding on the
    same IP with no prior verdict DOES get stamped, so this actually
    proves the pre-verified one was skipped, not that nothing ran at all."""
    suffix = uuid.uuid4().hex[:6]
    ip = f"192.0.2.{210 + int(suffix, 16) % 40}"
    host = f"owned-{suffix}.example.com"

    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: da.AffinityResult(
        hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_AFFINE, signals=[], matrix={},
    )

    db = SessionLocal()
    target_ids: list = []
    try:
        target = Target(id=uuid.uuid4(), type=TargetType.IP, value=ip, verified=True)
        db.add(target)
        db.commit()
        target_ids.append(target.id)

        ip_asset = _make_ip_with_owned_host(db, ip, host)

        write_findings(db, uuid.uuid4(), [
            DiscoveredFinding(
                asset_value=ip, asset_id=ip_asset.id, finding_type="cve", source="shodan",
                severity="medium", title="Already verified", description="d",
                detail={"fingerprint": "cve-already"},
            ),
            DiscoveredFinding(
                asset_value=ip, asset_id=ip_asset.id, finding_type="cve", source="shodan",
                severity="medium", title="Not yet verified", description="d",
                detail={"fingerprint": "cve-fresh"},
            ),
        ])
        rows = db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id == ip_asset.id).all()
        pre_verified = next(r for r in rows if r.title == "Already verified")
        fresh = next(r for r in rows if r.title == "Not yet verified")
        pre_verified.verification = "rejected_shared_infra"
        db.commit()

        touched_ids = verify_findings(db, {"domains": [], "ip_ranges": [ip]}, set())

        db.refresh(pre_verified)
        db.refresh(fresh)
        assert pre_verified.verification == "rejected_shared_infra"
        assert pre_verified.id not in touched_ids
        assert fresh.verification == "confirmed_ours"
        assert fresh.id in touched_ids
    finally:
        _cleanup(db, ip, host, target_ids)
        db.close()


def test_ip_target_with_no_touched_assets_still_gets_stamped():
    """End-to-end regression check for planning#113's whole reason to
    exist: an IP-target's finding, on a run that didn't touch any assets
    (touched_asset_ids empty — e.g. a connector cadence gate skipped it),
    must still get classified via target_scoped_asset_ids, not silently
    skipped the way touched-only selection would have left it."""
    suffix = uuid.uuid4().hex[:6]
    ip = f"192.0.2.{100 + int(suffix, 16) % 90}"
    host = f"owned-{suffix}.example.com"

    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: da.AffinityResult(
        hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_AFFINE, signals=[], matrix={},
    )

    db = SessionLocal()
    target_ids: list = []
    try:
        target = Target(id=uuid.uuid4(), type=TargetType.IP, value=ip, verified=True)
        db.add(target)
        db.commit()
        target_ids.append(target.id)

        ip_asset = _make_ip_with_owned_host(db, ip, host)

        write_findings(db, uuid.uuid4(), [
            DiscoveredFinding(
                asset_value=ip, asset_id=ip_asset.id, finding_type="cve", source="shodan",
                severity="medium", title="Untouched-run finding", description="d",
                detail={"fingerprint": "cve-untouched"},
            ),
        ])

        touched_ids = verify_findings(db, {"domains": [], "ip_ranges": [ip]}, set())  # empty touched_asset_ids

        finding = db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id == ip_asset.id).one()
        assert finding.verification == "confirmed_ours"
        assert finding.id in touched_ids
    finally:
        _cleanup(db, ip, host, target_ids)
        db.close()


def test_plain_unverified_ip_leaves_findings_unstamped_and_still_eligible():
    """planning#113 Fable review, finding 1, end-to-end (not just the
    isolated unit test in test_shared_infra_verifier.py): an IP with no
    owned hostnames resolves to a plain 'unverified' classification —
    verify_findings must leave every finding on it untouched (verification
    still NULL), not lock them out of ever being reconsidered."""
    suffix = uuid.uuid4().hex[:6]
    ip = f"192.0.2.{150 + int(suffix, 16) % 30}"

    db = SessionLocal()
    target_ids: list = []
    try:
        target = Target(id=uuid.uuid4(), type=TargetType.IP, value=ip, verified=True)
        db.add(target)
        db.commit()
        target_ids.append(target.id)

        write_assets(db, uuid.uuid4(), [
            DiscoveredAsset(asset_type="ip_address", value=ip, parent_value=None, asset_metadata={}),
        ])
        ip_asset = db.query(AssetCanonical).filter(AssetCanonical.value == ip).one()

        write_findings(db, uuid.uuid4(), [
            DiscoveredFinding(
                asset_value=ip, asset_id=ip_asset.id, finding_type="cve", source="shodan",
                severity="medium", title="No owned hostnames on this IP", description="d",
                detail={"fingerprint": "cve-unverified"},
            ),
        ])

        touched_ids = verify_findings(db, {"domains": [], "ip_ranges": [ip]}, set())

        finding = db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id == ip_asset.id).one()
        assert finding.verification is None
        assert finding.id not in touched_ids
        # But the IP-level cache itself IS written (avoids re-probing on
        # every run) — only the finding-level stamp is withheld. planning#144
        # L3a: that cache is now an affinity_confirmation claim, not
        # asset_metadata.
        claim = get_current_claim(db, ip_asset.id, "shared_infra_verifier", "affinity_confirmation")
        assert claim is not None and claim.claim_value.get("verdict") == "unverified"
    finally:
        _cleanup(db, ip, None, target_ids)
        db.close()


def test_ownership_verdict_claim_cache_hit_and_ttl_refetch():
    """planning#144 L3a round-trip: the ownership_verdict TTL cache now
    lives as an affinity_confirmation claim (shared_infra_verifier
    observer) instead of asset_metadata. A claim within TTL is reused with
    no recompute; a claim older than the TTL is recomputed and overwritten.
    Real DB, through classify_ip_ownership -> claim_emitter.get_current_claim
    /upsert_single_claim end to end (not the fake in-memory cache
    test_shared_infra_verifier.py uses to stay DB-free)."""
    suffix = uuid.uuid4().hex[:6]
    ip = f"192.0.2.{10 + int(suffix, 16) % 190}"
    host = f"owned-{suffix}.example.com"
    calls = {"n": 0}

    def _spy(hostname, origin_ip, apexes, ports=None):
        calls["n"] += 1
        return da.AffinityResult(hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_AFFINE, signals=[], matrix={})
    da.check_affinity = _spy

    db = SessionLocal()
    target_ids: list = []
    try:
        target = Target(id=uuid.uuid4(), type=TargetType.IP, value=ip, verified=True)
        db.add(target)
        db.commit()
        target_ids.append(target.id)

        ip_asset = _make_ip_with_owned_host(db, ip, host)

        first = classify_ip_ownership(db, ip_asset)
        assert calls["n"] == 1
        assert first["verdict"] == "confirmed_ours"

        second = classify_ip_ownership(db, ip_asset)
        assert calls["n"] == 1, "an affinity_confirmation claim within TTL must not recompute"
        assert second["verdict"] == "confirmed_ours"

        # Age the claim past its TTL directly, then confirm a refetch happens.
        stale = datetime.now(timezone.utc) - siv._OWNERSHIP_VERDICT_TTL - timedelta(days=1)
        upsert_single_claim(db, ip_asset.id, "shared_infra_verifier", "affinity_confirmation", second, stale)
        db.commit()

        third = classify_ip_ownership(db, ip_asset)
        assert calls["n"] == 2, "a claim past its TTL must recompute"
        assert third["verdict"] == "confirmed_ours"

        claim = get_current_claim(db, ip_asset.id, "shared_infra_verifier", "affinity_confirmation")
        assert claim is not None
        assert claim.last_observed_at > stale
    finally:
        _cleanup(db, ip, host, target_ids)
        db.close()


def test_force_reverify_restamps_an_already_verified_finding_end_to_end():
    """planning#115, end-to-end through the real query filter (not just the
    mocked logic in test_shared_infra_verifier.py): a finding that already
    holds a decisive verdict is invisible to a normal (force=False) call —
    verify_once_contract_preserved above already proves that — but a
    force=True call (the manual Re-verify path) must still reach and
    re-stamp it, immediately, with no grace wait."""
    suffix = uuid.uuid4().hex[:6]
    ip = f"192.0.2.{10 + int(suffix, 16) % 190}"
    host = f"owned-{suffix}.example.com"

    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: da.AffinityResult(
        hostname=hostname, origin_ip=origin_ip, verdict=da.VERDICT_NOT_AFFINE, signals=[], matrix={},
    )

    db = SessionLocal()
    target_ids: list = []
    try:
        target = Target(id=uuid.uuid4(), type=TargetType.IP, value=ip, verified=True)
        db.add(target)
        db.commit()
        target_ids.append(target.id)

        ip_asset = _make_ip_with_owned_host(db, ip, host)

        write_findings(db, uuid.uuid4(), [
            DiscoveredFinding(
                asset_value=ip, asset_id=ip_asset.id, finding_type="cve", source="shodan",
                severity="medium", title="Stuck on a stale verdict", description="d",
                detail={"fingerprint": "cve-stuck"},
            ),
        ])
        finding = db.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id == ip_asset.id).one()
        finding.verification = "confirmed_ours"
        db.commit()

        # A normal automatic re-run must NOT touch it (unchanged #113 "verify
        # once" contract for a run with no force flag).
        touched_ids = verify_findings(db, {"domains": [], "ip_ranges": [ip]}, set())
        db.refresh(finding)
        assert finding.verification == "confirmed_ours"
        assert finding.id not in touched_ids

        # force=True (the manual Re-verify endpoint's path) reaches it
        # immediately, no grace wait, even though check_affinity now
        # disagrees with the prior verdict.
        touched_ids = verify_findings(db, {"domains": [], "ip_ranges": [ip]}, set(), force=True)
        db.refresh(finding)
        assert finding.verification == "rejected_shared_infra"
        assert finding.id in touched_ids
    finally:
        _cleanup(db, ip, host, target_ids)
        db.close()


def _run():
    tests = [
        test_widens_stamping_to_every_finding_type_and_source_on_the_ip,
        test_verify_once_contract_preserved,
        test_ip_target_with_no_touched_assets_still_gets_stamped,
        test_plain_unverified_ip_leaves_findings_unstamped_and_still_eligible,
        test_force_reverify_restamps_an_already_verified_finding_end_to_end,
        test_ownership_verdict_claim_cache_hit_and_ttl_refetch,
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
