"""Tests for the ownership decision rule + IP-level caching in
app.services.shared_infra_verifier (epic#81 Phase D, planning#108/#113).

Deterministic, no DB / no live network I/O — _owned_hostnames_for_ip,
domain_affinity.check_affinity, hosting_classifier.classify_ip, and
origin_corroboration.corroborate_liveness/corroborate_tech_absence are all
monkeypatched, per the test_dangling_dns_routing.py convention.
classify_ip_ownership only reads ip_asset.value/.asset_metadata and writes
ip_asset.asset_metadata, so a plain SimpleNamespace stands in for the
AssetCanonical row; a bare object with a no-op .commit() stands in for the
DB session.

For WHICH findings get selected/stamped (the DB-query half of
stamp_findings_for_ip/verify_findings — the planning#113 widening beyond
Shodan-only, and the NON_STAMPABLE_FINDING_TYPES exclusion), see the
real-DB integration tests in test_ownership_stamping.py instead.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_shared_infra_verifier        (from /app)
       or: pytest app/tests/test_shared_infra_verifier.py
"""

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services import domain_affinity as da
from app.services import hosting_classifier as hc
from app.services import origin_corroboration as oc
from app.services import shared_infra_verifier as siv

_IP = "203.0.113.44"


class _NoopSession:
    """classify_ip_ownership only calls db.commit() on a cache write —
    everything else it touches (_owned_hostnames_for_ip, the affinity/
    hosting/corroboration calls) is monkeypatched per-test below."""
    def commit(self):
        pass


def _ip_asset(metadata: dict | None = None):
    return SimpleNamespace(id=uuid.uuid4(), asset_type="ip_address", value=_IP, asset_metadata=metadata or {})


def _owned_host(value="itsupport.contoso.com"):
    return SimpleNamespace(id=uuid.uuid4(), value=value)


def _finding(cve_id=None, title="", description=""):
    return SimpleNamespace(
        id=uuid.uuid4(), asset_canonical_id=uuid.uuid4(), cve_id=cve_id, title=title, description=description,
        finding_type="cve", verification=None, verification_evidence=None, verified_at=None,
    )


def _affinity_result(verdict, matrix=None):
    return da.AffinityResult(
        hostname="itsupport.contoso.com", origin_ip=_IP, verdict=verdict,
        signals=[], matrix=matrix if matrix is not None else {"443": {"owned": {}}},
    )


def test_ambiguous_plus_corroboration_promotes_to_ownership_unverifiable():
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_INDETERMINATE)
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]
    hc.classify_ip = lambda db, ip: hc.HostingClass(is_datacenter=True, company_name="IONOS Inc.", asn=8560)
    oc.corroborate_liveness = lambda db, origin_ip, subject_value, owned_apexes: oc.CorroborationResult(
        attempted=True, origin_serves_others=True, corroborating_hostname="othertenant.com",
        evidence="tls_san_match", hostnames_probed=["othertenant.com"],
    )

    ip_asset = _ip_asset()
    result = siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert result["verdict"] == "ownership_unverifiable"
    assert result["evidence"]["corroboration"]["corroborating_hostname"] == "othertenant.com"
    assert result["evidence"]["hosting_class"]["company_name"] == "IONOS Inc."
    # Decisive verdict — cached onto the IP asset for reuse.
    assert ip_asset.asset_metadata["ownership_verdict"]["verdict"] == "ownership_unverifiable"
    assert "ownership_verdict_at" in ip_asset.asset_metadata


def test_ambiguous_with_no_corroboration_stays_unverified():
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_INDETERMINATE)
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]
    hc.classify_ip = lambda db, ip: hc.HostingClass(is_datacenter=True, company_name="IONOS Inc.", asn=8560)
    oc.corroborate_liveness = lambda db, origin_ip, subject_value, owned_apexes: oc.CorroborationResult(
        attempted=True, origin_serves_others=False,
    )

    result = siv.classify_ip_ownership(_NoopSession(), _ip_asset())
    assert result["verdict"] == "unverified"


def test_budget_starvation_is_not_cached():
    """planning#113 Fable review, regression 2: corroborate_liveness
    attempted=False because hosting_classifier's HackerTarget budget was
    exhausted (not because there's nothing to corroborate) must NOT be
    cached at the full TTL — otherwise the day's first ~15 IPs pin every
    other IP at unverified for the whole TTL window."""
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_INDETERMINATE)
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]
    hc.classify_ip = lambda db, ip: hc.HostingClass(is_datacenter=True)
    oc.corroborate_liveness = lambda db, origin_ip, subject_value, owned_apexes: oc.CorroborationResult(attempted=False)

    ip_asset = _ip_asset()
    result = siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert result["verdict"] == "unverified"
    assert "ownership_verdict" not in ip_asset.asset_metadata, (
        "budget-starved result must be left uncached so the next call retries fresh"
    )


def test_cache_hit_skips_recompute_entirely():
    calls = {"n": 0}

    def _spy(hostname, origin_ip, apexes, ports=None):
        calls["n"] += 1
        return _affinity_result(da.VERDICT_AFFINE)
    da.check_affinity = _spy
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]

    ip_asset = _ip_asset()
    first = siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert calls["n"] == 1
    assert first["verdict"] == "confirmed_ours"

    def _should_not_be_called(db, ip):
        raise AssertionError("_owned_hostnames_for_ip must not run on a cache hit")
    siv._owned_hostnames_for_ip = _should_not_be_called

    second = siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert calls["n"] == 1, "check_affinity must not re-run on a cache hit"
    assert second["verdict"] == "confirmed_ours"


def test_not_a_datacenter_never_spends_corroboration_call():
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_INDETERMINATE)
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]
    hc.classify_ip = lambda db, ip: hc.HostingClass(is_datacenter=False)  # attempted=True by default

    def _should_not_be_called(*a, **k):
        raise AssertionError("corroborate_liveness must not be called when is_datacenter is False")
    oc.corroborate_liveness = _should_not_be_called

    ip_asset = _ip_asset()
    result = siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert result["verdict"] == "unverified"
    # A genuine (attempted) "not a datacenter" determination IS cacheable —
    # contrast with test_hosting_lookup_failure_is_not_cached below, where
    # the lookup itself failed rather than genuinely concluding this.
    assert ip_asset.asset_metadata["ownership_verdict"]["verdict"] == "unverified"


def test_hosting_lookup_failure_is_not_cached():
    """planning#113 Fable review, finding 2: hosting_classifier.classify_ip
    fails soft to is_datacenter=False on ANY error (network failure, quota
    exhaustion, no ip_address asset row) — indistinguishable from a genuine
    negative determination unless the caller checks `attempted`. Caching a
    failed lookup at the full TTL would mislabel the IP as non-datacenter
    (skipping corroboration entirely) for 14 days on what might be transient."""
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_INDETERMINATE)
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]
    hc.classify_ip = lambda db, ip: hc.HostingClass(is_datacenter=False, attempted=False)

    def _should_not_be_called(*a, **k):
        raise AssertionError("corroborate_liveness must not be called when the hosting lookup itself failed")
    oc.corroborate_liveness = _should_not_be_called

    ip_asset = _ip_asset()
    result = siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert result["verdict"] == "unverified"
    assert "ownership_verdict" not in ip_asset.asset_metadata, (
        "a failed hosting lookup must be left uncached so the next call retries fresh"
    )


def test_unanimous_not_affine_still_hard_rejects_unaffected_by_phase_d():
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_NOT_AFFINE)

    def _should_not_be_called(*a, **k):
        raise AssertionError("Phase D logic must not run when the aggregate already hard-rejects")
    hc.classify_ip = _should_not_be_called
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]

    result = siv.classify_ip_ownership(_NoopSession(), _ip_asset())
    assert result["verdict"] == "rejected_shared_infra"


def test_confirmed_ours_unaffected_by_phase_d():
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_AFFINE)

    def _should_not_be_called(*a, **k):
        raise AssertionError("Phase D logic must not run when a hostname confirms ownership")
    hc.classify_ip = _should_not_be_called
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]

    result = siv.classify_ip_ownership(_NoopSession(), _ip_asset())
    assert result["verdict"] == "confirmed_ours"


def test_no_owned_hostnames_cached_as_unverified():
    siv._owned_hostnames_for_ip = lambda db, ip: []

    ip_asset = _ip_asset()
    result = siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert result["verdict"] == "unverified"
    assert result["evidence"]["reason"] == "no owned hostnames resolve to this IP"
    assert ip_asset.asset_metadata["ownership_verdict"]["verdict"] == "unverified"


def test_unverified_classification_stamps_nothing():
    """planning#113 Fable review, finding 1: a plain 'unverified'
    classification must not write onto any finding at all, even a
    genuinely-eligible one — leaving verification NULL so the finding
    stays eligible once the IP's cache TTL expires and gets recomputed,
    rather than being permanently locked out by the verify-once IS-NULL
    gate on an inconclusive result. This is what actually makes the
    budget-starvation cache guards (above) effective: refusing to cache an
    inconclusive verdict is pointless if the finding gets stamped
    'unverified' anyway on the same call."""
    classification = {"verdict": "unverified", "evidence": {"ip": _IP, "reason": "no owned hostnames resolve to this IP"}, "matrices": {}}
    finding = _finding()

    class _FakeFindingQuery:
        def filter(self, *a, **k):
            return self
        def all(self):
            raise AssertionError("must short-circuit before even querying for eligible findings")

    class _FakeSession:
        def query(self, *a, **k):
            return _FakeFindingQuery()

    stamped = siv.stamp_findings_for_ip(_FakeSession(), _ip_asset(), classification)
    assert stamped == set()
    assert finding.verification is None


def test_stamp_findings_for_ip_includes_tech_absence_when_cve_product_matches():
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]
    matrix = {"80": {"owned": {"status_code": 404, "tech": ["nginx"]}}}
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(
        da.VERDICT_INDETERMINATE, matrix=matrix,
    )
    hc.classify_ip = lambda db, ip: hc.HostingClass(is_datacenter=True)
    oc.corroborate_liveness = lambda db, origin_ip, subject_value, owned_apexes: oc.CorroborationResult(
        attempted=True, origin_serves_others=True, corroborating_hostname="othertenant.com",
        evidence="tls_san_match", hostnames_probed=["othertenant.com"],
    )

    ip_asset = _ip_asset()
    classification = siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert classification["verdict"] == "ownership_unverifiable"

    finding = _finding(cve_id="CVE-2020-11023", title="Potential XSS vulnerability in jQuery")

    class _FakeFindingQuery:
        def filter(self, *a, **k):
            return self
        def all(self):
            return [finding]

    class _FakeSession:
        def query(self, *a, **k):
            return _FakeFindingQuery()

    stamped = siv.stamp_findings_for_ip(_FakeSession(), ip_asset, classification)
    assert stamped == {finding.id}
    assert finding.verification == "ownership_unverifiable"
    tech_absence = finding.verification_evidence.get("tech_absence")
    assert tech_absence is not None
    assert tech_absence["cve_product"] == "jquery"
    assert tech_absence["expected_tech_absent"] is True
    assert tech_absence["state_affecting"] is False


def test_force_bypasses_ttl_cache():
    """planning#115: the manual Re-verify path must skip the cache and
    recompute live, even immediately after a cache-warming call."""
    calls = {"n": 0}

    def _spy(hostname, origin_ip, apexes, ports=None):
        calls["n"] += 1
        return _affinity_result(da.VERDICT_AFFINE)
    da.check_affinity = _spy
    siv._owned_hostnames_for_ip = lambda db, ip: [_owned_host()]

    ip_asset = _ip_asset()
    siv.classify_ip_ownership(_NoopSession(), ip_asset)
    assert calls["n"] == 1

    result = siv.classify_ip_ownership(_NoopSession(), ip_asset, force=True)
    assert calls["n"] == 2, "force=True must skip the cache and recompute"
    assert result["verdict"] == "confirmed_ours"


def test_force_restamps_regardless_of_current_verification():
    """planning#115: force=True is the escape hatch that can downgrade
    confirmed_ours outright — an explicit human action wins over the
    automatic grace guard."""
    finding = _finding()
    finding.verification = "confirmed_ours"
    finding.verification_evidence = {"ip": _IP}
    classification = {"verdict": "rejected_shared_infra", "evidence": {"ip": _IP}, "matrices": {}}

    class _FakeFindingQuery:
        def filter(self, *a, **k):
            return self
        def all(self):
            return [finding]

    class _FakeSession:
        def query(self, *a, **k):
            return _FakeFindingQuery()

    stamped = siv.stamp_findings_for_ip(_FakeSession(), _ip_asset(), classification, force=True)
    assert stamped == {finding.id}
    assert finding.verification == "rejected_shared_infra"


def test_automatic_contrary_verdict_is_grace_guarded_not_applied_immediately():
    """planning#115: a single automatic contrary result must not
    immediately flip a decisive verdict — it's recorded as pending and the
    finding is left unchanged."""
    finding = _finding()
    finding.verification = "confirmed_ours"
    finding.verification_evidence = {"ip": _IP}
    classification = {"verdict": "rejected_shared_infra", "evidence": {"ip": _IP}, "matrices": {}}

    class _FakeFindingQuery:
        def filter(self, *a, **k):
            return self
        def all(self):
            return [finding]

    class _FakeSession:
        def query(self, *a, **k):
            return _FakeFindingQuery()

    stamped = siv.stamp_findings_for_ip(_FakeSession(), _ip_asset(), classification)
    assert stamped == set()
    assert finding.verification == "confirmed_ours"
    pending = finding.verification_evidence["_pending_reversal"]
    assert pending["verdict"] == "rejected_shared_infra"


def test_automatic_contrary_verdict_applies_once_grace_elapses():
    """planning#115: the SAME contrary verdict, sustained past
    _OWNERSHIP_UNSEGREGATE_GRACE_DAYS, is allowed to flip the finding."""
    finding = _finding()
    finding.verification = "confirmed_ours"
    old = datetime.now(timezone.utc) - timedelta(days=siv._OWNERSHIP_UNSEGREGATE_GRACE_DAYS + 1)
    finding.verification_evidence = {
        "ip": _IP,
        "_pending_reversal": {"verdict": "rejected_shared_infra", "first_seen_at": old.isoformat()},
    }
    classification = {"verdict": "rejected_shared_infra", "evidence": {"ip": _IP}, "matrices": {}}

    class _FakeFindingQuery:
        def filter(self, *a, **k):
            return self
        def all(self):
            return [finding]

    class _FakeSession:
        def query(self, *a, **k):
            return _FakeFindingQuery()

    stamped = siv.stamp_findings_for_ip(_FakeSession(), _ip_asset(), classification)
    assert stamped == {finding.id}
    assert finding.verification == "rejected_shared_infra"
    assert "_pending_reversal" not in (finding.verification_evidence or {})


def test_flip_flopping_contrary_verdict_restarts_grace_clock():
    """planning#115: a DIFFERENT contrary verdict than whatever was pending
    must restart the grace clock, not inherit the old pending entry's age —
    only a sustained, consistent contrary signal counts."""
    finding = _finding()
    finding.verification = "confirmed_ours"
    old = datetime.now(timezone.utc) - timedelta(days=siv._OWNERSHIP_UNSEGREGATE_GRACE_DAYS + 1)
    finding.verification_evidence = {
        "ip": _IP,
        "_pending_reversal": {"verdict": "ownership_unverifiable", "first_seen_at": old.isoformat()},
    }
    classification = {"verdict": "rejected_shared_infra", "evidence": {"ip": _IP}, "matrices": {}}

    class _FakeFindingQuery:
        def filter(self, *a, **k):
            return self
        def all(self):
            return [finding]

    class _FakeSession:
        def query(self, *a, **k):
            return _FakeFindingQuery()

    stamped = siv.stamp_findings_for_ip(_FakeSession(), _ip_asset(), classification)
    assert stamped == set(), "a different contrary verdict must restart the clock"
    assert finding.verification == "confirmed_ours"
    pending = finding.verification_evidence["_pending_reversal"]
    assert pending["verdict"] == "rejected_shared_infra"


def _run():
    tests = [
        test_ambiguous_plus_corroboration_promotes_to_ownership_unverifiable,
        test_ambiguous_with_no_corroboration_stays_unverified,
        test_budget_starvation_is_not_cached,
        test_cache_hit_skips_recompute_entirely,
        test_not_a_datacenter_never_spends_corroboration_call,
        test_hosting_lookup_failure_is_not_cached,
        test_unanimous_not_affine_still_hard_rejects_unaffected_by_phase_d,
        test_confirmed_ours_unaffected_by_phase_d,
        test_no_owned_hostnames_cached_as_unverified,
        test_unverified_classification_stamps_nothing,
        test_stamp_findings_for_ip_includes_tech_absence_when_cve_product_matches,
        test_force_bypasses_ttl_cache,
        test_force_restamps_regardless_of_current_verification,
        test_automatic_contrary_verdict_is_grace_guarded_not_applied_immediately,
        test_automatic_contrary_verdict_applies_once_grace_elapses,
        test_flip_flopping_contrary_verdict_restarts_grace_clock,
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
