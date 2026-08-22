"""Round-trip tests for hosting_classifier's TTL-cached claims — planning#144
L3a: `hosting_class` (classify_ip) and `reverse_ip` (reverse_ip_domains)
moved from an asset_metadata dict cache to asset_claims, attributed to the
"hosting_classifier" observer.

Real DB (a persisted ip_address AssetCanonical row is required to resolve
the claim's asset_canonical_id); the network-touching `connector_get` call
is monkeypatched per-test, per the test_shared_infra_verifier.py/
test_dangling_dns_routing.py convention — hosting_classifier is already in
conftest.py's `_GUARDED_MODULES` list, so a per-test monkeypatch of
hc.connector_get is auto-restored between tests.

Run with:  python -m app.tests.test_hosting_classifier
       or: pytest app/tests/test_hosting_classifier.py
"""

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import ClaimHistory
from app.services import hosting_classifier as hc
from app.services.claim_emitter import get_current_claim, upsert_single_claim


def _make_ip_asset(db, ip: str) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _cleanup(value: str) -> None:
    db = SessionLocal()
    try:
        rows = db.query(AssetCanonical).filter(AssetCanonical.value == value).all()
        ids = [r.id for r in rows]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value == value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _fake_response(payload: dict | None = None, text: str = ""):
    return SimpleNamespace(raise_for_status=lambda: None, json=lambda: payload or {}, text=text)


# ── classify_ip / hosting_class claim ───────────────────────────────────────

def test_classify_ip_hits_claim_cache_within_ttl_no_refetch():
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{10 + (int(suffix[:2], 16) % 60)}"
    calls = {"n": 0}

    def _spy(url, params=None, timeout=None):
        calls["n"] += 1
        return _fake_response({"is_datacenter": True, "company": {"name": "Acme Hosting"}, "asn": {"asn": 64500}})
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        _make_ip_asset(db, ip)

        first = hc.classify_ip(db, ip)
        assert calls["n"] == 1
        assert first.is_datacenter is True
        assert first.company_name == "Acme Hosting"

        second = hc.classify_ip(db, ip)
        assert calls["n"] == 1, "a fresh hosting_class claim within TTL must not refetch"
        assert second.is_datacenter is True
        assert second.company_name == "Acme Hosting"
    finally:
        db.close()
        _cleanup(ip)


def test_classify_ip_refetches_past_ttl():
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{80 + (int(suffix[:2], 16) % 60)}"
    calls = {"n": 0}

    def _spy(url, params=None, timeout=None):
        calls["n"] += 1
        return _fake_response({"is_datacenter": False, "company": {"name": "Fresh Co"}, "asn": {"asn": 64501}})
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        stale = datetime.now(timezone.utc) - hc._HOSTING_CLASS_TTL - timedelta(days=1)
        upsert_single_claim(
            db, asset.id, "hosting_classifier", "hosting_class",
            {"is_datacenter": True, "company_name": "Stale Co", "asn": 1}, stale,
        )
        db.commit()

        result = hc.classify_ip(db, ip)
        assert calls["n"] == 1, "a hosting_class claim past its TTL must refetch"
        assert result.company_name == "Fresh Co"

        claim = get_current_claim(db, asset.id, "hosting_classifier", "hosting_class")
        assert claim is not None
        assert claim.claim_value["company_name"] == "Fresh Co"
        assert claim.last_observed_at > stale
    finally:
        db.close()
        _cleanup(ip)


def test_classify_ip_no_ip_asset_does_not_write_a_claim():
    """No ip_address row at all -> fails soft (attempted=False), same as
    before this slice; nothing to attach a claim to, so nothing is written."""
    ip = "203.0.113.250"  # deliberately never inserted
    db = SessionLocal()
    try:
        result = hc.classify_ip(db, ip)
        assert result.is_datacenter is False
        assert result.attempted is False
    finally:
        db.close()


# ── reverse_ip_domains / reverse_ip claim ───────────────────────────────────

def test_reverse_ip_domains_hits_claim_cache_within_ttl_no_refetch():
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{10 + (int(suffix[:2], 16) % 60)}"
    calls = {"n": 0}

    def _spy(url, params=None, timeout=None):
        calls["n"] += 1
        return _fake_response(text="a.example.com\nb.example.com")
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        _make_ip_asset(db, ip)

        first = hc.reverse_ip_domains(db, ip)
        assert calls["n"] == 1
        assert first == ["a.example.com", "b.example.com"]

        second = hc.reverse_ip_domains(db, ip)
        assert calls["n"] == 1, "a fresh reverse_ip claim within TTL must not refetch"
        assert second == ["a.example.com", "b.example.com"]
    finally:
        db.close()
        _cleanup(ip)


def test_reverse_ip_domains_refetches_past_ttl():
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{80 + (int(suffix[:2], 16) % 60)}"
    calls = {"n": 0}

    def _spy(url, params=None, timeout=None):
        calls["n"] += 1
        return _fake_response(text="fresh.example.com")
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        stale = datetime.now(timezone.utc) - hc._REVERSE_IP_TTL - timedelta(days=1)
        upsert_single_claim(db, asset.id, "hosting_classifier", "reverse_ip", {"domains": ["stale.example.com"]}, stale)
        db.commit()

        result = hc.reverse_ip_domains(db, ip)
        assert calls["n"] == 1, "a reverse_ip claim past its TTL must refetch"
        assert result == ["fresh.example.com"]

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is not None
        assert claim.claim_value["domains"] == ["fresh.example.com"]
    finally:
        db.close()
        _cleanup(ip)


def _run():
    tests = [
        test_classify_ip_hits_claim_cache_within_ttl_no_refetch,
        test_classify_ip_refetches_past_ttl,
        test_classify_ip_no_ip_asset_does_not_write_a_claim,
        test_reverse_ip_domains_hits_claim_cache_within_ttl_no_refetch,
        test_reverse_ip_domains_refetches_past_ttl,
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
