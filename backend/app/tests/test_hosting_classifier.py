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
from collections import deque
from contextlib import contextmanager
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

    # This is the parse contract: a response that actually carries
    # `is_datacenter` (the flat free-tier shape, planning#177). Today's
    # keyless free tier does NOT carry it — see
    # test_classify_ip_free_tier_shape_is_unattempted_not_a_negative below.
    def _spy(url, params=None, timeout=None):
        calls["n"] += 1
        return _fake_response({"is_datacenter": True, "company": "Acme Hosting", "asn": "AS64500 Acme Hosting Ltd."})
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        _make_ip_asset(db, ip)

        first = hc.classify_ip(db, ip)
        assert calls["n"] == 1
        assert first.is_datacenter is True
        assert first.company_name == "Acme Hosting"
        assert first.asn == 64500

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
        return _fake_response({"is_datacenter": False, "company": "Fresh Co", "asn": "AS64501 Fresh Co"})
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
        assert result.asn == 64501

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


def test_classify_ip_free_tier_shape_is_unattempted_not_a_negative():
    """planning#177 — the keyless free tier dropped `is_datacenter`. Absent
    must read as "couldn't check", not "checked, not a datacenter", because
    the caller (shared_infra_verifier.py) keys cache eligibility off
    `attempted` (planning#113 finding 2)."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{140 + (int(suffix[:2], 16) % 60)}"

    def _spy(url, params=None, timeout=None):
        return _fake_response({
            "ip": ip, "is_bogon": False,
            "company": "Linode",
            "asn": "AS63949 Akamai Technologies, Inc.",
            "city": "Fremont", "region": "California", "country": "US",
            "lat": 1.0, "lon": 2.0, "timezone": "America/Los_Angeles",
            "docs": "https://ipapi.is/free-tier.html",
        })
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)

        result = hc.classify_ip(db, ip)
        assert result.attempted is False
        assert result.is_datacenter is False

        claim = get_current_claim(db, asset.id, "hosting_classifier", "hosting_class")
        assert claim is None, "an unusable response must never be cached"
    finally:
        db.close()
        _cleanup(ip)


def test_classify_ip_unusable_schema_leaves_stale_claim_intact():
    """A broken dependency must not overwrite or poison what is already
    cached — the stale claim survives untouched for the next attempt."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"203.0.113.{200 + (int(suffix[:2], 16) % 50)}"

    def _spy(url, params=None, timeout=None):
        return _fake_response({
            "ip": ip, "is_bogon": False,
            "company": "Linode",
            "asn": "AS63949 Akamai Technologies, Inc.",
            "city": "Fremont", "region": "California", "country": "US",
            "lat": 1.0, "lon": 2.0, "timezone": "America/Los_Angeles",
            "docs": "https://ipapi.is/free-tier.html",
        })
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
        assert result.attempted is False

        claim = get_current_claim(db, asset.id, "hosting_classifier", "hosting_class")
        assert claim is not None
        assert claim.claim_value["company_name"] == "Stale Co"
        assert claim.last_observed_at == stale
    finally:
        db.close()
        _cleanup(ip)


# ── reverse_ip_domains / reverse_ip claim ───────────────────────────────────

def _pdns_response(ip: str, domains: list[str], *, count: int | None = None,
                   last_seen_ms: int | None = None):
    """A mnemonic pDNS payload (planning#180) shaped like the real endpoint.

    Real response fields, verified live: top-level `count` (total, independent
    of the page size) and `data[]` entries carrying `rrtype`, `query` (the
    domain), `answer` (the address), and epoch-millisecond
    `firstSeenTimestamp` / `lastSeenTimestamp`.
    """
    if last_seen_ms is None:
        last_seen_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    return _fake_response({
        "count": count if count is not None else len(domains),
        "size": len(domains),
        "limit": 100,
        "offset": 0,
        "data": [
            {"rrtype": "a", "query": d, "answer": ip, "times": 5,
             "firstSeenTimestamp": last_seen_ms - 86_400_000,
             "lastSeenTimestamp": last_seen_ms}
            for d in domains
        ],
    })

def test_reverse_ip_domains_hits_claim_cache_within_ttl_no_refetch():
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{10 + (int(suffix[:2], 16) % 60)}"
    calls = {"n": 0}

    def _spy(url, params=None, timeout=None):
        calls["n"] += 1
        return _pdns_response(ip, ["a.example.com", "b.example.com"])
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
        return _pdns_response(ip, ["fresh.example.com"])
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


@contextmanager
def _fresh_rate_budget():
    """Isolates a test's reverse_ip_domains call from whatever the
    module-global rate-limiter state (hc._minute_calls/_budget_date/
    _budget_used) happens to hold — every test that reaches
    _spend_reverse_ip_budget spends a REAL slot from those globals, and with
    _MNEMONIC_PER_MINUTE == 8, more than eight such tests running back to
    back in one pytest process would starve the later ones regardless of
    order. Resets to a clean, fully-available budget for the `with` block,
    then restores exactly what was there before — the same
    save/restore-in-a-finally discipline the dedicated rate-limit tests use
    below, just wrapped for reuse."""
    orig_calls, orig_date, orig_used = hc._minute_calls, hc._budget_date, hc._budget_used
    hc._minute_calls = deque()
    hc._budget_date = datetime.now(timezone.utc).date().isoformat()
    hc._budget_used = 0
    try:
        yield
    finally:
        hc._minute_calls, hc._budget_date, hc._budget_used = orig_calls, orig_date, orig_used


# ── sharing verdict — the point of the migration (planning#180) ────────────

def test_sharing_dedicated_for_few_current_domains():
    """A handful of recently-seen domains reads as dedicated hosting —
    planning#180's baseline case."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{140 + (int(suffix[:2], 16) % 8)}"
    domains = [f"d{i}.example.com" for i in range(5)]

    def _spy(url, params=None, timeout=None):
        return _pdns_response(ip, domains)
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            hc.reverse_ip_domains(db, ip)

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is not None
        assert claim.claim_value["sharing"] == "dedicated"
        assert claim.claim_value["count"] == len(domains)
        assert claim.claim_value["active_count"] == len(domains)
        assert claim.claim_value["truncated"] is False
    finally:
        db.close()
        _cleanup(ip)


def test_sharing_shared_when_many_domains_are_current():
    """More than _SHARED_DOMAIN_THRESHOLD domains, all seen recently, is live
    shared-hosting — the straightforward positive case."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{148 + (int(suffix[:2], 16) % 8)}"
    domains = [f"s{i}.example.com" for i in range(hc._SHARED_DOMAIN_THRESHOLD + 5)]

    def _spy(url, params=None, timeout=None):
        return _pdns_response(ip, domains)
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            hc.reverse_ip_domains(db, ip)

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is not None
        assert claim.claim_value["sharing"] == "shared"
    finally:
        db.close()
        _cleanup(ip)


def test_sharing_historically_shared_when_many_domains_are_all_stale():
    """The case HackerTarget could not express at all, and the single most
    important assertion in this module's tests: many domains that all
    stopped resolving here years ago is a RECYCLED address, not live shared
    infrastructure. Without last-seen dates this would misread as "shared"
    and wrongly reject findings that really are the customer's (planning#180,
    scanme.nmap.org's 7-domains/none-in-a-year worked example).

    This case requires an UNTRUNCATED payload (count == len(data)) — per the
    updated _sharing_verdict, a truncated page can never support the
    historical claim, since active_count over a partial page is a lower
    bound, not a measurement (see the truncation test below)."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{156 + (int(suffix[:2], 16) % 8)}"
    domains = [f"h{i}.example.com" for i in range(hc._SHARED_DOMAIN_THRESHOLD + 5)]
    stale_ms = int((datetime.now(timezone.utc) - timedelta(days=365 * 3)).timestamp() * 1000)

    def _spy(url, params=None, timeout=None):
        return _pdns_response(ip, domains, last_seen_ms=stale_ms)
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            hc.reverse_ip_domains(db, ip)

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is not None
        assert claim.claim_value["truncated"] is False, "the historical claim requires a complete, untruncated view"
        assert claim.claim_value["sharing"] == "historically_shared", (
            "many domains all last seen 3 years ago must not read as currently shared"
        )
        assert claim.claim_value["active_count"] == 0
    finally:
        db.close()
        _cleanup(ip)


def test_sharing_unknown_when_no_pdns_data():
    """No pDNS history at all (count 0, empty data) is neither dedicated nor
    shared — it's unknown, and yields no candidate domains."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{164 + (int(suffix[:2], 16) % 8)}"

    def _spy(url, params=None, timeout=None):
        return _pdns_response(ip, [], count=0)
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            result = hc.reverse_ip_domains(db, ip)
        assert result == []

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is not None
        assert claim.claim_value["sharing"] == "unknown"
    finally:
        db.close()
        _cleanup(ip)


# ── count vs the fetched page ────────────────────────────────────────────

def test_truncated_page_still_uses_authoritative_total():
    """`count` is the true total even when the fetched page (capped at
    _MAX_DOMAINS) is smaller. Here total (500) exceeds _SHARED_DOMAIN_THRESHOLD
    and the page is truncated, so the updated _sharing_verdict reports
    "shared" rather than attempting (and being unable to support) a
    historically_shared verdict from a partial view."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{172 + (int(suffix[:2], 16) % 8)}"
    domains = ["p1.example.com", "p2.example.com", "p3.example.com"]

    def _spy(url, params=None, timeout=None):
        return _pdns_response(ip, domains, count=500)
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            result = hc.reverse_ip_domains(db, ip)
        assert len(result) == 3

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is not None
        assert claim.claim_value["count"] == 500
        assert claim.claim_value["truncated"] is True
        assert len(claim.claim_value["domains"]) == 3
        assert claim.claim_value["sharing"] == "shared", (
            "the verdict follows the true total, not the page size"
        )
    finally:
        db.close()
        _cleanup(ip)


def test_truncated_page_cannot_claim_historically_shared():
    """The subtlest rule in the module. A live run against the real mnemonic
    API caught this: a major CDN's anycast address returned count=332, of
    which we fetch 100, of which only 6 were active — and the old logic
    called that "historically_shared", i.e. "not live shared infra", for the
    single most shared address on the internet.

    `active_count` is computed over the fetched page only, so on a truncated
    response it is a LOWER BOUND, not a measurement: the unseen ~388 records
    here could all be current. There is no complete view to base a
    historical claim on, so the module refuses it and calls this "shared"
    instead. That is the safe direction — mistaking live shared infra for a
    recycled address causes FALSE ATTRIBUTION (blaming a customer for
    someone else's box), which this product cannot afford. The reverse
    error only costs a finding we declined to attribute."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{180 + (int(suffix[:2], 16) % 8)}"
    domains = [f"c{i}.example.com" for i in range(12)]
    stale_ms = int((datetime.now(timezone.utc) - timedelta(days=365 * 3)).timestamp() * 1000)

    def _spy(url, params=None, timeout=None):
        return _pdns_response(ip, domains, count=400, last_seen_ms=stale_ms)
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            hc.reverse_ip_domains(db, ip)

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is not None
        assert claim.claim_value["truncated"] is True
        assert claim.claim_value["sharing"] == "shared", (
            "a truncated page of all-stale records must not be read as "
            "'historically_shared' — the unseen records could all be current"
        )
    finally:
        db.close()
        _cleanup(ip)


# ── record parsing ──────────────────────────────────────────────────────

def test_non_forward_records_and_foreign_answers_are_ignored():
    """_parse_pdns_records must filter to forward (A/AAAA) records answering
    this exact IP, dedup by domain, and skip malformed entries instead of
    raising."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{188 + (int(suffix[:2], 16) % 8)}"
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    other_ip = "203.0.113.99"

    def _spy(url, params=None, timeout=None):
        return _fake_response({
            "count": 1,
            "data": [
                {"rrtype": "a", "query": "valid.example.com", "answer": ip,
                 "firstSeenTimestamp": now_ms - 86_400_000, "lastSeenTimestamp": now_ms},
                {"rrtype": "ptr", "query": "ptr.example.com", "answer": ip,
                 "firstSeenTimestamp": now_ms - 86_400_000, "lastSeenTimestamp": now_ms},
                {"rrtype": "a", "query": "other.example.com", "answer": other_ip,
                 "firstSeenTimestamp": now_ms - 86_400_000, "lastSeenTimestamp": now_ms},
                {"rrtype": "a", "query": "valid.example.com", "answer": ip,
                 "firstSeenTimestamp": now_ms - 86_400_000, "lastSeenTimestamp": now_ms},
                "not-a-record",
                {"rrtype": "a", "answer": ip},
            ],
        })
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            result = hc.reverse_ip_domains(db, ip)
        assert result == ["valid.example.com"], f"expected only the one valid forward record, got {result}"
    finally:
        db.close()
        _cleanup(ip)


def test_records_carry_iso_timestamps():
    """planning#180's whole point: per-domain first_seen/last_seen survive
    into the claim as parseable ISO-8601, and a record mnemonic reports with
    no last-seen data must store None, not an epoch-zero date that would
    misread as "seen in 1970" (see _epoch_ms's value<=0 guard)."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{196 + (int(suffix[:2], 16) % 8)}"
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

    def _spy(url, params=None, timeout=None):
        return _fake_response({
            "count": 2,
            "data": [
                {"rrtype": "a", "query": "dated.example.com", "answer": ip,
                 "firstSeenTimestamp": now_ms - 86_400_000, "lastSeenTimestamp": now_ms},
                {"rrtype": "a", "query": "undated.example.com", "answer": ip,
                 "firstSeenTimestamp": 0, "lastSeenTimestamp": 0},
            ],
        })
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            hc.reverse_ip_domains(db, ip)

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is not None
        records = {r["domain"]: r for r in claim.claim_value["records"]}
        assert set(records) == {"dated.example.com", "undated.example.com"}

        dated = records["dated.example.com"]
        assert dated["last_seen"] is not None
        datetime.fromisoformat(dated["last_seen"])  # must not raise

        undated = records["undated.example.com"]
        assert undated["last_seen"] is None, "a zero/missing lastSeenTimestamp must store None, not epoch-zero"
        assert undated["first_seen"] is None
    finally:
        db.close()
        _cleanup(ip)


# ── failure handling ─────────────────────────────────────────────────────

def test_unusable_payload_is_unattempted_not_empty():
    """planning#177's lesson applied to mnemonic: a vendor schema change (no
    `data` list) must read as an unattempted lookup, not as "this IP has no
    domains" — so it must not write a reverse_ip claim at all."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{204 + (int(suffix[:2], 16) % 8)}"

    def _spy(url, params=None, timeout=None):
        return _fake_response({"count": 5, "size": 0, "limit": 100, "offset": 0})
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            result = hc.reverse_ip_domains(db, ip)
        assert result == []

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is None, "an unusable mnemonic schema must never be cached as 'no domains'"
    finally:
        db.close()
        _cleanup(ip)


def test_network_failure_returns_empty_and_writes_no_claim():
    """Same fail-soft contract as the schema-mismatch case above: a raised
    exception from connector_get must not be recorded as a negative result."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{212 + (int(suffix[:2], 16) % 8)}"

    def _spy(url, params=None, timeout=None):
        raise ConnectionError("simulated network failure")
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        asset = _make_ip_asset(db, ip)
        with _fresh_rate_budget():
            result = hc.reverse_ip_domains(db, ip)
        assert result == []

        claim = get_current_claim(db, asset.id, "hosting_classifier", "reverse_ip")
        assert claim is None
    finally:
        db.close()
        _cleanup(ip)


# ── rate limiting — honour BOTH published mnemonic limits ──────────────────
#
# hc._minute_calls / hc._budget_date / hc._budget_used are module-global.
# conftest.py's _GUARDED_MODULES only restores an attribute when a test
# REASSIGNS it (identity check) — _minute_calls is a deque that
# _spend_reverse_ip_budget mutates in place (append/popleft), so in-place
# mutation would NOT be undone automatically. Every test below saves and
# restores all three explicitly, in a finally, regardless.

def test_minute_limit_blocks_further_calls():
    """The per-minute sliding window: exactly _MNEMONIC_PER_MINUTE calls are
    allowed, the next is blocked, and a call timestamp older than 60s falls
    out of the window again."""
    orig_calls, orig_date, orig_used = hc._minute_calls, hc._budget_date, hc._budget_used
    try:
        hc._minute_calls = deque()
        hc._budget_date = datetime.now(timezone.utc).date().isoformat()
        hc._budget_used = 0

        for i in range(hc._MNEMONIC_PER_MINUTE):
            assert hc._spend_reverse_ip_budget() is True, f"call {i + 1} should be within the per-minute budget"
        assert hc._spend_reverse_ip_budget() is False, "the per-minute cap must block the next call"

        # Simulate the window sliding: every recorded call is now > 60s old.
        hc._minute_calls = deque(t - 61 for t in hc._minute_calls)
        assert hc._spend_reverse_ip_budget() is True, "calls older than 60s must fall out of the sliding window"
    finally:
        hc._minute_calls, hc._budget_date, hc._budget_used = orig_calls, orig_date, orig_used


def test_daily_limit_blocks_further_calls():
    """The daily cap is enforced independently of the minute window — an
    empty minute window must not paper over an exhausted daily budget."""
    orig_calls, orig_date, orig_used = hc._minute_calls, hc._budget_date, hc._budget_used
    try:
        hc._minute_calls = deque()
        hc._budget_date = datetime.now(timezone.utc).date().isoformat()
        hc._budget_used = hc._MNEMONIC_PER_DAY

        assert hc._spend_reverse_ip_budget() is False, "the daily cap must block even with an empty minute window"
    finally:
        hc._minute_calls, hc._budget_date, hc._budget_used = orig_calls, orig_date, orig_used


def test_budget_exhaustion_skips_the_lookup_entirely():
    """Once the daily/minute budget is spent, reverse_ip_domains must not
    even attempt the network call — the budget check runs before
    connector_get, not just after, to decide whether to cache the result."""
    suffix = uuid.uuid4().hex[:10]
    ip = f"198.51.100.{220 + (int(suffix[:2], 16) % 8)}"
    orig_calls, orig_date, orig_used = hc._minute_calls, hc._budget_date, hc._budget_used
    calls = {"n": 0}

    def _spy(url, params=None, timeout=None):
        calls["n"] += 1
        return _pdns_response(ip, ["should.not.be.fetched.example.com"])
    hc.connector_get = _spy

    db = SessionLocal()
    try:
        _make_ip_asset(db, ip)
        hc._minute_calls = deque()
        hc._budget_date = datetime.now(timezone.utc).date().isoformat()
        hc._budget_used = hc._MNEMONIC_PER_DAY

        result = hc.reverse_ip_domains(db, ip)
        assert result == [], "budget exhaustion must yield an empty result, not raise"
        assert calls["n"] == 0, "budget exhaustion must skip the network call entirely"
    finally:
        hc._minute_calls, hc._budget_date, hc._budget_used = orig_calls, orig_date, orig_used
        db.close()
        _cleanup(ip)


def _run():
    tests = [
        test_classify_ip_hits_claim_cache_within_ttl_no_refetch,
        test_classify_ip_refetches_past_ttl,
        test_classify_ip_no_ip_asset_does_not_write_a_claim,
        test_classify_ip_free_tier_shape_is_unattempted_not_a_negative,
        test_classify_ip_unusable_schema_leaves_stale_claim_intact,
        test_reverse_ip_domains_hits_claim_cache_within_ttl_no_refetch,
        test_reverse_ip_domains_refetches_past_ttl,
        test_sharing_dedicated_for_few_current_domains,
        test_sharing_shared_when_many_domains_are_current,
        test_sharing_historically_shared_when_many_domains_are_all_stale,
        test_sharing_unknown_when_no_pdns_data,
        test_truncated_page_still_uses_authoritative_total,
        test_truncated_page_cannot_claim_historically_shared,
        test_non_forward_records_and_foreign_answers_are_ignored,
        test_records_carry_iso_timestamps,
        test_unusable_payload_is_unattempted_not_empty,
        test_network_failure_returns_empty_and_writes_no_claim,
        test_minute_limit_blocks_further_calls,
        test_daily_limit_blocks_further_calls,
        test_budget_exhaustion_skips_the_lookup_entirely,
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
