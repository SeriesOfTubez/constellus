"""Tests for app.services.origin_corroboration (planning#106, epic#81
Phase C — Shodan affiliated-hostname liveness corroboration).

Deterministic, no live network I/O for the pure candidate-selection and
evidence-evaluation logic; corroborate_liveness's probe call is covered
separately by live verification against the real dev DB (see session notes
— real Shodan-captured hostnames on the epic's motivating customer's IPs
are all auto-PTR artifacts correctly filtered to zero candidates).

Its DB lookup half IS covered here as of planning#144 L3c-3, which moved
the candidate source from `asset_metadata["shodan_hostnames"]` to the
`reverse_hostname` claim. A silent [] out of that lookup degrades to
`attempted=False` — corroboration quietly never running — so it needs a
test that fails loudly rather than a monkeypatch that skips past it.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_origin_corroboration        (from /app)
       or: pytest app/tests/test_origin_corroboration.py
"""

import uuid
from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import ClaimHistory
from app.services import origin_corroboration as oc
from app.services.claim_emitter import upsert_single_claim


def test_ip_in_hostname_ipv4_plain():
    assert oc._ip_in_hostname("203.0.113.44", "203-0-113-44.elastic-ssl.ui-r.com") is True


def test_ip_in_hostname_ipv4_zero_padded():
    assert oc._ip_in_hostname("198.51.100.77", "syn-198-051-100-077.biz.spectrum.com") is True


def test_ip_in_hostname_ipv6_exploded():
    assert oc._ip_in_hostname(
        "2607:f1c0:100f:f000::200",
        "2607-f1c0-100f-f000-0000-0000-0000-0200.elastic-ssl.ui-r.com",
    ) is True


def test_ip_in_hostname_false_for_real_hostname():
    assert oc._ip_in_hostname("203.0.113.44", "sslvpn.contoso.com") is False


def test_select_candidates_filters_own_apex_and_ptr_artifacts():
    raw = [
        "sslvpn.contoso.com",                           # our own apex -> filtered
        "syn-198-051-100-077.biz.spectrum.com",             # IP-embedded PTR -> filtered
        "ec2-18-204-110-60.compute-1.amazonaws.com",        # infra suffix -> filtered
        "othertenant.com",                                  # real candidate -> kept
    ]
    candidates = oc._select_candidates(raw, "subject.contoso.com", {"contoso.com"}, "198.51.100.77")
    assert candidates == ["othertenant.com"]


def test_select_candidates_dedupes_by_apex_and_caps():
    raw = [f"sub{i}.tenant{i % 2}.com" for i in range(10)]  # only 2 distinct apexes
    candidates = oc._select_candidates(raw, "subject.example.com", set(), "203.0.113.5")
    assert len(candidates) == 2


def test_evaluate_strong_hit_on_san_match():
    matrix = {
        "othertenant.com": {
            "443": {"status_code": 200, "sans": ["othertenant.com", "*.othertenant.com"]},
        },
    }
    strong, weak = oc._evaluate(matrix)
    assert strong == "othertenant.com"
    assert weak is None


def test_evaluate_weak_hit_on_bare_2xx_no_san_match():
    matrix = {
        "othertenant.com": {
            "443": {"status_code": 200, "sans": []},
        },
    }
    strong, weak = oc._evaluate(matrix)
    assert strong is None
    assert weak == "othertenant.com"


def test_evaluate_no_hit_on_negative_status():
    matrix = {
        "othertenant.com": {
            "443": {"status_code": 404, "sans": []},
        },
    }
    strong, weak = oc._evaluate(matrix)
    assert strong is None
    assert weak is None


def test_tech_absence_not_applicable_for_unmapped_product():
    matrix = {"443": {"owned": {"status_code": 404, "tech": ["nginx"]}}}
    assert oc.corroborate_tech_absence(matrix, "some-obscure-cms") is None


def test_tech_absence_not_applicable_when_owned_side_silent():
    # No status_code anywhere -> the owned side never answered at all;
    # absence proves nothing, must not be reported as a signal.
    matrix = {"443": {"owned": {"status_code": None, "tech": []}}}
    assert oc.corroborate_tech_absence(matrix, "jquery") is None


def test_tech_absence_present_when_owned_side_answers_without_product():
    matrix = {
        "80": {"owned": {"status_code": 404, "tech": ["nginx"]}},
        "443": {"owned": {"status_code": None, "tech": []}},  # unreachable port ignored
    }
    result = oc.corroborate_tech_absence(matrix, "jquery")
    assert result is not None
    assert result["expected_tech_absent"] is True
    assert result["state_affecting"] is False
    assert result["checked_ports"] == ["80"]


def test_tech_absence_false_when_product_actually_detected():
    matrix = {"443": {"owned": {"status_code": 200, "tech": ["nginx", "jQuery"]}}}
    result = oc.corroborate_tech_absence(matrix, "jquery")
    assert result is not None
    assert result["expected_tech_absent"] is False


def _run():
    tests = [
        test_ip_in_hostname_ipv4_plain,
        test_ip_in_hostname_ipv4_zero_padded,
        test_ip_in_hostname_ipv6_exploded,
        test_ip_in_hostname_false_for_real_hostname,
        test_select_candidates_filters_own_apex_and_ptr_artifacts,
        test_select_candidates_dedupes_by_apex_and_caps,
        test_evaluate_strong_hit_on_san_match,
        test_evaluate_weak_hit_on_bare_2xx_no_san_match,
        test_evaluate_no_hit_on_negative_status,
        test_tech_absence_not_applicable_for_unmapped_product,
        test_tech_absence_not_applicable_when_owned_side_silent,
        test_tech_absence_present_when_owned_side_answers_without_product,
        test_tech_absence_false_when_product_actually_detected,
        # DB-backed (planning#144 L3c-3) — need DATABASE_URL, unlike the
        # pure-assert tests above.
        test_shodan_hostnames_read_from_reverse_hostname_claim,
        test_shodan_hostnames_empty_without_claim,
    ]
    for fn in tests:
        try:
            fn()
            print(f"OK: {fn.__name__}")
        except AssertionError as exc:
            print(f"FAIL: {fn.__name__}: {exc}")
            raise SystemExit(1)
    print("ALL PASS")


# ── corroborate_liveness's candidate source (planning#144 L3c-3) ────────────

def _seed_ip_with_reverse_hostname_claim(db, ip: str, hostnames):
    now = datetime.now(timezone.utc)
    row = AssetCanonical(
        id=uuid.uuid4(), asset_type="ip_address", value=ip, parent_value=None,
        first_seen_at=now, last_seen_at=now, asset_metadata={"sources": ["shodan"]},
    )
    db.add(row); db.commit(); db.refresh(row)
    if hostnames is not None:
        upsert_single_claim(db, row.id, "shodan", "reverse_hostname", {"hostnames": hostnames}, now)
        db.commit()
    return row


def _cleanup_ip(value: str) -> None:
    db = SessionLocal()
    try:
        ids = [r.id for r in db.query(AssetCanonical).filter(AssetCanonical.value == value).all()]
        if ids:
            db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(ids)).delete(synchronize_session=False)
        db.query(AssetCanonical).filter(AssetCanonical.value == value).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_shodan_hostnames_read_from_reverse_hostname_claim():
    """planning#144 L3c-3: the candidate pool comes from the
    `reverse_hostname` claim, which is where claim_emitter's Table 1 puts
    what asset_metadata["shodan_hostnames"] used to hold."""
    ip = f"203.0.113.{150 + (uuid.uuid4().int % 40)}"
    db = SessionLocal()
    try:
        row = _seed_ip_with_reverse_hostname_claim(db, ip, ["a.example.com", "b.example.com"])
        assert sorted(oc._shodan_hostnames(db, row.id)) == ["a.example.com", "b.example.com"]
    finally:
        db.close()
        _cleanup_ip(ip)


def test_shodan_hostnames_empty_without_claim():
    """No claim -> [] (not an error). The caller unions this with
    HackerTarget's reverse-IP list, and an empty union is the
    graceful-degradation `attempted=False` signal."""
    ip = f"203.0.113.{60 + (uuid.uuid4().int % 40)}"
    db = SessionLocal()
    try:
        row = _seed_ip_with_reverse_hostname_claim(db, ip, None)
        assert oc._shodan_hostnames(db, row.id) == []
    finally:
        db.close()
        _cleanup_ip(ip)


if __name__ == "__main__":
    _run()
