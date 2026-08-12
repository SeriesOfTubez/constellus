"""Tests for the severity-tier routing logic in
app.services.dangling_dns_analyzer (planning#104/#105, epic#81 Phase B;
planning#106 Phase C corroboration promotion; planning#114 Phase D
follow-up L2 — the three-way outcome + cadence gate).

Deterministic, no DB / no live network I/O — domain_affinity.resolve_origin/
check_affinity, takeover_fingerprint.find_takeover_signal, and
origin_corroboration.corroborate_liveness are monkeypatched per the
test_domain_affinity_unreachable.py convention. _evaluate_record only reads
.id/.value/.asset_metadata off its `record` argument, so a plain
SimpleNamespace stands in for a real AssetCanonical row.

Pure-assert style: no pytest dependency required.
Run with:  python -m app.tests.test_dangling_dns_routing        (from /app)
       or: pytest app/tests/test_dangling_dns_routing.py
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from app.services import dangling_dns_analyzer as dda
from app.services import domain_affinity as da
from app.services import origin_corroboration as oc
from app.services import takeover_fingerprint as tf

_SINCE = datetime(2026, 1, 1, tzinfo=timezone.utc)
_NO_APEXES: set[str] = set()


def _record(value, record_type="A", content="203.0.113.5", cdn=None):
    return SimpleNamespace(
        id=uuid.uuid4(),
        value=value,
        asset_metadata={"record_type": record_type, "content": content, "cdn": cdn},
    )


def _affinity_result(verdict, unreachable_votes=0, matrix=None, signals=None):
    return da.AffinityResult(
        hostname="test.example.com", origin_ip="203.0.113.5", verdict=verdict,
        signals=signals or [], matrix=matrix if matrix is not None else {"443": {}},
        unreachable_votes=unreachable_votes,
    )


def _no_corroboration(db, origin_ip, subject_value, owned_apexes):
    return oc.CorroborationResult(attempted=False)


def test_high_tier_wins_regardless_of_cdn():
    """A takeover fingerprint hit is High, checked before CDN status or
    affinity — should win even on a CDN-annotated record."""
    tf.find_takeover_signal = lambda db, asset_id, since: {
        "finding_id": uuid.uuid4(), "template_id": "aws-s3-takeover", "title": "t", "matched_at": "x",
    }
    record = _record("cdn.example.com", "CNAME", cdn="cloudfront.net")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_HIT
    assert result.tier_result["tier"] == dda.TIER_HIGH
    assert result.tier_result["layer"] == dda.LAYER_FINGERPRINT
    assert result.probed is False


def test_fingerprint_hit_fires_even_when_gate_closed():
    """Layer 2 is a free DB query, never gated (planning#114) — a
    fingerprint hit must fire regardless of the cadence/budget gate."""
    tf.find_takeover_signal = lambda db, asset_id, since: {
        "finding_id": uuid.uuid4(), "template_id": "aws-s3-takeover", "title": "t", "matched_at": "x",
    }
    record = _record("gated.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=False)
    assert result.status == dda.STATUS_HIT
    assert result.tier_result["layer"] == dda.LAYER_FINGERPRINT


def test_gate_closed_skips_without_probing():
    """planning#114: a closed cadence/budget gate must skip the record
    without ever attempting Layer 1 (no resolve_origin call) — the
    fingerprint miss alone isn't enough to justify a live probe attempt."""
    tf.find_takeover_signal = lambda db, asset_id, since: None
    called = {"resolve_origin": False}

    def _should_not_be_called(db, record):
        called["resolve_origin"] = True
        return "203.0.113.5"
    da.resolve_origin = _should_not_be_called

    record = _record("gated.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=False)
    assert result.status == dda.STATUS_SKIPPED
    assert result.probed is False
    assert called["resolve_origin"] is False


def test_medium_tier_on_not_affine():
    tf.find_takeover_signal = lambda db, asset_id, since: None
    da.resolve_origin = lambda db, record: "203.0.113.5"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_NOT_AFFINE)
    oc.corroborate_liveness = _no_corroboration
    record = _record("shared.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_HIT
    assert result.tier_result["tier"] == dda.TIER_MEDIUM
    assert result.tier_result["layer"] == dda.LAYER_AFFINITY_NOT_AFFINE
    assert result.probed is True


def test_low_tier_on_fully_unreachable_origin():
    tf.find_takeover_signal = lambda db, asset_id, since: None
    da.resolve_origin = lambda db, record: "203.0.113.5"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(
        da.VERDICT_INDETERMINATE, unreachable_votes=2, matrix={"443": {}, "80": {}},
    )
    oc.corroborate_liveness = _no_corroboration
    record = _record("dead.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_HIT
    assert result.tier_result["tier"] == dda.TIER_LOW
    assert result.tier_result["layer"] == dda.LAYER_AFFINITY_UNREACHABLE
    assert result.probed is True


def test_low_promoted_to_medium_on_strong_corroboration():
    """planning#106: a strong corroboration hit (origin alive for another
    Shodan-known hostname) promotes an otherwise-Low finding to Medium —
    the Low tier's premise (origin dead) is directly falsified."""
    tf.find_takeover_signal = lambda db, asset_id, since: None
    da.resolve_origin = lambda db, record: "203.0.113.5"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(
        da.VERDICT_INDETERMINATE, unreachable_votes=2, matrix={"443": {}, "80": {}},
    )
    oc.corroborate_liveness = lambda db, origin_ip, subject_value, owned_apexes: oc.CorroborationResult(
        attempted=True, origin_serves_others=True,
        corroborating_hostname="othertenant.com", evidence="tls_san_match",
        hostnames_probed=["othertenant.com"],
    )
    record = _record("dead.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_HIT
    assert result.tier_result["tier"] == dda.TIER_MEDIUM
    assert result.tier_result["layer"] == dda.LAYER_AFFINITY_CORROBORATED_ALIVE
    assert result.tier_result["corroboration"].corroborating_hostname == "othertenant.com"


def test_low_stays_low_on_weak_or_absent_corroboration():
    """A weak hit (bare 2xx, no cert match) or no corroboration data at all
    must NOT promote — only a strong (cert-SAN-match) hit does."""
    tf.find_takeover_signal = lambda db, asset_id, since: None
    da.resolve_origin = lambda db, record: "203.0.113.5"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(
        da.VERDICT_INDETERMINATE, unreachable_votes=2, matrix={"443": {}, "80": {}},
    )
    oc.corroborate_liveness = lambda db, origin_ip, subject_value, owned_apexes: oc.CorroborationResult(
        attempted=True, origin_serves_others=False,
        corroborating_hostname="maybe.example.com", evidence="http_2xx",
        hostnames_probed=["maybe.example.com"],
    )
    record = _record("dead.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_HIT
    assert result.tier_result["tier"] == dda.TIER_LOW
    assert result.tier_result["layer"] == dda.LAYER_AFFINITY_UNREACHABLE


def test_silent_on_ambiguous_indeterminate():
    """Indeterminate but NOT every port unreachable -> probed_clean (Low
    tier must not misfire on genuine ambiguity)."""
    tf.find_takeover_signal = lambda db, asset_id, since: None
    da.resolve_origin = lambda db, record: "203.0.113.5"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(
        da.VERDICT_INDETERMINATE, unreachable_votes=0, matrix={"443": {}},
    )
    record = _record("ambiguous.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_PROBED_CLEAN
    assert result.probed is True


def test_silent_on_affine():
    tf.find_takeover_signal = lambda db, asset_id, since: None
    da.resolve_origin = lambda db, record: "203.0.113.5"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(da.VERDICT_AFFINE)
    record = _record("healthy.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_PROBED_CLEAN
    assert result.probed is True


def test_cdn_touched_this_run_is_probed_clean():
    """CDN-annotated, no fingerprint hit, gate open (touched this run) ->
    probed_clean (Layer 1 never attempted, but this run's fresh evidence is
    "still CDN-fronted, no signature") — not stamped though, since no origin
    probe actually ran."""
    tf.find_takeover_signal = lambda db, asset_id, since: None
    called = {"resolve_origin": False}

    def _should_not_be_called(db, record):
        called["resolve_origin"] = True
        return "203.0.113.5"
    da.resolve_origin = _should_not_be_called

    record = _record("cdn.example.com", "CNAME", cdn="cloudfront.net")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_PROBED_CLEAN
    assert result.probed is False
    assert called["resolve_origin"] is False


def test_cdn_scope_only_untouched_is_skipped():
    """CDN-annotated, gate closed (scope-only, never touched, permanently
    excluded from the budget-gated bucket per planning#114 regression #2) ->
    skipped_not_judged, same code path as any other gate-closed record."""
    tf.find_takeover_signal = lambda db, asset_id, since: None
    record = _record("cdn.example.com", "CNAME", cdn="cloudfront.net")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=False)
    assert result.status == dda.STATUS_SKIPPED
    assert result.probed is False


def test_empty_probe_matrix_is_skipped_not_probed_clean():
    """planning#114 regression #1: an empty matrix (scanner-worker fully
    unreachable) must be skipped_not_judged, not treated as clean — a
    worker outage must never silently resolve open findings."""
    tf.find_takeover_signal = lambda db, asset_id, since: None
    da.resolve_origin = lambda db, record: "203.0.113.5"
    da.check_affinity = lambda hostname, origin_ip, apexes, ports=None: _affinity_result(
        da.VERDICT_INDETERMINATE, unreachable_votes=0, matrix={},
    )
    record = _record("worker-down.example.com", "A")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_SKIPPED
    assert result.probed is False


def test_silent_when_origin_unresolvable():
    tf.find_takeover_signal = lambda db, asset_id, since: None
    da.resolve_origin = lambda db, record: None
    record = _record("norecord.example.com", "CNAME")
    result = dda._evaluate_record(None, record, _SINCE, _NO_APEXES, gate_open=True)
    assert result.status == dda.STATUS_PROBED_CLEAN
    assert result.probed is True


def _run():
    tests = [
        test_high_tier_wins_regardless_of_cdn,
        test_fingerprint_hit_fires_even_when_gate_closed,
        test_gate_closed_skips_without_probing,
        test_medium_tier_on_not_affine,
        test_low_tier_on_fully_unreachable_origin,
        test_low_promoted_to_medium_on_strong_corroboration,
        test_low_stays_low_on_weak_or_absent_corroboration,
        test_silent_on_ambiguous_indeterminate,
        test_silent_on_affine,
        test_cdn_touched_this_run_is_probed_clean,
        test_cdn_scope_only_untouched_is_skipped,
        test_empty_probe_matrix_is_skipped_not_probed_clean,
        test_silent_when_origin_unresolvable,
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
