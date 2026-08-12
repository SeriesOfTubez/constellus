"""Tests for app.services.domain_affinity's _score_port scoring logic
(planning#81 Phase B — distinguishing "origin completely dead" from a merely
ambiguous indeterminate verdict, the Low-tier trigger for dangling_dns; and a
follow-up fix where a negative owned-side status is evidence on its own even
when the default side never answers at all).

Pure-assert style: no pytest dependency required, no live network I/O —
_probe_worker is monkeypatched per the test_prune_stale_ports.py convention.
Run with:  python -m app.tests.test_domain_affinity_unreachable   (from /app)
       or: pytest app/tests/test_domain_affinity_unreachable.py
"""

import app.services.domain_affinity as da


def test_fully_dead_origin_sets_unreachable_votes():
    """Every probed port unreachable on both sides -> indeterminate, and
    unreachable_votes accounts for every port (the Low-tier signal)."""
    def fake_probe(hostname, origin_ip, ports=None):
        return {"ports": {
            "443": {"owned": {}, "default": {}},
            "80": {"owned": {}, "default": {}},
        }}
    da._probe_worker = fake_probe
    r = da.check_affinity("test.example.com", "203.0.113.5", {"example.com"})
    assert r.verdict == da.VERDICT_INDETERMINATE
    assert r.unreachable_votes == len(r.matrix) == 2


def test_ambiguous_indeterminate_does_not_set_unreachable_votes():
    """Both sides reachable but identity-indistinguishable -> indeterminate,
    but NOT the "origin dead" case — unreachable_votes must stay 0 so Low-tier
    routing doesn't misfire on genuine ambiguity."""
    def fake_probe(hostname, origin_ip, ports=None):
        same = {"status_code": 200, "webserver": "nginx", "tls_ok": True}
        return {"ports": {"443": {"owned": dict(same), "default": dict(same)}}}
    da._probe_worker = fake_probe
    r = da.check_affinity("test.example.com", "203.0.113.5", {"example.com"})
    assert r.verdict == da.VERDICT_INDETERMINATE
    assert r.unreachable_votes == 0


def test_mixed_ports_not_fully_unreachable():
    """One port dead, one port affine -> affine wins the verdict (existing
    behavior unchanged) and unreachable_votes reflects only the dead port,
    not every port — Low-tier routing requires unreachable_votes == len(matrix)."""
    def fake_probe(hostname, origin_ip, ports=None):
        return {"ports": {
            "443": {"owned": {"sans": ["test.example.com"]}, "default": {}},
            "80": {"owned": {}, "default": {}},
        }}
    da._probe_worker = fake_probe
    r = da.check_affinity("test.example.com", "203.0.113.5", {"example.com"})
    assert r.verdict == da.VERDICT_AFFINE
    assert r.unreachable_votes == 1
    assert r.unreachable_votes != len(r.matrix)


def test_owned_negative_status_is_not_affine_even_with_default_unreachable():
    """A 404/400-class owned response is reachable, not evidence-free — it
    means "nothing here for our hostname" on its own, even when the default
    (no-SNI) probe gets nothing back at all. Live-verified: a
    Cloudflare-fronted origin returned this exact shape for a hostname
    Cloudflare had no zone config for."""
    def fake_probe(hostname, origin_ip, ports=None):
        return {"ports": {
            "443": {"owned": {"status_code": 404, "tls_ok": True}, "default": {}},
        }}
    da._probe_worker = fake_probe
    r = da.check_affinity("test.example.com", "203.0.113.5", {"example.com"})
    assert r.verdict == da.VERDICT_NOT_AFFINE
    assert r.unreachable_votes == 0


def test_owned_positive_status_still_abstains_with_default_unreachable():
    """Regression guard: a POSITIVE owned response with nothing to compare
    against must stay a true abstention (normal single-vhost host) — only
    negative owned statuses get treated as evidence on their own."""
    def fake_probe(hostname, origin_ip, ports=None):
        return {"ports": {
            "443": {"owned": {"status_code": 200, "tls_ok": True}, "default": {}},
        }}
    da._probe_worker = fake_probe
    r = da.check_affinity("test.example.com", "203.0.113.5", {"example.com"})
    assert r.verdict == da.VERDICT_INDETERMINATE
    assert r.unreachable_votes == 0


def _run():
    tests = [
        test_fully_dead_origin_sets_unreachable_votes,
        test_ambiguous_indeterminate_does_not_set_unreachable_votes,
        test_mixed_ports_not_fully_unreachable,
        test_owned_negative_status_is_not_affine_even_with_default_unreachable,
        test_owned_positive_status_still_abstains_with_default_unreachable,
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
