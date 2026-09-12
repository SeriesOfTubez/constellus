"""Tests for the Wiz cloud-inventory connector (planning#118a).

Covers the connector in isolation — no DB, no network. The HTTP layer is
replaced by stubbing `wiz.connector_post`, which is the single seam every
outbound call goes through.

Everything asserted here about Wiz's response shapes was verified against
the live tenant before being written down (see the module docstring of
`app/connectors/wiz.py`); the fixtures below reproduce those shapes rather
than inventing plausible ones. Addresses are RFC-5737 documentation ranges
throughout — no real address may appear in a tracked file (CLAUDE.md).

Run with:  python -m app.tests.test_wiz_ownership
       or: pytest app/tests/test_wiz_ownership.py
"""

import json

from app.connectors import wiz
from app.connectors.base import DiscoveredAsset
from app.models.asset import AssetType


# ── stub plumbing ──────────────────────────────────────────────────────────

class _Response:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("not json")
        return self._payload


class _Stub:
    """Stands in for connector_post. Records calls; serves token exchanges
    from a fixed payload and GraphQL posts from a per-IP script."""

    def __init__(self, by_ip=None, graphql_response=None):
        self.by_ip = by_ip or {}
        self.graphql_response = graphql_response
        self.calls = []
        self.token_calls = 0

    def __call__(self, url, *, headers=None, params=None, json=None, data=None, timeout=None, **kw):
        self.calls.append({"url": url, "json": json, "data": data, "headers": headers})
        if url == wiz._TOKEN_URL:
            self.token_calls += 1
            return _Response({"access_token": "stub-token", "expires_in": 86400})
        if self.graphql_response is not None:
            return self.graphql_response
        ip = (json or {}).get("variables", {}).get("filterBy", {}).get("destinationIpRange", [None])[0]
        nodes = self.by_ip.get(ip, [])
        return _Response({"data": {"networkExposures": {
            "nodes": nodes,
            "pageInfo": {"hasNextPage": False, "endCursor": None},
        }}})


def _install(monkey_stub, secrets=None, public_ips=False):
    """Swap the HTTP seam and the secrets lookup. Returns a restore callable.

    Raw attribute assignment matches this suite's convention; conftest.py's
    autouse fixture does not guard app.connectors.wiz, so this restores
    explicitly rather than relying on it.

    `public_ips=True` additionally stubs `_is_public_ip` to accept the
    RFC-5737 documentation addresses these tests are written with. That is
    not papering over a bug — Python's `ipaddress` classifies 192.0.2.0/24,
    198.51.100.0/24 and 203.0.113.0/24 as private (they are special-use, not
    globally routable), so the real filter correctly rejects every address
    this repo is permitted to write down. `test_public_ip_filter_*` below
    exercise the unstubbed function, so the filter itself stays covered;
    stubbing it here keeps the orchestration tests from being hostage to the
    address-hygiene rule (CLAUDE.md: no real address in a tracked file).
    """
    original_post = wiz.connector_post
    original_secret = wiz.get_secret
    original_sleep = wiz.time.sleep
    original_is_public = wiz._is_public_ip
    original_cache = dict(wiz._token_cache)

    values = secrets if secrets is not None else {
        "WIZ_CLIENT_ID": "id", "WIZ_CLIENT_SECRET": "secret",
        "WIZ_API_ENDPOINT": "https://api.example.invalid/graphql",
    }
    wiz.connector_post = monkey_stub
    wiz.get_secret = lambda key: values.get(key)
    wiz.time.sleep = lambda _seconds: None
    if public_ips:
        wiz._is_public_ip = lambda value: value.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    wiz._token_cache.clear()

    def restore():
        wiz.connector_post = original_post
        wiz.get_secret = original_secret
        wiz.time.sleep = original_sleep
        wiz._is_public_ip = original_is_public
        wiz._token_cache.clear()
        wiz._token_cache.update(original_cache)

    return restore


def _node(exposure_id, entity_id, name="resource", type_="VIRTUAL_MACHINE", deleted_at=None):
    return {
        "id": exposure_id,
        "type": "PUBLIC_INTERNET",
        # Live tenants return a /32 CIDR, a one-address range, a bare "-", or
        # a hostname here — never a plain IP. Nothing in the connector reads
        # it, which is the point; the value is present only so the fixture
        # matches the real payload.
        "destinationIpRange": "192.0.2.10/32",
        "firstSeenAt": "2026-01-01T00:00:00Z",
        "exposedEntity": {"id": entity_id, "name": name, "type": type_, "deletedAt": deleted_at},
    }


# ── the public-IP filter (exercised unstubbed) ─────────────────────────────

def test_public_ip_filter_excludes_non_routable_addresses():
    for value in [
        "10.0.0.1", "172.16.0.1", "192.168.1.1",  # RFC-1918
        "127.0.0.1", "::1",                        # loopback
        "169.254.1.1", "fe80::1",                  # link-local
        "224.0.0.1", "ff02::1",                    # multicast
        "0.0.0.0",                                 # unspecified
        "100.64.0.1",                              # CGNAT (RFC 6598) — the
        # case the six existing copies of this predicate get wrong
    ]:
        assert wiz._is_public_ip(value) is False, value


def test_public_ip_filter_excludes_documentation_ranges():
    """RFC-5737 / RFC-3849 ranges are special-use, not globally routable, so
    the real filter rejects them. This is why the enrich() tests stub it —
    see `_install` — and asserting it here keeps that stub honest: if the
    filter ever started accepting these, the stub would be masking a change
    rather than working around a constraint."""
    for value in ["192.0.2.10", "198.51.100.5", "203.0.113.7", "2001:db8::1"]:
        assert wiz._is_public_ip(value) is False, value


def test_public_ip_filter_accepts_globally_routable_addresses():
    """The positive half — a filter that rejected everything would pass all
    the exclusion tests above."""
    for value in ["8.8.8.8", "2606:4700::1111"]:
        assert wiz._is_public_ip(value) is True, value


def test_public_ip_filter_rejects_non_addresses_without_raising():
    for value in ["", "example.com", "not-an-ip", "192.0.2.10/32", "-"]:
        assert wiz._is_public_ip(value) is False, value


# ── _claim_from_nodes ──────────────────────────────────────────────────────

def test_no_nodes_yields_no_claim_not_a_negative_one():
    """Absence of evidence must not be recorded as evidence of absence.

    `cloud_inventory` is a positive assertion of ownership. Wiz not knowing
    an address is equally consistent with an uncovered cloud account, an
    on-prem address, or a graph entry still being built — so the connector
    returns None and lets the absence layer (planning#145) represent "we
    looked and found nothing" by the claim's absence."""
    assert wiz._claim_from_nodes([]) is None


def test_confirmed_claim_carries_resources_and_evidence():
    claim = wiz._claim_from_nodes([
        _node("exp-1", "res-b", name="web", type_="WEB_SERVICE"),
        _node("exp-2", "res-a", name="vm", type_="VIRTUAL_MACHINE"),
    ])
    assert claim["confirmed"] is True
    assert claim["resource_count"] == 2
    assert [r["id"] for r in claim["resources"]] == ["res-a", "res-b"]  # sorted, stable
    assert claim["exposure_count"] == 2
    assert claim["evidence_ref"] == ["exp-1", "exp-2"]


def test_authorised_names_is_empty_never_the_resource_names():
    """Wiz proves the ADDRESS is ours; it licenses no hostname.

    `exposedEntity.name` is a cloud resource name, not a DNS name. If it
    leaked into `authorised_names`, a name-addressed probe would be
    authorised to send traffic to a string nobody resolves."""
    claim = wiz._claim_from_nodes([_node("exp-1", "res-a", name="prod-web-lb")])
    assert claim["authorised_names"] == []
    assert "prod-web-lb" not in json.dumps(claim["authorised_names"])


def test_multiple_exposures_of_one_resource_collapse_to_one_resource():
    """Several nodes per IP are per-port rules for the same resource — the
    live round-trip returned up to 22 nodes and exactly one distinct
    entity."""
    claim = wiz._claim_from_nodes([_node(f"exp-{i}", "res-a") for i in range(22)])
    assert claim["resource_count"] == 1
    assert claim["exposure_count"] == 22


def test_deleted_resource_does_not_confirm_ownership():
    """A resource deleted in-cloud lingers in the Wiz graph for ~48h. Its
    address may already have been reassigned, so it must not keep
    authorising probes against it."""
    claim = wiz._claim_from_nodes([_node("exp-1", "res-a", deleted_at="2026-01-02T00:00:00Z")])
    assert claim is None


def test_deleted_resource_does_not_suppress_a_live_one_on_the_same_address():
    claim = wiz._claim_from_nodes([
        _node("exp-1", "res-dead", deleted_at="2026-01-02T00:00:00Z"),
        _node("exp-2", "res-live"),
    ])
    assert claim["resource_count"] == 1
    assert claim["resources"][0]["id"] == "res-live"


def test_missing_enrichment_fields_degrade_detail_not_the_verdict():
    """Nulls usually mean the graph is still building asynchronously, not
    that a module is unlicensed."""
    claim = wiz._claim_from_nodes([_node("exp-1", "res-a", name=None, type_=None)])
    assert claim["confirmed"] is True
    assert claim["resources"][0]["name"] is None


def test_entity_without_an_id_is_ignored():
    assert wiz._claim_from_nodes([_node("exp-1", None)]) is None


def test_resource_list_is_capped_but_the_count_is_not():
    nodes = [_node(f"exp-{i}", f"res-{i:03d}") for i in range(wiz._MAX_RESOURCES_PER_CLAIM + 5)]
    claim = wiz._claim_from_nodes(nodes)
    assert claim["resource_count"] == wiz._MAX_RESOURCES_PER_CLAIM + 5
    assert len(claim["resources"]) == wiz._MAX_RESOURCES_PER_CLAIM


# ── GraphQL transport ──────────────────────────────────────────────────────

def test_errors_array_is_fatal_even_on_http_200():
    """Wiz can return HTTP 200 with partial data AND an errors array, so the
    array is checked independently of the status code."""
    stub = _Stub(graphql_response=_Response({
        "data": {"networkExposures": {"nodes": [], "pageInfo": {}}},
        "errors": [{"message": "boom", "extensions": {"code": "RATE_LIMIT_EXCEEDED"}}],
    }, status_code=200))
    restore = _install(stub)
    try:
        raised = None
        try:
            wiz._graphql("https://api.example.invalid/graphql", "tok", "query {}", {})
        except RuntimeError as exc:
            raised = str(exc)
        assert raised is not None
        assert "RATE_LIMIT_EXCEEDED" in raised
    finally:
        restore()


def test_non_json_body_is_reported_not_swallowed():
    stub = _Stub(graphql_response=_Response("<html>502</html>", status_code=502))
    restore = _install(stub)
    try:
        raised = None
        try:
            wiz._graphql("https://api.example.invalid/graphql", "tok", "query {}", {})
        except RuntimeError as exc:
            raised = str(exc)
        assert raised is not None and "502" in raised
    finally:
        restore()


def test_query_uses_variables_and_never_interpolates_the_address():
    """Our tenant drops variables on introspection but honours them on real
    queries, so the connector must keep using them — an interpolated
    document would be the injection-shaped path."""
    stub = _Stub(by_ip={"192.0.2.10": [_node("exp-1", "res-a")]})
    restore = _install(stub)
    try:
        wiz._exposures_for_ip("https://api.example.invalid/graphql", "tok", "192.0.2.10")
        gql_calls = [c for c in stub.calls if c["url"] != wiz._TOKEN_URL]
        assert len(gql_calls) == 1
        body = gql_calls[0]["json"]
        assert body["variables"]["filterBy"]["destinationIpRange"] == ["192.0.2.10"]
        assert body["variables"]["filterBy"]["type"] == ["PUBLIC_INTERNET"]
        assert "192.0.2.10" not in body["query"]
    finally:
        restore()


def test_pagination_follows_the_cursor_and_stops():
    pages = [
        _Response({"data": {"networkExposures": {
            "nodes": [_node("exp-1", "res-a")],
            "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"}}}}),
        _Response({"data": {"networkExposures": {
            "nodes": [_node("exp-2", "res-b")],
            "pageInfo": {"hasNextPage": False, "endCursor": None}}}}),
    ]
    seen_cursors = []

    def post(url, *, headers=None, params=None, json=None, data=None, timeout=None, **kw):
        if url == wiz._TOKEN_URL:
            return _Response({"access_token": "t", "expires_in": 86400})
        seen_cursors.append(json["variables"]["after"])
        return pages[len(seen_cursors) - 1]

    restore = _install(post)
    try:
        nodes = wiz._exposures_for_ip("https://api.example.invalid/graphql", "tok", "192.0.2.10")
        assert len(nodes) == 2
        assert seen_cursors == [None, "cursor-1"]
    finally:
        restore()


def test_pagination_stops_at_the_page_limit_rather_than_looping_forever():
    def post(url, *, headers=None, params=None, json=None, data=None, timeout=None, **kw):
        if url == wiz._TOKEN_URL:
            return _Response({"access_token": "t", "expires_in": 86400})
        return _Response({"data": {"networkExposures": {
            "nodes": [_node("exp", "res-a")],
            "pageInfo": {"hasNextPage": True, "endCursor": "always-more"}}}})

    restore = _install(post)
    try:
        nodes = wiz._exposures_for_ip("https://api.example.invalid/graphql", "tok", "192.0.2.10")
        assert len(nodes) == wiz._PAGE_LIMIT
    finally:
        restore()


# ── token caching ──────────────────────────────────────────────────────────

def test_token_is_fetched_once_and_reused_across_addresses():
    """Wiz rate-limits the token endpoint per service account and asks
    integrations to cache for the full 24h validity."""
    stub = _Stub(by_ip={f"192.0.2.{i}": [_node(f"exp-{i}", "res-a")] for i in range(1, 6)})
    restore = _install(stub, public_ips=True)
    try:
        assets = [DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value=f"192.0.2.{i}") for i in range(1, 6)]
        wiz.WizConnector().enrich(assets, {})
        assert stub.token_calls == 1
    finally:
        restore()


def test_token_cache_is_keyed_by_client_id_so_rotation_is_not_served_stale():
    stub = _Stub()
    restore = _install(stub)
    try:
        wiz._get_token("client-a", "secret-a")
        wiz._get_token("client-a", "secret-a")
        assert stub.token_calls == 1
        wiz._get_token("client-b", "secret-b")
        assert stub.token_calls == 2
    finally:
        restore()


def test_token_failure_reports_status_only_never_the_body():
    """A failed token exchange can echo credential material back in its
    body, so the error carries the status code alone."""
    stub = _Stub(graphql_response=None)

    def post(url, *, headers=None, params=None, json=None, data=None, timeout=None, **kw):
        return _Response({"error": "invalid_client", "client_secret": "SUPERSECRET"}, status_code=401)

    restore = _install(post)
    try:
        raised = None
        try:
            wiz._get_token("id", "secret")
        except RuntimeError as exc:
            raised = str(exc)
        assert raised is not None
        assert "401" in raised
        assert "SUPERSECRET" not in raised
        assert "invalid_client" not in raised
    finally:
        restore()


# ── enrich() ───────────────────────────────────────────────────────────────

def test_enrich_emits_one_asset_per_confirmed_ip_attributed_to_wiz():
    stub = _Stub(by_ip={
        "192.0.2.10": [_node("exp-1", "res-a")],
        "192.0.2.11": [],  # known to Wiz's API, but no exposure -> no claim
    })
    restore = _install(stub, public_ips=True)
    try:
        assets = [
            DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value="192.0.2.10"),
            DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value="192.0.2.11"),
        ]
        result = wiz.WizConnector().enrich(assets, {})
        assert len(result.assets) == 1
        emitted = result.assets[0]
        assert emitted.value == "192.0.2.10"
        assert emitted.observer == "wiz"
        assert emitted.asset_metadata["sources"] == ["wiz"]
        assert emitted.asset_metadata["cloud_inventory"]["confirmed"] is True
        assert result.findings == []
    finally:
        restore()


def test_enrich_skips_private_and_non_ip_assets_without_a_network_call():
    stub = _Stub()
    restore = _install(stub)
    try:
        assets = [
            DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value="10.0.0.1"),
            DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value="127.0.0.1"),
            DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value="169.254.1.1"),
            DiscoveredAsset(asset_type=AssetType.DNS_RECORD, value="example.com"),
        ]
        result = wiz.WizConnector().enrich(assets, {})
        assert result.assets == []
        assert stub.calls == []  # not even a token exchange
    finally:
        restore()


def test_enrich_deduplicates_repeated_addresses():
    stub = _Stub(by_ip={"192.0.2.10": [_node("exp-1", "res-a")]})
    restore = _install(stub, public_ips=True)
    try:
        assets = [DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value="192.0.2.10") for _ in range(4)]
        result = wiz.WizConnector().enrich(assets, {})
        assert len(result.assets) == 1
        assert len([c for c in stub.calls if c["url"] != wiz._TOKEN_URL]) == 1
    finally:
        restore()


def test_one_failing_address_does_not_abandon_the_batch():
    def post(url, *, headers=None, params=None, json=None, data=None, timeout=None, **kw):
        if url == wiz._TOKEN_URL:
            return _Response({"access_token": "t", "expires_in": 86400})
        ip = json["variables"]["filterBy"]["destinationIpRange"][0]
        if ip == "192.0.2.11":
            raise RuntimeError("transient")
        return _Response({"data": {"networkExposures": {
            "nodes": [_node("exp-1", "res-a")], "pageInfo": {"hasNextPage": False}}}})

    restore = _install(post, public_ips=True)
    try:
        assets = [DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value=f"192.0.2.{i}") for i in (10, 11, 12)]
        result = wiz.WizConnector().enrich(assets, {})
        assert sorted(a.value for a in result.assets) == ["192.0.2.10", "192.0.2.12"]
    finally:
        restore()


def test_enrich_is_inert_without_credentials():
    stub = _Stub()
    restore = _install(stub, secrets={"WIZ_CLIENT_ID": "id", "WIZ_CLIENT_SECRET": "secret"})  # no endpoint
    try:
        assets = [DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value="192.0.2.10")]
        assert wiz.WizConnector().enrich(assets, {}).assets == []
        assert stub.calls == []
    finally:
        restore()


def test_enrich_survives_a_token_failure_without_raising_into_the_scan():
    def post(url, *, headers=None, params=None, json=None, data=None, timeout=None, **kw):
        return _Response({"error": "nope"}, status_code=500)

    restore = _install(post, public_ips=True)
    try:
        assets = [DiscoveredAsset(asset_type=AssetType.IP_ADDRESS, value="192.0.2.10")]
        assert wiz.WizConnector().enrich(assets, {}).assets == []
    finally:
        restore()


if __name__ == "__main__":
    for name, fn in sorted(list(globals().items())):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
    print("all wiz ownership tests passed")
