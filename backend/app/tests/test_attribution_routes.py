"""The attribution on the detail routes (planning#358): `GET /api/assets/{id}`
and `GET /api/findings/{id}`, as an admin (read scope is covered at the
service level by test_attribution_chain_scope.py).

The world is a full chain: an ours organization, an entity it acquired, a
domain target with a claimed candidate and two signals, hostnames under it
pointing at one address, and a sighting on the address.

Synthetic data only: `acr-<hex>.example.org`, addresses `_a(0)` of
test_exposure_path.py.

Run with:  backend/scripts/test.sh app/tests/test_attribution_routes.py
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.connectors.base import ObservedEndpoint
from app.main import app
from app.schemas.attribution_chain import Attribution
from app.tests.test_attribution_chain import _Env
from app.tests.test_attribution_chain_scope import _full_world
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)

_DOM = f"acr-{uuid.uuid4().hex[:8]}.example.org"


@pytest.fixture(scope="module")
def admin():
    headers, uid = _make_user("admin")
    yield headers
    _cleanup_user(uid)


@pytest.fixture
def env():
    e = _Env()
    try:
        yield e
    finally:
        e.cleanup()


def _asset_body(admin, asset_id) -> dict:
    r = client.get(f"/api/assets/{asset_id}", headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


def _finding_world(env):
    """The full chain, plus one finding on the address."""
    w = _full_world(env, _DOM)
    (fid,) = env.xw.write(env.xw.finding(w.ip, [ObservedEndpoint(address=w.ip, port=443, protocol="tcp")]))
    return w, fid


def _expected(env, asset) -> dict:
    return env.build(asset).model_dump(mode="json")


def _assert_full_chain(attribution: dict) -> None:
    # Reached: the chain is the whole of it, not the no-target case.
    (chain,) = attribution["chains"]
    assert [h["kind"] for h in chain["hops"]] == ["organization", "entity", "scope", "host", "address"]
    assert chain["target_id"] is not None
    assert chain["hops"][0]["status"] == "observed"
    assert len(chain["hops"][2]["evidence"]) == 2


# 16 -----------------------------------------------------------------------


def test_the_asset_route_returns_the_built_attribution(env, admin):
    w = _full_world(env, _DOM)
    body = _asset_body(admin, w.ip_asset.id)
    _assert_full_chain(body["attribution"])
    assert body["attribution"] == _expected(env, w.ip_asset)
    assert body["id"] == str(w.ip_asset.id)  # the rest of the payload is still there


# 17 -----------------------------------------------------------------------


def test_the_finding_route_returns_the_same_attribution_and_still_the_paths(env, admin):
    w, fid = _finding_world(env)
    r = client.get(f"/api/findings/{fid}", headers=admin)
    assert r.status_code == 200, r.text
    body = r.json()
    _assert_full_chain(body["attribution"])
    assert body["attribution"] == _asset_body(admin, w.ip_asset.id)["attribution"]
    assert body["attribution"] == _expected(env, w.ip_asset)
    assert len(body["exposure_paths"]) == 1


# 18 -----------------------------------------------------------------------


def test_the_asset_list_does_not_carry_attribution(env, admin):
    w = _full_world(env, _DOM)
    r = client.get("/api/assets/?asset_type=ip_address", headers=admin)
    assert r.status_code == 200, r.text
    rows = [x for x in r.json() if x["id"] == str(w.ip_asset.id)]
    assert len(rows) == 1  # the asset is in the list, so the check below is not vacuous
    assert "attribution" not in rows[0]
    assert "attribution" in _asset_body(admin, w.ip_asset.id)


# 19 -----------------------------------------------------------------------


def _refs(node) -> list[str]:
    if isinstance(node, dict):
        out = [node["$ref"]] if isinstance(node.get("$ref"), str) else []
        for v in node.values():
            out += _refs(v)
        return out
    if isinstance(node, list):
        return [r for v in node for r in _refs(v)]
    return []


def _detail_schema(spec, path: str) -> dict:
    ok = spec["paths"][path]["get"]["responses"]["200"]
    ref = ok["content"]["application/json"]["schema"]["$ref"]
    return spec["components"]["schemas"][ref.rsplit("/", 1)[-1]]


def test_openapi_names_attribution_on_both_detail_responses():
    spec = app.openapi()
    for path, title in (
        ("/api/assets/{asset_id}", "AssetDetailResponse"),
        ("/api/findings/{finding_id}", "FindingDetailResponse"),
    ):
        detail = _detail_schema(spec, path)
        assert detail["title"] == title
        refs = [r.rsplit("/", 1)[-1] for r in _refs(detail["properties"]["attribution"])]
        assert refs == ["Attribution"], path
    # The finding's attribution is nullable (a finding with no asset).
    finding = _detail_schema(spec, "/api/findings/{finding_id}")
    assert {"type": "null"} in finding["properties"]["attribution"]["anyOf"]


# 20 -----------------------------------------------------------------------


def test_a_response_validates_against_the_model(env, admin):
    w, fid = _finding_world(env)
    asset_body = _asset_body(admin, w.ip_asset.id)
    parsed = Attribution.model_validate(asset_body["attribution"])
    assert [h.kind for h in parsed.chains[0].hops] == ["organization", "entity", "scope", "host", "address"]
    assert parsed.model_dump(mode="json") == asset_body["attribution"]
    finding_body = client.get(f"/api/findings/{fid}", headers=admin).json()
    assert Attribution.model_validate(finding_body["attribution"]) == parsed
