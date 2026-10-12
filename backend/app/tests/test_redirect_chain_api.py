"""`redirect_chain` on every web endpoint state (planning#271).

The hops are recorded by `app.services.redirect_follow` (planning#268); the API
only reads them. Synthetic data only. Reuses the `world` / `admin` fixtures and
helpers from test_web_classifier (imported so pytest finds the fixtures).
"""

import uuid

from sqlalchemy import event

from app.core.database import SessionLocal, engine
from app.models.http_redirect_hop import HttpRedirectHop
from app.services import read_scope
from app.tests.test_web_classifier import (  # noqa: F401  (fixtures are used by name)
    SSH_PORT, TITLE, _endpoint_items, _web_port, admin, client, world,
)

HOP_TITLE = "Fabrikam Sign In"


def _add_hops(origin, port, specs, *, scheme="https") -> None:
    """specs: dicts of hop fields (hop_index, url, followed, ...). Inserted in
    the order given, in one transaction."""
    db = SessionLocal()
    try:
        for s in specs:
            db.add(HttpRedirectHop(origin_asset_id=origin, origin_port=port, origin_scheme=scheme, **s))
        db.commit()
    finally:
        db.close()


def _get(asset_id, headers) -> dict[int, dict]:
    r = client.get(f"/api/assets/{asset_id}/web-classifications", headers=headers)
    assert r.status_code == 200, r.text
    return {e["port"]: e for e in r.json()["endpoints"]}


def _listed(headers, *asset_ids) -> dict[tuple[str, int], dict]:
    wanted = {str(a) for a in asset_ids}
    return {(i["asset_id"], i["port"]): i for i in _endpoint_items(headers) if i["asset_id"] in wanted}


def _hop(index, url, *, followed=True, reason=None, status=200, title=None, asset=None) -> dict:
    return dict(hop_index=index, url=url, followed=followed, reason=reason, http_status=status,
                http_title=title, hop_asset_id=asset)


def test_chain_is_in_hop_order_with_every_field_and_keeps_the_endpoints_own_title(world, admin):
    headers, _ = admin
    hop_asset = world.asset(value=f"login-{uuid.uuid4().hex[:6]}.fabrikam.example")
    a = world.asset(ports=[_web_port(443, http_title=None, http_status=302)])
    # Hop 2 is inserted first: insertion order is the reverse of hop order.
    hops1 = [_hop(2, "https://login.fabrikam.example/signin", title=HOP_TITLE, asset=hop_asset),
             _hop(1, "https://www.fabrikam.example/", status=301)]
    _add_hops(a, 443, hops1)

    ep = _get(a, headers)[443]  # reached: the endpoint is in the response
    assert ep["redirect_chain"] == [
        {"hop_index": 1, "url": "https://www.fabrikam.example/", "followed": True, "reason": None,
         "http_status": 301, "http_title": None, "hop_asset_id": None},
        {"hop_index": 2, "url": "https://login.fabrikam.example/signin", "followed": True, "reason": None,
         "http_status": 200, "http_title": HOP_TITLE, "hop_asset_id": str(hop_asset)},
    ]
    assert ep["http_title"] is None and ep["http_status"] == 302  # the origin's own, not the last hop's


def test_a_refused_hop_comes_back_as_refused(world, admin):
    headers, _ = admin
    a = world.asset(ports=[_web_port(443)])
    _add_hops(a, 443, [_hop(1, "https://partner.fabrikam.example/", followed=False,
                            reason="posture:passive_only", status=None)])
    ep = _get(a, headers)[443]
    assert ep["redirect_chain"] == [
        {"hop_index": 1, "url": "https://partner.fabrikam.example/", "followed": False,
         "reason": "posture:passive_only", "http_status": None, "http_title": None, "hop_asset_id": None}]
    assert ep["http_title"] == TITLE


def test_endpoints_without_hops_get_an_empty_chain_and_non_web_ports_never_show_one(world, admin):
    headers, _ = admin
    a = world.asset(ports=[_web_port(443), _web_port(8443), SSH_PORT])
    _add_hops(a, 443, [_hop(1, "https://www.fabrikam.example/", title=HOP_TITLE)])
    _add_hops(a, 22, [_hop(1, "https://ssh.fabrikam.example/", title="Never shown")])
    eps = _get(a, headers)
    assert set(eps) == {443, 8443}  # reached: 22 is not a web endpoint
    assert [h["hop_index"] for h in eps[443]["redirect_chain"]] == [1]
    assert eps[8443]["redirect_chain"] == []
    assert "Never shown" not in str(eps)


def test_web_endpoints_listing_carries_the_chain_per_asset_and_port_without_leaking(world, admin):
    headers, _ = admin
    a = world.asset(ports=[_web_port(443), _web_port(8443)])
    b = world.asset(ports=[_web_port(443)])
    _add_hops(a, 443, [_hop(1, "https://a-one.fabrikam.example/", title="A one")])
    _add_hops(b, 443, [_hop(1, "https://b-one.fabrikam.example/", followed=False, reason="loop", status=None),
                       _hop(2, "https://b-two.fabrikam.example/", followed=False, reason="hop_cap", status=None)])
    items = _listed(headers, a, b)
    assert set(items) == {(str(a), 443), (str(a), 8443), (str(b), 443)}  # reached
    assert [h["url"] for h in items[(str(a), 443)]["redirect_chain"]] == ["https://a-one.fabrikam.example/"]
    assert items[(str(a), 8443)]["redirect_chain"] == []
    assert [(h["url"], h["reason"]) for h in items[(str(b), 443)]["redirect_chain"]] == [
        ("https://b-one.fabrikam.example/", "loop"), ("https://b-two.fabrikam.example/", "hop_cap")]
    assert items[(str(a), 443)]["http_title"] == TITLE  # the endpoint's own title


def _hop_statements(fn) -> int:
    """Statements of the redirect_chain read. web_classifier's own per-asset
    `_titles_after_redirect` also reads the table (one query per asset, from
    before planning#271); it has no join, the chain read joins the hop asset."""
    seen = []

    def _listener(conn, cursor, statement, parameters, context, executemany):
        if "http_redirect_hops" in statement and "JOIN assets_canonical" in statement:
            seen.append(statement)

    event.listen(engine, "before_cursor_execute", _listener)
    try:
        fn()
    finally:
        event.remove(engine, "before_cursor_execute", _listener)
    return len(seen)


def test_the_listing_loads_all_chains_in_one_statement(world, admin):
    headers, _ = admin

    def with_chains(n):
        ids = []
        for _ in range(n):
            a = world.asset(ports=[_web_port(443)])
            _add_hops(a, 443, [_hop(1, "https://www.fabrikam.example/", title=HOP_TITLE)])
            ids.append(a)
        return ids

    def run(ids):
        got = {}
        return _hop_statements(lambda: got.update(_listed(headers, *ids))), got

    count, got = run(with_chains(1))
    assert len(got) == 1 and all(len(i["redirect_chain"]) == 1 for i in got.values())  # reached
    assert count == 1

    count, got = run(with_chains(3))
    assert len(got) == 3 and all(len(i["redirect_chain"]) == 1 for i in got.values())  # reached
    assert count == 1


def test_hop_asset_id_is_given_only_when_the_caller_can_read_that_asset(world, admin, monkeypatch):
    headers, _ = admin
    hidden = world.asset(value=f"hidden-{uuid.uuid4().hex[:6]}.fabrikam.example")
    visible = world.asset(value=f"open-{uuid.uuid4().hex[:6]}.fabrikam.example")
    a = world.asset(ports=[_web_port(443)])
    _add_hops(a, 443, [
        _hop(1, "https://hidden.fabrikam.example/", status=301, title="Hidden title", asset=hidden),
        _hop(2, "https://open.fabrikam.example/", title="Open title", asset=visible),
        _hop(3, "https://unknown.fabrikam.example/", title="Unknown title", asset=None),
    ])

    def ids():
        return [h["hop_asset_id"] for h in _get(a, headers)[443]["redirect_chain"]]

    assert ids() == [str(hidden), str(visible), None]  # precondition: readable before the patch

    original = read_scope.asset_clause

    def clause(user, asset):
        return original(user, asset) & (asset.id != hidden)

    monkeypatch.setattr(read_scope, "asset_clause", clause)
    chain = _get(a, headers)[443]["redirect_chain"]  # the origin itself is still readable
    assert [h["hop_asset_id"] for h in chain] == [None, str(visible), None]
    assert [(h["url"], h["http_title"]) for h in chain] == [
        ("https://hidden.fabrikam.example/", "Hidden title"), ("https://open.fabrikam.example/", "Open title"),
        ("https://unknown.fabrikam.example/", "Unknown title")]


def test_the_admin_put_response_carries_the_chain_too(world, admin):
    headers, _ = admin
    a = world.asset(ports=[_web_port(443)])
    _add_hops(a, 443, [_hop(1, "https://www.fabrikam.example/", title=HOP_TITLE)])
    r = client.put(f"/api/assets/{a}/web-endpoints/443/classification", headers=headers,
                   json={"kind": "login_portal", "environment": "production"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source"] == "user"  # reached: the correction was applied
    assert [(h["hop_index"], h["url"], h["http_title"]) for h in body["redirect_chain"]] == [
        (1, "https://www.fabrikam.example/", HOP_TITLE)]
    assert body["http_title"] == TITLE
