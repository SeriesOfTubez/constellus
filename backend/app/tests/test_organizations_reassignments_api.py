"""GET /api/organizations/{org_id}/reassignments and the `reassigned` filter on
the candidates list (planning#278 S3c3b2, slice B).

Synthetic data only: RFC 3849 prefixes, `EXAMPLE-*` handles. Cleanup is the
World's (its purge deletes reassignments before candidates and evidence).

Run with:  scripts/test.sh app/tests/test_organizations_reassignments_api.py
"""

import ipaddress
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import false, true

from app.models.user import UserRole
from app.services import read_scope
from app.services.org_discovery import candidates as cd
from app.services.org_discovery.reassignment import Reassigned, record_reassignment
from app.tests._org_world import client

# Reused fixtures (a throwaway World; the cloud-ranges meta row a CIDR claim needs).
from app.tests.test_org_discovery_asn_cidr import _cidr, meta, w  # noqa: F401

VIEWER = UserRole.VIEWER.value
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _half(cand, upper=False):
    """A /65 inside the candidate's /64 (2001:db8:278:n::/64)."""
    lower, upper_half = ipaddress.ip_network(cand.value).subnets(prefixlen_diff=1)
    return str(upper_half if upper else lower)


def _claimed(w, root, n):
    cand = _cidr(w, root, n)
    result = cd.claim(w.db, candidate_id=cand.id, user=w.user())
    w.track_target(result.target.value)
    w.db.commit()
    return cand


def _reassign(w, cand, prefix, kind, handle, seen):
    ev = w.evidence_row()
    record_reassignment(
        w.db, candidate_id=cand.id, found=Reassigned(prefix, kind, handle), evidence_id=ev.id, now=seen
    )
    w.db.commit()
    return ev


def _get(w, root, params=None, headers=None):
    return client.get(
        f"/api/organizations/{root.id}/reassignments", params=params or {}, headers=headers or w.headers(role=VIEWER)
    )


@pytest.fixture
def world(w, meta):  # noqa: F811
    """Root A with claimed c1 (two rows), c2 (one row), c0 (none); root B with c3 (one row)."""
    a, b = w.ours(), w.ours()
    c0, c1, c2 = _claimed(w, a, 0), _claimed(w, a, 1), _claimed(w, a, 2)
    c3 = _claimed(w, b, 3)
    ev1 = _reassign(w, c1, _half(c1), "org", "EXAMPLE-B", T0)
    ev2 = _reassign(w, c1, _half(c1, upper=True), "unregistered", None, T0 + timedelta(days=2))
    ev3 = _reassign(w, c2, _half(c2), "customer", "EXAMPLE-C", T0 + timedelta(days=1))
    _reassign(w, c3, _half(c3), "org", "EXAMPLE-D", T0 + timedelta(days=3))
    w.a, w.b, w.c0, w.c1, w.c2, w.c3 = a, b, c0, c1, c2, c3
    w.ev = (ev1, ev2, ev3)
    return w


def test_lists_this_roots_rows_with_every_field_ordered_by_last_seen_desc(world):
    w = world
    r = _get(w, w.a)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] == 3
    got = [(i["candidate_id"], i["prefix"], i["new_holder_kind"], i["new_holder_handle"]) for i in body["items"]]
    assert got == [
        (str(w.c1.id), _half(w.c1, upper=True), "unregistered", None),
        (str(w.c2.id), _half(w.c2), "customer", "EXAMPLE-C"),
        (str(w.c1.id), _half(w.c1), "org", "EXAMPLE-B"),
    ]
    first, second, third = body["items"]
    assert first["candidate_value"] == w.c1.value and first["rir"] == "ripe" and first["rir_handle"] == "EXAMPLE-HOLDINGS-A"
    assert first["evidence_id"] == str(w.ev[1].id)
    assert second["evidence_id"] == str(w.ev[2].id) and third["evidence_id"] == str(w.ev[0].id)
    assert second["candidate_value"] == w.c2.value
    assert datetime.fromisoformat(first["first_detected_at"]) == T0 + timedelta(days=2)
    assert datetime.fromisoformat(first["last_seen_at"]) == T0 + timedelta(days=2)
    assert datetime.fromisoformat(third["last_seen_at"]) == T0
    assert uuid.UUID(first["id"])


def test_another_roots_rows_never_appear_but_this_roots_do(world):
    w = world
    mine = _get(w, w.a).json()
    assert mine["total"] == 3  # the filter was reached: A's rows came back in the same call
    assert str(w.c3.id) not in {i["candidate_id"] for i in mine["items"]}
    theirs = _get(w, w.b).json()
    assert [i["candidate_id"] for i in theirs["items"]] == [str(w.c3.id)] and theirs["total"] == 1


def test_candidate_id_filter_and_a_foreign_candidate_yields_nothing(world):
    w = world
    r = _get(w, w.a, {"candidate_id": str(w.c1.id)}).json()
    assert r["total"] == 2 and {i["candidate_id"] for i in r["items"]} == {str(w.c1.id)}
    r = _get(w, w.a, {"candidate_id": str(w.c3.id)})
    assert r.status_code == 200 and r.json() == {"items": [], "total": 0}
    r = _get(w, w.a, {"candidate_id": str(uuid.uuid4())})
    assert r.status_code == 200 and r.json()["total"] == 0


def test_new_holder_kind_filter(world):
    w = world
    r = _get(w, w.a, {"new_holder_kind": "customer"}).json()
    assert [i["new_holder_kind"] for i in r["items"]] == ["customer"] and r["total"] == 1
    r = _get(w, w.a, {"new_holder_kind": "unknown"}).json()
    assert r == {"items": [], "total": 0}
    assert _get(w, w.a, {"new_holder_kind": "bogus"}).status_code == 422


def test_seen_since_filter_is_inclusive(world):
    w = world
    r = _get(w, w.a, {"seen_since": (T0 + timedelta(days=1)).isoformat()}).json()
    assert r["total"] == 2
    assert {i["new_holder_kind"] for i in r["items"]} == {"customer", "unregistered"}
    r = _get(w, w.a, {"seen_since": (T0 + timedelta(days=1, seconds=1)).isoformat()}).json()
    assert [i["new_holder_kind"] for i in r["items"]] == ["unregistered"]
    r = _get(w, w.a, {"seen_since": (T0 + timedelta(days=9)).isoformat()}).json()
    assert r == {"items": [], "total": 0}


def test_unknown_root_and_a_non_root_entity_are_404(world):
    w = world
    assert client.get(f"/api/organizations/{uuid.uuid4()}/reassignments", headers=w.headers(role=VIEWER)).status_code == 404
    plain = w.entity()  # no relationship: not a root
    assert _get(w, plain).status_code == 404


def test_an_invisible_root_is_404(world, monkeypatch):
    w = world
    outsider_user = w.user(VIEWER)
    outsider = w.headers(user=outsider_user)
    monkeypatch.setattr(
        read_scope, "entity_clause",
        lambda user, entity: true() if user.id != outsider_user.id else entity.id != w.a.id,
    )
    assert _get(w, w.a, headers=w.headers(role=VIEWER)).status_code == 200
    assert _get(w, w.a, headers=outsider).status_code == 404


def test_the_row_query_applies_entity_clause_itself_not_only_the_root_guard(world, monkeypatch):
    """The root guard calls entity_clause once; refuse every later call (the row
    query's). Without the clause on the row query the rows would still come back."""
    w = world
    calls = []

    def clause(user, entity):
        calls.append(1)
        return true() if len(calls) == 1 else false()

    monkeypatch.setattr(read_scope, "entity_clause", clause)
    r = _get(w, w.a)
    assert r.status_code == 200, r.text
    assert len(calls) == 2  # the guard AND the row query reached the hook
    assert r.json() == {"items": [], "total": 0}


def test_unauthenticated_is_401(world):
    r = client.get(f"/api/organizations/{world.a.id}/reassignments")
    assert r.status_code == 401


def test_paging_and_the_limit_bound(world):
    w = world
    p1 = _get(w, w.a, {"limit": 2, "offset": 0}).json()
    p2 = _get(w, w.a, {"limit": 2, "offset": 2}).json()
    assert p1["total"] == p2["total"] == 3
    assert [i["new_holder_kind"] for i in p1["items"]] == ["unregistered", "customer"]
    assert [i["new_holder_kind"] for i in p2["items"]] == ["org"]
    assert _get(w, w.a, {"limit": 1001}).status_code == 422
    assert _get(w, w.a, {"limit": 0}).status_code == 422
    assert _get(w, w.a, {"offset": -1}).status_code == 422


def _cands(w, root, **params):
    r = client.get(
        f"/api/organizations/{root.id}/candidates",
        params={"kind": "cidr", "status": "claimed", **params},
        headers=w.headers(role=VIEWER),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return {i["id"] for i in body["items"]}, body["total"]


def test_reassigned_filter_on_the_candidates_list(world):
    w = world
    both = {str(w.c0.id), str(w.c1.id), str(w.c2.id)}
    assert _cands(w, w.a) == (both, 3)
    assert _cands(w, w.a, reassigned="true") == ({str(w.c1.id), str(w.c2.id)}, 2)  # c1 has two rows: still one candidate
    assert _cands(w, w.a, reassigned="false") == ({str(w.c0.id)}, 1)
    # composes with another filter
    assert _cands(w, w.a, reassigned="true", q=w.c2.value) == ({str(w.c2.id)}, 1)
    assert _cands(w, w.a, reassigned="false", q=w.c2.value) == (set(), 0)
