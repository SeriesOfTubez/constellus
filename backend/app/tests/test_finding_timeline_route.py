"""The timeline on the finding detail route (planning#360): `GET
/api/findings/{id}` as an admin carries `timeline`, built from the finding, its
CVE record and the attribution the same response holds.

The world is the full attribution chain of test_attribution_routes.py (an ours
organization, an entity it acquired, a claimed domain target) plus one finding
on the address. `_full_world`'s acquisition edge has no `event_date`, so the
test sets one on that `entity_relations` row (month precision).

Synthetic data only: `ftr-<hex>.example.org`, `CVE-2099-<digits>`, addresses
`_a(0)` of test_exposure_path.py.

Run with:  backend/scripts/test.sh app/tests/test_finding_timeline_route.py
"""

import random
import uuid
from datetime import date, datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.cve_record import CveRecord
from app.models.entity_relation import EntityRelation
from app.models.finding_canonical import FindingCanonical
from app.schemas.finding_detail import FindingDetailResponse
from app.tests.test_attribution_chain import _Env
from app.tests.test_attribution_routes import _detail_schema, _finding_world, _refs
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

client = TestClient(app)

_CVE_UPPER = f"CVE-2099-{random.randint(0, 999999):06d}"
_CVE_LOWER = _CVE_UPPER.lower()

_PUBLISHED = datetime(2026, 1, 14, 12, 0, tzinfo=timezone.utc)
_VULNCHECK = date(2026, 1, 10)
_CISA = date(2026, 2, 1)
_CONFIRMED = datetime(2026, 3, 5, 10, 0, tzinfo=timezone.utc)
_ACQUIRED = date(2019, 6, 1)


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
        e.db.rollback()
        e.db.query(CveRecord).filter(CveRecord.cve_id == _CVE_UPPER).delete(synchronize_session=False)
        e.db.commit()


def _put_cve_record(env) -> None:
    env.db.rollback()
    env.db.query(CveRecord).filter(CveRecord.cve_id == _CVE_UPPER).delete(synchronize_session=False)
    env.db.add(CveRecord(
        cve_id=_CVE_UPPER, published_at=_PUBLISHED, published_source="vulncheck_nvd2",
        vulncheck_kev_date_added=_VULNCHECK))
    env.db.commit()


def _prepare_finding(env, fid) -> None:
    """A lower-case CVE id, so the lookup must upper-case it; a CISA date; and
    the fields that give the BOD SLA a due date."""
    env.db.rollback()
    f = env.db.get(FindingCanonical, fid)
    f.cve_id = _CVE_LOWER
    f.kev = True
    f.kev_date_added = _CISA
    f.ssvc_source = "vulnrichment"
    f.ownership_confirmed_at = _CONFIRMED
    env.db.commit()


def _date_the_acquisition(env, w) -> None:
    env.db.rollback()
    row = (
        env.db.query(EntityRelation)
        .filter(EntityRelation.subject_id == w.root.id, EntityRelation.object_id == w.a.id,
                EntityRelation.relation == "acquired")
        .one()
    )
    assert row.event_date is None  # the world's edge is undated: the test dates it
    row.event_date = _ACQUIRED
    row.event_date_precision = "month"
    env.db.commit()


def _get(admin, fid) -> dict:
    r = client.get(f"/api/findings/{fid}", headers=admin)
    assert r.status_code == 200, r.text
    return r.json()


def _by_kind(timeline) -> dict:
    out = {}
    for e in timeline:
        assert e["kind"] not in out, f"{e['kind']} appears twice"
        out[e["kind"]] = e
    return out


def test_the_finding_route_returns_the_timeline(env, admin):
    w, fid = _finding_world(env)
    _prepare_finding(env, fid)
    _put_cve_record(env)
    _date_the_acquisition(env, w)
    body = _get(admin, fid)
    timeline = body["timeline"]
    by = _by_kind(timeline)
    assert set(by) == {
        "cve_published", "listed_exploited_vulncheck", "listed_exploited_cisa", "acquired", "claimed",
        "first_seen", "ownership_confirmed", "due"}

    assert by["cve_published"]["date"] == "2026-01-14"
    assert by["cve_published"]["source"] == "vulncheck_nvd2"
    assert by["listed_exploited_vulncheck"]["date"] == "2026-01-10"
    assert by["listed_exploited_cisa"]["date"] == "2026-02-01"
    assert by["ownership_confirmed"]["date"] == "2026-03-05"
    assert by["claimed"]["target_id"] == str(w.target.id)
    assert by["claimed"]["target_value"] == w.target.value
    assert by["claimed"]["date"] == "2020-01-01"
    acq = by["acquired"]
    assert (acq["date"], acq["precision"]) == ("2019-06-01", "month")
    assert acq["entity_id"] == str(w.a.id)
    assert acq["acquirer_id"] == str(w.root.id)

    # The due date is the one the same response states for the BOD SLA.
    assert body["bod_sla"]["due_date"] is not None
    assert by["due"]["date"] == body["bod_sla"]["due_date"]
    assert by["due"]["source"] == "bod_26_04"

    # Sorted by date, and a listing before the published date comes first.
    assert [e["date"] for e in timeline] == sorted(e["date"] for e in timeline)
    kinds = [e["kind"] for e in timeline]
    assert kinds.index("listed_exploited_vulncheck") < kinds.index("cve_published")


def test_no_cve_record_leaves_out_the_cve_events_but_first_seen_is_there(env, admin):
    w, fid = _finding_world(env)
    _prepare_finding(env, fid)
    env.db.rollback()
    env.db.query(CveRecord).filter(CveRecord.cve_id == _CVE_UPPER).delete(synchronize_session=False)
    env.db.commit()
    by = _by_kind(_get(admin, fid)["timeline"])
    assert "first_seen" in by  # reached
    assert "listed_exploited_cisa" in by
    assert "cve_published" not in by
    assert "listed_exploited_vulncheck" not in by


def test_a_response_validates_and_openapi_names_the_timeline(env, admin):
    w, fid = _finding_world(env)
    _prepare_finding(env, fid)
    _put_cve_record(env)
    body = _get(admin, fid)
    parsed = FindingDetailResponse.model_validate(body)
    assert len(parsed.timeline) == len(body["timeline"]) > 0
    assert [e.model_dump(mode="json", exclude_none=False) for e in parsed.timeline] == body["timeline"]

    detail = _detail_schema(app.openapi(), "/api/findings/{finding_id}")
    refs = [r.rsplit("/", 1)[-1] for r in _refs(detail["properties"]["timeline"])]
    assert refs == ["TimelineEvent"]
    assert detail["properties"]["timeline"]["type"] == "array"
