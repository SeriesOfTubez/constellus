"""Coverage for planning#219's backend slice: the EDGAR ingest run record
(migration 0065, `POST /edgar-ingest` + `GET /edgar-ingest/runs[/{id}]`,
`run_reaper`'s ingest sweeps) and the `relation_id` / `evidence_id` that
`GET /{id}/edges` now carries on each source.

`TestClient` runs `BackgroundTasks` inline after the response, so by the
time `client.post` returns, the run has already reached its final status.
No live SEC call, no real CIK/company name (`make_cik` draws from a
"99"-prefixed range).

Run with:  backend/scripts/test.ps1 app/tests/test_entity_ingest_runs.py
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.database import SessionLocal
from app.main import app
from app.models.entity_ingest_run import EntityIngestRun
from app.models.entity_relation import EntityRelation
from app.models.org_entity import OrgEntity
from app.models.user import UserRole
from app.services import run_reaper, sec_edgar
from app.tests._edgar import cleanup_cik, make_cik
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user

_UA = "planning219-tests contact@example.invalid"


@pytest.fixture(autouse=True)
def _set_user_agent(monkeypatch):
    monkeypatch.setattr(settings, "sec_user_agent", _UA)


@pytest.fixture
def cik():
    db = SessionLocal()
    try:
        value = make_cik(db)
    finally:
        db.close()
    yield value
    db = SessionLocal()
    try:
        cleanup_cik(db, value)
    finally:
        db.close()


@pytest.fixture
def admin():
    headers, uid = _make_user(UserRole.ADMIN.value)
    yield headers
    _cleanup_user(uid)


@pytest.fixture
def viewer():
    headers, uid = _make_user(UserRole.VIEWER.value)
    yield headers
    _cleanup_user(uid)


def _body(cik: str, *, former_names=None) -> bytes:
    return json.dumps({
        "cik": cik,
        "name": "Example Run Holdings",
        "formerNames": former_names or [],
        "filings": {
            "recent": {"form": ["8-K"], "accessionNumber": ["9900000219-24-000001"],
                       "filingDate": ["2024-01-01"], "items": ["2.01"]},
            "files": [],
        },
    }).encode()


def _serve(handler) -> None:
    sec_edgar._transport = httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _reset_transport():
    yield
    sec_edgar._transport = None


# ── run lifecycle ────────────────────────────────────────────────────────────

def test_successful_ingest_records_a_succeeded_run_a_viewer_can_read(cik, admin, viewer):
    _serve(lambda request: httpx.Response(200, content=_body(cik)))
    client = TestClient(app)

    r = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=admin)
    assert r.status_code == 202, r.text
    run_id = r.json()["run_id"]

    r = client.get(f"/api/entities/edgar-ingest/runs/{run_id}", headers=viewer)
    assert r.status_code == 200, r.text
    run = r.json()
    assert run["status"] == "succeeded"
    assert run["error"] is None
    assert run["started_at"] and run["finished_at"]
    assert run["result"]["events_inserted"] == 1
    assert "entity_id" not in run["result"]

    db = SessionLocal()
    try:
        entity = db.query(OrgEntity).filter(OrgEntity.cik == cik).one()
    finally:
        db.close()
    assert run["entity_id"] == str(entity.id)
    assert run["entity_name"] == "Example Run Holdings"

    listed = client.get("/api/entities/edgar-ingest/runs", headers=viewer).json()
    assert run_id in [x["id"] for x in listed]


def test_failed_ingest_records_the_error_class_and_message(cik, admin):
    calls = []

    def _forbidden(request):
        calls.append(request.url)
        return httpx.Response(403, content=b"denied")

    _serve(_forbidden)
    client = TestClient(app)
    r = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=admin)
    assert r.status_code == 202, r.text
    assert calls, "precondition: the background ingest never reached the transport"

    run = client.get(f"/api/entities/edgar-ingest/runs/{r.json()['run_id']}", headers=admin).json()
    assert run["status"] == "failed"
    assert run["error"].startswith("SecForbidden")
    assert len(run["error"]) <= 500
    assert run["result"] is None
    # The 403 hit the submissions fetch, before the entity upsert.
    assert run["entity_id"] is None


def test_a_second_ingest_of_an_active_cik_gets_409_and_never_runs(cik, admin):
    db = SessionLocal()
    try:
        db.add(EntityIngestRun(cik=cik.zfill(10), status="running", started_at=datetime.now(timezone.utc)))
        db.commit()
    finally:
        db.close()

    calls = []
    _serve(lambda request: calls.append(request.url) or httpx.Response(200, content=_body(cik)))
    client = TestClient(app)
    r = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=admin)
    assert r.status_code == 409, r.text
    assert "already queued or running" in r.json()["detail"]
    assert calls == []

    db = SessionLocal()
    try:
        assert db.query(EntityIngestRun).filter(EntityIngestRun.cik == cik.zfill(10)).count() == 1
    finally:
        db.close()


def test_a_finished_run_does_not_block_the_next_ingest(cik, admin):
    _serve(lambda request: httpx.Response(200, content=_body(cik)))
    client = TestClient(app)
    first = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=admin)
    second = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=admin)
    assert first.status_code == 202 and second.status_code == 202, (first.text, second.text)
    assert first.json()["run_id"] != second.json()["run_id"]


def test_unknown_run_is_404(viewer):
    r = TestClient(app).get(f"/api/entities/edgar-ingest/runs/{uuid.uuid4()}", headers=viewer)
    assert r.status_code == 404


# ── schema ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("fields", [
    {"status": "failed", "started_at": "now", "finished_at": "now"},              # no error
    {"status": "succeeded", "started_at": "now", "finished_at": "now"},           # no result
    {"status": "running"},                                                        # no started_at
    {"status": "queued", "finished_at": "now"},                                   # finished but queued
])
def test_status_checks_refuse_inconsistent_rows(cik, fields):
    now = datetime.now(timezone.utc)
    values = {k: (now if v == "now" else v) for k, v in fields.items()}
    db = SessionLocal()
    try:
        db.add(EntityIngestRun(cik=cik.zfill(10), **values))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        db.close()


# ── reaper ───────────────────────────────────────────────────────────────────

def _insert(cik10: str, status: str, *, age: timedelta) -> uuid.UUID:
    now = datetime.now(timezone.utc)
    then = now - age
    row = EntityIngestRun(cik=cik10, status=status, created_at=then)
    if status != "queued":
        row.started_at = then
    if status == "succeeded":
        row.result, row.finished_at = {}, then
    db = SessionLocal()
    try:
        db.add(row)
        db.commit()
        return row.id
    finally:
        db.close()


def _status(run_id: uuid.UUID) -> str:
    db = SessionLocal()
    try:
        return db.get(EntityIngestRun, run_id).status
    finally:
        db.close()


def test_startup_sweep_fails_unfinished_runs_and_leaves_finished_ones(cik):
    # Distinct CIKs: the active-CIK index allows only one unfinished row each.
    other = str(int(cik) + 1)
    done = _insert(cik, "succeeded", age=timedelta(minutes=1))
    running = _insert(cik, "running", age=timedelta(minutes=1))
    queued = _insert(other, "queued", age=timedelta(seconds=1))
    try:
        db = SessionLocal()
        try:
            run_reaper.reap_ingest_runs_at_startup(db)
        finally:
            db.close()
        assert (_status(done), _status(running), _status(queued)) == ("succeeded", "failed", "failed")
    finally:
        db = SessionLocal()
        try:
            db.query(EntityIngestRun).filter(EntityIngestRun.cik == other).delete()
            db.commit()
        finally:
            db.close()


def test_stale_sweep_fails_only_runs_past_their_age_limit(cik):
    other = str(int(cik) + 1)
    old_running = _insert(cik, "running", age=run_reaper.INGEST_RUNNING_TIMEOUT + timedelta(minutes=5))
    young_queued = _insert(other, "queued", age=timedelta(minutes=5))
    try:
        db = SessionLocal()
        try:
            run_reaper.reap_stale_ingest_runs(db)
        finally:
            db.close()
        assert _status(old_running) == "failed"
        assert _status(young_queued) == "queued"
    finally:
        db = SessionLocal()
        try:
            db.query(EntityIngestRun).filter(EntityIngestRun.cik == other).delete()
            db.commit()
        finally:
            db.close()


# ── edges carry relation_id + evidence_id ────────────────────────────────────

def test_edge_sources_carry_the_relation_and_evidence_ids(cik, admin, viewer):
    _serve(lambda request: httpx.Response(
        200, content=_body(cik, former_names=[{"name": "Example Former Name Inc", "from": "2001-01-01", "to": "2010-06-30"}])
    ))
    client = TestClient(app)
    assert client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=admin).status_code == 202

    db = SessionLocal()
    try:
        entity = db.query(OrgEntity).filter(OrgEntity.cik == cik).one()
        relation = db.query(EntityRelation).filter(EntityRelation.subject_id == entity.id).one()
        entity_id, relation_id, evidence_id = entity.id, relation.id, relation.evidence_id
    finally:
        db.close()

    edges = client.get(f"/api/entities/{entity_id}/edges", headers=viewer).json()
    assert len(edges) == 1 and edges[0]["relation"] == "formerly_named"
    [source] = edges[0]["sources"]
    assert source["relation_id"] == str(relation_id)
    assert source["evidence_id"] == str(evidence_id)
    # …and the id opens the evidence the page links to.
    assert client.get(f"/api/entities/evidence/{source['evidence_id']}", headers=viewer).status_code == 200
