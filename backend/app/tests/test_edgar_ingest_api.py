"""Coverage for the SEC EDGAR ingest API surface (planning#213, L4 slice 1)
— `POST /api/entities/edgar-ingest` and `GET /api/entities/{id}/filing-
events` in `app/api/entities.py`.

`TestClient` runs `BackgroundTasks` inline (synchronously, after the
response), so the injected `sec_edgar._transport` is still in effect when
`_run_edgar_ingest` runs in-process. No live SEC call, no real CIK/company
name.

⚠ The spec asked for "an ANALYST-role user" on the GET test. This codebase's
`UserRole` enum (`app/models/user.py`) has no `analyst` role — only
`viewer`, `admin`, `report_admin`, `integration_admin`. `GET .../filing-
events` is gated by plain `get_current_user` (any authenticated user,
matching #212's GET convention), so the closest real substitute is
`VIEWER`, used below. Flagged in the report's answer 3.

Run with:  backend/scripts/test.ps1 app/tests/test_edgar_ingest_api.py
       or: pytest app/tests/test_edgar_ingest_api.py
"""

import json
import logging
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.auth import create_access_token
from app.core.config import settings
from app.core.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.entity_filing_event import EntityFilingEvent
from app.models.org_entity import OrgEntity
from app.models.user import User, UserRole
from app.services import sec_edgar
from app.tests._edgar import cleanup_cik, html_table, index_html, make_cik, text_block_html, tr

_UA = "planning213-api-tests contact@example.invalid"


@pytest.fixture(autouse=True)
def _set_user_agent(monkeypatch):
    monkeypatch.setattr(settings, "sec_user_agent", _UA)


def _make_user(role: str) -> tuple[dict, uuid.UUID]:
    db = SessionLocal()
    try:
        user = User(
            id=uuid.uuid4(), email=f"edgar213api-{uuid.uuid4().hex[:8]}@example.invalid",
            full_name="edgar213 api test user", role=role, is_active=True,
        )
        db.add(user)
        db.commit()
        uid = user.id
    finally:
        db.close()
    headers = {"Authorization": f"Bearer {create_access_token(str(uid), role)}"}
    return headers, uid


def _cleanup_user(user_id: uuid.UUID | None) -> None:
    """Deletes this user's `audit_logs` rows FIRST — `AuditLog.user_id` has
    no ON DELETE clause, so deleting the user first would raise
    `IntegrityError` (same order `test_audit_log.py`'s `_Fixture.teardown`
    uses)."""
    if user_id is None:
        return
    db = SessionLocal()
    try:
        db.query(AuditLog).filter(AuditLog.user_id == user_id).delete(synchronize_session=False)
        db.query(User).filter(User.id == user_id).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _submissions_body(cik: str, *, recent=None, former_names=None) -> bytes:
    payload = {
        "cik": cik,
        "name": "Example API Holdings",
        "formerNames": former_names if former_names is not None else [],
        "filings": {
            "recent": recent if recent is not None else {"form": [], "accessionNumber": [], "filingDate": [], "items": []},
            "files": [],
        },
    }
    return json.dumps(payload).encode()


# ── POST /api/entities/edgar-ingest ─────────────────────────────────────────

def test_admin_gets_202_and_the_background_ingest_runs():
    db_cik_holder = SessionLocal()
    cik = make_cik(db_cik_holder)
    db_cik_holder.close()

    headers, admin_id = _make_user(UserRole.ADMIN.value)
    recent = {"form": ["8-K"], "accessionNumber": ["9900000050-24-000050"], "filingDate": ["2024-01-01"], "items": ["2.01"]}
    body = _submissions_body(cik, recent=recent)

    def _handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    sec_edgar._transport = httpx.MockTransport(_handle)
    client = TestClient(app)
    try:
        r = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=headers)
        assert r.status_code == 202, r.text
        payload = r.json()
        assert payload["status"] == "accepted"
        assert payload["cik"] == cik.zfill(10)

        db = SessionLocal()
        try:
            entity = db.query(OrgEntity).filter(OrgEntity.cik == cik).one_or_none()
            assert entity is not None, "background ingest did not run inline under TestClient"
            events = db.query(EntityFilingEvent).filter(EntityFilingEvent.entity_id == entity.id).all()
            assert len(events) == 1

            audit_row = (
                db.query(AuditLog)
                .filter(AuditLog.user_id == admin_id, AuditLog.action == "edgar_ingest_requested")
                .order_by(AuditLog.occurred_at.desc())
                .first()
            )
            assert audit_row is not None
            assert audit_row.detail.get("changes", {}).get("cik") != "[redacted]"
            assert audit_row.detail.get("changes", {}).get("cik") == cik.zfill(10)
        finally:
            db.close()
    finally:
        sec_edgar._transport = None
        db = SessionLocal()
        try:
            cleanup_cik(db, cik)
        finally:
            db.close()
        _cleanup_user(admin_id)


def test_non_admin_gets_403():
    headers, uid = _make_user(UserRole.VIEWER.value)
    client = TestClient(app)
    try:
        r = client.post("/api/entities/edgar-ingest", json={"cik": "9900000099"}, headers=headers)
        assert r.status_code == 403
    finally:
        _cleanup_user(uid)


def test_unset_user_agent_gets_409_with_zero_requests(monkeypatch):
    monkeypatch.setattr(settings, "sec_user_agent", None)
    headers, uid = _make_user(UserRole.ADMIN.value)

    seen: list[httpx.Request] = []

    def _handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"{}")

    sec_edgar._transport = httpx.MockTransport(_handle)
    client = TestClient(app)
    try:
        r = client.post("/api/entities/edgar-ingest", json={"cik": "9900000098"}, headers=headers)
        assert r.status_code == 409
        assert seen == []
    finally:
        sec_edgar._transport = None
        _cleanup_user(uid)


def test_invalid_cik_gets_422():
    headers, uid = _make_user(UserRole.ADMIN.value)
    client = TestClient(app)
    try:
        r = client.post("/api/entities/edgar-ingest", json={"cik": "not-digits"}, headers=headers)
        assert r.status_code == 422
    finally:
        _cleanup_user(uid)


def test_ingest_complete_log_line_includes_the_slice2_and_planning220_counters(caplog):
    """planning#220 (minor): the `edgar ingest complete` line only printed
    slice-1 counters, so a live run's slice-2 outcome (and now the new
    `documents_not_found`/`documents_fetch_failed` counters) could not be
    read without a debugger. Only checks the field NAMES are present — the
    values are exercised by `test_edgar_ingest.py`'s own counter
    assertions."""
    db_cik_holder = SessionLocal()
    cik = make_cik(db_cik_holder)
    db_cik_holder.close()

    headers, admin_id = _make_user(UserRole.ADMIN.value)
    recent = {"form": ["8-K"], "accessionNumber": ["9900000072-24-000072"], "filingDate": ["2024-01-01"], "items": ["2.01"]}
    body = _submissions_body(cik, recent=recent)

    def _handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    sec_edgar._transport = httpx.MockTransport(_handle)
    client = TestClient(app)
    try:
        with caplog.at_level(logging.INFO, logger="app.api.entities"):
            r = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=headers)
        assert r.status_code == 202, r.text

        assert "edgar ingest complete" in caplog.text
        assert "documents_not_found=" in caplog.text
        assert "documents_fetch_failed=" in caplog.text
        assert "sections_stored=" in caplog.text
    finally:
        sec_edgar._transport = None
        db = SessionLocal()
        try:
            cleanup_cik(db, cik)
        finally:
            db.close()
        _cleanup_user(admin_id)


# ── GET /api/entities/{entity_id}/filing-events ─────────────────────────────

def test_get_filing_events_returns_them_newest_first_for_any_authenticated_user():
    db_cik_holder = SessionLocal()
    cik = make_cik(db_cik_holder)
    db_cik_holder.close()

    admin_headers, admin_id = _make_user(UserRole.ADMIN.value)
    # See module docstring: no `analyst` role exists in this codebase's
    # `UserRole`; `VIEWER` is the closest real substitute for "any
    # authenticated user, read-only".
    viewer_headers, viewer_id = _make_user(UserRole.VIEWER.value)

    recent = {
        "form": ["8-K", "8-K"],
        "accessionNumber": ["9900000051-24-000051", "9900000052-24-000052"],
        "filingDate": ["2023-01-01", "2024-06-01"],
        "items": ["2.01", "5.01"],
    }
    body = _submissions_body(cik, recent=recent)

    def _handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    sec_edgar._transport = httpx.MockTransport(_handle)
    client = TestClient(app)
    try:
        r = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=admin_headers)
        assert r.status_code == 202, r.text

        db = SessionLocal()
        try:
            entity = db.query(OrgEntity).filter(OrgEntity.cik == cik).one()
            entity_id = entity.id
        finally:
            db.close()

        r2 = client.get(f"/api/entities/{entity_id}/filing-events", headers=viewer_headers)
        assert r2.status_code == 200, r2.text
        items = r2.json()
        assert len(items) == 2
        assert items[0]["filing_date"] > items[1]["filing_date"]
        assert {i["accession_number"] for i in items} == {"9900000051-24-000051", "9900000052-24-000052"}
        assert all(i["observer_name"] == "edgar_8k_items" for i in items)
    finally:
        sec_edgar._transport = None
        db = SessionLocal()
        try:
            cleanup_cik(db, cik)
        finally:
            db.close()
        _cleanup_user(admin_id)
        _cleanup_user(viewer_id)


# ── GET /api/entities/{entity_id}/subsidiary-listings + /filing-sections ────
# (planning#213 slice 2)

def test_get_subsidiary_listings_and_filing_sections_work_for_a_viewer():
    db_cik_holder = SessionLocal()
    cik = make_cik(db_cik_holder)
    db_cik_holder.close()

    admin_headers, admin_id = _make_user(UserRole.ADMIN.value)
    # See module docstring: no `analyst` role exists; VIEWER is the closest
    # real substitute for "any authenticated user, read-only".
    viewer_headers, viewer_id = _make_user(UserRole.VIEWER.value)

    accession = "9900000060-24-000060"
    idx = index_html([
        {"Document": "subs.htm", "Type": "EX-21.1"},
        {"Document": "form10k.htm", "Type": "10-K"},
    ])
    ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example API Sub LLC", "Delaware"))
    footnote_doc = text_block_html(["Note 3 - Business Combinations"] + [f"Body {i}" for i in range(1, 12)])
    recent = {"form": ["10-K"], "accessionNumber": [accession], "filingDate": ["2024-03-01"], "items": [""]}
    body = _submissions_body(cik, recent=recent)

    def _handle(request: httpx.Request) -> httpx.Response:
        leaf = request.url.path.rsplit("/", 1)[-1]
        if leaf.endswith("-index.htm"):
            return httpx.Response(200, content=idx.encode())
        if leaf == "subs.htm":
            return httpx.Response(200, content=ex21_body.encode())
        if leaf == "form10k.htm":
            return httpx.Response(200, content=footnote_doc.encode())
        return httpx.Response(200, content=body)

    sec_edgar._transport = httpx.MockTransport(_handle)
    client = TestClient(app)
    try:
        r = client.post("/api/entities/edgar-ingest", json={"cik": cik}, headers=admin_headers)
        assert r.status_code == 202, r.text

        db = SessionLocal()
        try:
            entity = db.query(OrgEntity).filter(OrgEntity.cik == cik).one()
            entity_id = entity.id
        finally:
            db.close()

        r2 = client.get(f"/api/entities/{entity_id}/subsidiary-listings", headers=viewer_headers)
        assert r2.status_code == 200, r2.text
        groups = r2.json()
        assert len(groups) == 1
        group = groups[0]
        assert group["accession_number"] == accession
        assert group["exhibit_type"] == "EX-21.1"
        assert len(group["rows"]) == 1
        assert group["rows"][0]["name"] == "Example API Sub LLC"
        assert group["rows"][0]["jurisdiction"] == "Delaware"
        assert group["rows"][0]["subsidiary_entity_id"] is not None

        r3 = client.get(f"/api/entities/{entity_id}/filing-sections", headers=viewer_headers)
        assert r3.status_code == 200, r3.text
        sections = r3.json()
        assert len(sections) == 1
        assert sections[0]["section"] == "business_combinations"
        assert sections[0]["heading"] == "Note 3 - Business Combinations"
        assert "Body 1" in sections[0]["text"]
    finally:
        sec_edgar._transport = None
        db = SessionLocal()
        try:
            cleanup_cik(db, cik)
        finally:
            db.close()
        _cleanup_user(admin_id)
        _cleanup_user(viewer_id)
