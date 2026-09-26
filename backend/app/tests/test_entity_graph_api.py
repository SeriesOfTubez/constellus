"""API-layer acceptance for the corporate entity graph (planning#212, L3) —
`app/api/entities.py`, plus the `entity_id`/`subject_entity_id` fields this
slice adds to `PATCH /api/targets/{id}` and `PATCH /api/engagements/{id}`.

Direct-`TestClient` style, matching `test_engagement_acceptance.py`'s
convention: real HTTP requests through the full dependency chain (so
`AuditMiddleware` writes a row for every mutating call here — audit rows
are cleaned up before the users that made them, same as that file's
`_cleanup_users`). Every id used after a session closes is captured into a
plain variable BEFORE the close — an ORM instance's attributes are not
readable once its session is gone (`DetachedInstanceError`).

Run with:  pytest app/tests/test_entity_graph_api.py
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.auth import create_access_token
from app.core.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.target import Target, TargetType
from app.models.user import User, UserRole
from app.services import entity_graph
from app.tests._docaddr import alloc
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests._entity_graph import (
    cleanup_entity,
    cleanup_evidence,
    cleanup_observer,
    cleanup_relation,
    make_entity,
    make_evidence,
    make_observer,
)

client = TestClient(app)


def _make_user(role: str) -> tuple[dict, uuid.UUID]:
    db = SessionLocal()
    user = User(
        id=uuid.uuid4(), email=f"eg212-{role}-{uuid.uuid4().hex[:8]}@example.invalid",
        full_name=f"eg212 test {role}", role=role, is_active=True,
    )
    db.add(user)
    db.commit()
    uid = user.id
    db.close()
    return {"Authorization": f"Bearer {create_access_token(str(uid), role)}"}, uid


def _cleanup_users(user_ids: list[uuid.UUID]) -> None:
    ids = [i for i in user_ids if i is not None]
    if not ids:
        return
    db = SessionLocal()
    try:
        db.query(AuditLog).filter(AuditLog.user_id.in_(ids)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(ids)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


# ── entity creation ──────────────────────────────────────────────────────

def test_create_entity_happy_path_and_duplicate_cik_409():
    headers, admin_id = _make_user(UserRole.ADMIN.value)
    entity_id = None
    try:
        cik = "".join(str((uuid.uuid4().int + i) % 10) for i in range(10))
        r = client.post("/api/entities/", json={"legal_name": "Example Holdings API Test", "cik": cik}, headers=headers)
        assert r.status_code == 201, r.text
        body = r.json()
        entity_id = uuid.UUID(body["id"])
        assert body["legal_name"] == "Example Holdings API Test"
        assert body["cik"] == cik

        r2 = client.post("/api/entities/", json={"legal_name": "Example Holdings API Test Two", "cik": cik}, headers=headers)
        assert r2.status_code == 409, r2.text
    finally:
        cleanup_entity(SessionLocal(), entity_id)
        _cleanup_users([admin_id])


def test_create_entity_requires_admin():
    headers, viewer_id = _make_user(UserRole.VIEWER.value)
    try:
        r = client.post("/api/entities/", json={"legal_name": "Example Holdings Should Not Exist"}, headers=headers)
        assert r.status_code == 403, r.text
    finally:
        _cleanup_users([viewer_id])


def test_list_entities_includes_created_entity():
    headers, admin_id = _make_user(UserRole.ADMIN.value)
    db = SessionLocal()
    entity = make_entity(db, legal_name=f"Example Holdings List {uuid.uuid4().hex[:6]}")
    entity_id = entity.id
    db.close()
    try:
        r = client.get("/api/entities/", headers=headers)
        assert r.status_code == 200, r.text
        ids = {row["id"] for row in r.json()}
        assert str(entity_id) in ids
    finally:
        cleanup_entity(SessionLocal(), entity_id)
        _cleanup_users([admin_id])


# ── relations queue + edges + evidence content ──────────────────────────

def test_relations_queue_never_returns_blob_content_and_edges_group_sources():
    headers, admin_id = _make_user(UserRole.ADMIN.value)
    db = SessionLocal()
    subject = make_entity(db)
    obj = make_entity(db)
    observer = make_observer(db, trust="observed", confirms_relations=False)
    secret_content = b"the raw fetched bytes must never appear in the relations queue JSON"
    evidence = make_evidence(db, content=secret_content, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")
    subject_id, object_id, observer_id, evidence_id, evidence_url = (
        subject.id, obj.id, observer.id, evidence.id, evidence.source_url,
    )
    db.close()

    db2 = SessionLocal()
    relation = entity_graph.assert_relation(
        db2, subject_id=subject_id, object_id=object_id, relation="acquired",
        observer_id=observer_id, evidence_id=evidence_id,
        quote="an invented supporting passage for the API test", event_date=None, event_date_precision="unknown",
    )
    relation_id = relation.id
    db2.close()

    try:
        r = client.get("/api/entities/relations?status=proposed", headers=headers)
        assert r.status_code == 200, r.text
        rows = {row["id"]: row for row in r.json()}
        assert str(relation_id) in rows
        row = rows[str(relation_id)]
        assert row["evidence_url"] == evidence_url
        assert row["evidence_id"] == str(evidence_id)
        assert "content" not in row
        assert secret_content.decode() not in r.text, "raw evidence bytes must never appear in the review queue response"

        # The evidence endpoint DOES return the raw bytes, content-type
        # forced to text/plain.
        r_ev = client.get(f"/api/entities/evidence/{evidence_id}", headers=headers)
        assert r_ev.status_code == 200, r_ev.text
        assert r_ev.headers["content-type"].startswith("text/plain")
        assert r_ev.content == secret_content
        assert r_ev.headers["x-content-type-options"] == "nosniff"
        assert "sandbox" in r_ev.headers["content-security-policy"]

        # Edges group by (subject, object, relation).
        r_edges = client.get(f"/api/entities/{subject_id}/edges", headers=headers)
        assert r_edges.status_code == 200, r_edges.text
        edges = r_edges.json()
        assert len(edges) == 1
        assert edges[0]["confirmed"] is False
        assert len(edges[0]["sources"]) == 1
        assert edges[0]["sources"][0]["evidence_url"] == evidence_url
    finally:
        cleanup_relation(SessionLocal(), relation_id)
        cleanup_observer(SessionLocal(), observer_id)
        cleanup_evidence(SessionLocal(), evidence_id)
        cleanup_entity(SessionLocal(), subject_id)
        cleanup_entity(SessionLocal(), object_id)
        _cleanup_users([admin_id])


# ── decisions ────────────────────────────────────────────────────────────

def test_decide_relation_requires_admin_and_confirms_on_success():
    admin_headers, admin_id = _make_user(UserRole.ADMIN.value)
    viewer_headers, viewer_id = _make_user(UserRole.VIEWER.value)
    db = SessionLocal()
    subject = make_entity(db)
    obj = make_entity(db)
    observer = make_observer(db, trust="observed", confirms_relations=False)
    evidence = make_evidence(db, source_url=f"https://example.test/{uuid.uuid4().hex[:8]}")
    subject_id, object_id, observer_id, evidence_id = subject.id, obj.id, observer.id, evidence.id
    db.close()

    db2 = SessionLocal()
    relation = entity_graph.assert_relation(
        db2, subject_id=subject_id, object_id=object_id, relation="acquired",
        observer_id=observer_id, evidence_id=evidence_id,
        quote="an invented supporting passage", event_date=None, event_date_precision="unknown",
    )
    relation_id = relation.id
    db2.close()

    try:
        r_forbidden = client.post(
            f"/api/entities/relations/{relation_id}/decision", json={"status": "confirmed"}, headers=viewer_headers,
        )
        assert r_forbidden.status_code == 403, r_forbidden.text

        r_ok = client.post(
            f"/api/entities/relations/{relation_id}/decision", json={"status": "confirmed"}, headers=admin_headers,
        )
        assert r_ok.status_code == 200, r_ok.text
        assert r_ok.json()["status"] == "confirmed"

        db3 = SessionLocal()
        row = db3.execute(
            text("SELECT decision_kind, decided_by_id FROM entity_relations WHERE id=:id"),
            {"id": relation_id},
        ).one()
        db3.close()
        assert row.decision_kind == "person"
        assert row.decided_by_id == admin_id
    finally:
        cleanup_relation(SessionLocal(), relation_id)
        cleanup_observer(SessionLocal(), observer_id)
        cleanup_evidence(SessionLocal(), evidence_id)
        cleanup_entity(SessionLocal(), subject_id)
        cleanup_entity(SessionLocal(), object_id)
        _cleanup_users([admin_id, viewer_id])


# ── PATCH /api/targets/{id} entity_id — ADMIN-only widening of attribution ──

def test_patch_target_entity_id_requires_admin():
    admin_headers, admin_id = _make_user(UserRole.ADMIN.value)
    integ_headers, integ_id = _make_user(UserRole.INTEGRATION_ADMIN.value)
    db = SessionLocal()
    entity = make_entity(db)
    entity_id = entity.id
    target = Target(id=uuid.uuid4(), type=TargetType.DOMAIN, value=alloc(), token=uuid.uuid4().hex)
    db.add(target)
    db.commit()
    target_id = target.id
    db.close()

    try:
        r_forbidden = client.patch(f"/api/targets/{target_id}", json={"entity_id": str(entity_id)}, headers=integ_headers)
        assert r_forbidden.status_code == 403, r_forbidden.text

        r_ok = client.patch(f"/api/targets/{target_id}", json={"entity_id": str(entity_id)}, headers=admin_headers)
        assert r_ok.status_code == 200, r_ok.text
        assert r_ok.json()["entity_id"] == str(entity_id)

        r_missing = client.patch(
            f"/api/targets/{target_id}", json={"entity_id": str(uuid.uuid4())}, headers=admin_headers,
        )
        assert r_missing.status_code == 422, r_missing.text
    finally:
        db = SessionLocal()
        db.query(Target).filter(Target.id == target_id).delete(synchronize_session=False)
        db.commit()
        db.close()
        cleanup_entity(SessionLocal(), entity_id)
        _cleanup_users([admin_id, integ_id])


# ── PATCH /api/engagements/{id} subject_entity_id — ADMIN-only ─────────────

def test_patch_engagement_subject_entity_id_requires_admin():
    admin_headers, admin_id = _make_user(UserRole.ADMIN.value)
    integ_headers, integ_id = _make_user(UserRole.INTEGRATION_ADMIN.value)
    db = SessionLocal()
    entity = make_entity(db)
    entity_id = entity.id
    engagement = make_engagement(db)
    engagement_id = engagement.id
    db.close()

    try:
        r_forbidden = client.patch(
            f"/api/engagements/{engagement_id}", json={"subject_entity_id": str(entity_id)}, headers=integ_headers,
        )
        assert r_forbidden.status_code == 403, r_forbidden.text

        r_ok = client.patch(
            f"/api/engagements/{engagement_id}", json={"subject_entity_id": str(entity_id)}, headers=admin_headers,
        )
        assert r_ok.status_code == 200, r_ok.text
        assert r_ok.json()["subject_entity_id"] == str(entity_id)
    finally:
        db = SessionLocal()
        cleanup_engagement(db, engagement_id)
        db.close()
        cleanup_entity(SessionLocal(), entity_id)
        _cleanup_users([admin_id, integ_id])
