"""API acceptance for candidate domains (planning#216, L6) —
`app/api/entities.py`'s `/candidate-domains` routes.

Direct-`TestClient` style, like `test_entity_graph_api.py`: real requests
through the full dependency chain, so `AuditMiddleware` writes a row for
each mutating call (deleted before the users that made them).

`POST .../accept` queues the same initial-discovery run `POST /targets`
does; under `TestClient` a background task runs synchronously, so
`_prime_ct_and_launch` (Certspotter + a real scan) is replaced with a
recorder. The `ScanRun` row itself is real and is asserted on.

Run with:  pytest app/tests/test_candidate_domains_api.py
"""

import uuid

from fastapi.testclient import TestClient

from app.core.auth import create_access_token
from app.core.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.candidate_domain import CandidateDomain
from app.models.scan import ScanRun
from app.models.target import Target
from app.models.user import User, UserRole
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests._entity_graph import cleanup_entity, cleanup_evidence, make_entity

client = TestClient(app)


def _make_user(role: str) -> tuple[dict, uuid.UUID]:
    db = SessionLocal()
    user = User(
        id=uuid.uuid4(), email=f"cd216-{role}-{uuid.uuid4().hex[:8]}@example.invalid",
        full_name=f"cd216 test {role}", role=role, is_active=True,
    )
    db.add(user)
    db.commit()
    uid = user.id
    db.close()
    return {"Authorization": f"Bearer {create_access_token(str(uid), role)}"}, uid


def _cleanup(entity_ids, engagement_ids, user_ids):
    db = SessionLocal()
    try:
        rows = db.query(CandidateDomain).filter(CandidateDomain.entity_id.in_(entity_ids)).all()
        evidence_ids = [r.evidence_id for r in rows]
        db.query(CandidateDomain).filter(CandidateDomain.entity_id.in_(entity_ids)).delete(synchronize_session=False)
        db.query(Target).filter(Target.entity_id.in_(entity_ids)).delete(synchronize_session=False)
        db.query(ScanRun).filter(ScanRun.created_by_id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
        for eid in engagement_ids:
            cleanup_engagement(db, eid)
        for eid in entity_ids:
            cleanup_entity(db, eid)
        for fid in set(evidence_ids):
            cleanup_evidence(db, fid)
        db.query(AuditLog).filter(AuditLog.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def _manual_body(domain: str) -> dict:
    return {
        "domain": domain,
        "source_url": "https://news.example.test/deal",
        "excerpt": f"Deal announcement. The acquired business operates www.{domain} today.",
        "quote": f"operates www.{domain} today",
    }


def test_candidate_domain_lifecycle_and_roles(monkeypatch):
    launched: list[tuple] = []
    import app.api.targets as targets_api

    monkeypatch.setattr(targets_api, "_prime_ct_and_launch", lambda value, run_id, scope: launched.append((value, run_id, scope)))

    admin_headers, admin_id = _make_user(UserRole.ADMIN.value)
    viewer_headers, viewer_id = _make_user(UserRole.VIEWER.value)
    db = SessionLocal()
    entity = make_entity(db)
    entity_id = entity.id
    engagement_id = make_engagement(db, "pre_close", subject_entity_id=entity_id).id
    db.close()
    d1 = f"cd216-api-{uuid.uuid4().hex[:8]}.example"
    d2 = f"cd216-api-{uuid.uuid4().hex[:8]}.example"
    try:
        base = f"/api/entities/{entity_id}/candidate-domains"

        # Writes are ADMIN-only.
        assert client.post(base, json=_manual_body(d1), headers=viewer_headers).status_code == 403

        r = client.post(base, json=_manual_body(d1), headers=admin_headers)
        assert r.status_code == 201, r.text
        c1 = r.json()
        assert (c1["domain"], c1["source"], c1["status"], c1["evidence_origin"]) == (
            d1, "person", "proposed", "person_supplied",
        )
        c2 = client.post(base, json=_manual_body(d2), headers=admin_headers).json()

        # Duplicate → 409; bad domain → 422; unknown entity → 404.
        assert client.post(base, json=_manual_body(d1), headers=admin_headers).status_code == 409
        bad = _manual_body(d1) | {"domain": "not a domain"}
        assert client.post(base, json=bad, headers=admin_headers).status_code == 422
        assert client.post(
            f"/api/entities/{uuid.uuid4()}/candidate-domains", json=_manual_body(d1), headers=admin_headers
        ).status_code == 404

        # Reads are open to any authenticated user.
        listed = client.get(base, headers=viewer_headers)
        assert listed.status_code == 200
        assert sorted(x["domain"] for x in listed.json()) == sorted([d1, d2])

        accept_url = f"/api/entities/candidate-domains/{c1['id']}/accept"
        assert client.post(accept_url, json={"engagement_id": str(engagement_id)}, headers=viewer_headers).status_code == 403
        r = client.post(accept_url, json={"engagement_id": str(engagement_id)}, headers=admin_headers)
        assert r.status_code == 200, r.text
        accepted = r.json()
        assert accepted["status"] == "accepted" and accepted["engagement_id"] == str(engagement_id)

        db = SessionLocal()
        try:
            target = db.get(Target, uuid.UUID(accepted["target_id"]))
            assert (target.value, target.engagement_id, target.entity_id) == (d1, engagement_id, entity_id)
            # Initial discovery was REACHED (queued and launched), scoped to
            # exactly this domain.
            assert len(launched) == 1 and launched[0][0] == d1
            run = db.get(ScanRun, launched[0][1])
            assert run is not None and run.scope["domains"] == [d1]
            audit = (
                db.query(AuditLog)
                .filter(AuditLog.user_id == admin_id, AuditLog.detail["changes"]["candidate_domain"].astext == c1["id"])
                .all()
            )
            assert any(a.detail["changes"].get("decision") == {"from": "proposed", "to": "accepted"} for a in audit)
        finally:
            db.close()

        # Re-accepting a decided candidate → 409.
        assert client.post(accept_url, json={"engagement_id": str(engagement_id)}, headers=admin_headers).status_code == 409

        reject_url = f"/api/entities/candidate-domains/{c2['id']}/reject"
        assert client.post(reject_url, headers=viewer_headers).status_code == 403
        r = client.post(reject_url, headers=admin_headers)
        assert r.status_code == 200 and r.json()["status"] == "rejected"
        db = SessionLocal()
        try:
            row = db.get(CandidateDomain, uuid.UUID(c2["id"]))
            assert row.decided_by_id == admin_id
            audit = (
                db.query(AuditLog)
                .filter(AuditLog.user_id == admin_id, AuditLog.detail["changes"]["candidate_domain"].astext == c2["id"])
                .all()
            )
            assert any(a.detail["changes"].get("decision") == {"from": "proposed", "to": "rejected"} for a in audit)
        finally:
            db.close()
        assert len(launched) == 1  # a rejection launches nothing
    finally:
        _cleanup([entity_id], [engagement_id], [admin_id, viewer_id])
