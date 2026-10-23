"""A throwaway world for the organization-discovery tests (planning#277 S1a).

Synthetic names only (`make_entity`'s random "Example Holdings ..." names,
`.example.com` domains). Everything made through a `World` method is removed
by `close()` in FK order, including the targets a claim creates and the audit
rows an API call writes.
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from app.core.auth import create_access_token
from app.core.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.engagement import Engagement
from app.models.entity_ingest_run import EntityIngestRun
from app.models.org_entity import OrgEntity
from app.models.role_assignment import RoleAssignment
from app.models.scan import ScanRun
from app.models.target import Target
from app.models.user import User, UserRole
from app.services import entity_graph, entity_relationship
from app.tests import _scope_candidates
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


def hexid() -> str:
    return uuid.uuid4().hex[:10]


class World:
    def __init__(self) -> None:
        self.db = SessionLocal()
        self.entities: list[uuid.UUID] = []
        self.engagements: list[uuid.UUID] = []
        self.relations: list[uuid.UUID] = []
        self.evidence: list[uuid.UUID] = []
        self.users: list[uuid.UUID] = []
        self.observers: list[uuid.UUID] = []
        self.target_values: list[str] = []
        self.entity_names: list[str] = []

    # ── people ──────────────────────────────────────────────────────────────
    def user(self, role: str = UserRole.ADMIN.value) -> User:
        u = User(
            id=uuid.uuid4(), email=f"org277-{hexid()}@example.invalid", full_name="org277 test",
            role=role, is_active=True,
        )
        self.db.add(u)
        self.db.commit()
        self.users.append(u.id)
        return u

    def headers(self, user: User | None = None, role: str = UserRole.ADMIN.value) -> dict:
        user = user or self.user(role)
        return {"Authorization": f"Bearer {create_access_token(str(user.id), user.role)}"}

    # ── companies ───────────────────────────────────────────────────────────
    def entity(self, **kw) -> OrgEntity:
        e = make_entity(self.db, **kw)
        self.entities.append(e.id)
        return e

    def engagement(self, posture: str = "pre_close", subject: OrgEntity | None = None) -> Engagement:
        e = make_engagement(self.db, posture, subject_entity_id=subject.id if subject else None)
        self.engagements.append(e.id)
        return e

    def ours(self, entity: OrgEntity | None = None) -> OrgEntity:
        entity = entity or self.entity()
        entity_relationship.set_ours(self.db, entity_id=entity.id, reference="org277 ref", user=self.user())
        self.db.refresh(entity)
        return entity

    def deal(self, entity: OrgEntity | None = None) -> tuple[OrgEntity, Engagement]:
        """An M&A-target root with one live engagement."""
        entity = entity or self.entity()
        eng = self.engagement("pre_close", subject=entity)
        self.db.refresh(entity)
        return entity, eng

    def edge(self, subject: OrgEntity, obj: OrgEntity, relation: str, *, confirm: bool = True):
        if not self.observers:
            self.observers.append(make_observer(self.db).id)
        ev = make_evidence(self.db, content=f"org277 {hexid()}".encode(), source_url=f"https://example.test/{hexid()}")
        self.evidence.append(ev.id)
        rel = entity_graph.assert_relation(
            self.db, subject_id=subject.id, object_id=obj.id, relation=relation, observer_id=self.observers[0],
            evidence_id=ev.id, quote="org277", event_date=None, event_date_precision="unknown",
        )
        self.relations.append(rel.id)
        if confirm:
            entity_graph.decide(self.db, relation_id=rel.id, status="confirmed", user=self.user())
        return rel

    def child_of(self, parent: OrgEntity) -> OrgEntity:
        """A new company under `parent` (`child subsidiary_of parent`)."""
        child = self.entity()
        self.edge(child, parent, "subsidiary_of")
        return child

    # ── candidates ──────────────────────────────────────────────────────────
    def candidate(self, root: OrgEntity, via: OrgEntity | None = None, value: str | None = None):
        c, _ev = _scope_candidates.make_candidate(
            self.db, root_id=root.id, via_id=(via or root).id, value=value, track=self.evidence
        )
        return c

    def evidence_row(self, text: str = "excerpt"):
        f = make_evidence(self.db, content=f"{text} {hexid()}".encode(), source_url=f"https://example.test/{hexid()}")
        self.evidence.append(f.id)
        return f

    def track_target(self, value: str) -> None:
        self.target_values.append(value)

    # ── teardown ────────────────────────────────────────────────────────────
    def close(self) -> None:
        db = self.db
        db.rollback()
        # Entities an API call created (add organization) are found by name or by what we made.
        made = {e.id for e in db.query(OrgEntity).filter(OrgEntity.legal_name.in_(self.entity_names)).all()} \
            if self.entity_names else set()
        entity_ids = list(set(self.entities) | made)
        evidence = _scope_candidates.purge(db, entity_ids=entity_ids)
        db.query(Target).filter(Target.entity_id.in_(entity_ids)).delete(synchronize_session=False)
        if self.target_values:
            db.query(Target).filter(Target.value.in_(self.target_values)).delete(synchronize_session=False)
        api_engagements = [
            e.id for e in db.query(Engagement).filter(Engagement.subject_entity_id.in_(entity_ids)).all()
        ]
        eng_ids = set(self.engagements) | set(api_engagements)
        if eng_ids:
            db.query(Target).filter(Target.engagement_id.in_(eng_ids)).delete(synchronize_session=False)
        db.query(ScanRun).filter(ScanRun.created_by_id.in_(self.users)).delete(synchronize_session=False)
        db.commit()
        for eid in eng_ids:
            cleanup_engagement(db, eid)
        for rid in self.relations:
            cleanup_relation(db, rid)
        ciks = [c for (c,) in db.query(OrgEntity.cik).filter(OrgEntity.id.in_(entity_ids)).all() if c]
        if ciks:
            db.query(EntityIngestRun).filter(EntityIngestRun.cik.in_(ciks)).delete(synchronize_session=False)
            db.commit()
        for eid in entity_ids:
            cleanup_entity(db, eid)
        for fid in set(self.evidence) | evidence:
            cleanup_evidence(db, fid)
        for oid in self.observers:
            cleanup_observer(db, oid)
        db.query(RoleAssignment).filter(RoleAssignment.user_id.in_(self.users)).delete(synchronize_session=False)
        db.query(AuditLog).filter(AuditLog.user_id.in_(self.users)).delete(synchronize_session=False)
        db.query(User).filter(User.id.in_(self.users)).delete(synchronize_session=False)
        db.commit()
        db.close()
