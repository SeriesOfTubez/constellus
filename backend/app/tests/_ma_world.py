"""Shared synthetic corporate-family fixture for the M&A brief tests
(planning#230 slice 2): `test_query_entities.py` and `test_reports.py`.

Every company here is invented (`make_entity`'s random names plus a letter);
every domain is `<hex>.example.com`. Rows are deleted by id in `close`.

The tree, with the engagement E whose subject is S (all edges CONFIRMED unless
said otherwise; "X sub Y" is `X subsidiary_of Y`, "X acq Y" is `X acquired Y`):

    A sub S            child of S                      IN the family (depth 1)
    A acq B            B is acquired by A              IN (depth 2), event 2020-03-01
    B acq A            a cycle back to A               must terminate
    B acq C1 acq C2 acq C3     (Alpha, Beta, Gamma)    a chain: depths 3, 4, 5
    P sub S            PROPOSED                        NOT in the family
    R sub S            REJECTED                        NOT in the family
    S sub U            U is S's PARENT                 NOT in the family (never walk up)
    S formerly_named F                                 NOT in the family
    S dba D2                                           NOT in the family
    S acq Q, S dba Z   both PROPOSED                   NOT in the family, in no confirmed list

Engagement N has no subject. Engagement EA has A as its subject (so A has a
relationship of its own). Domains (candidate_domains):

    S accepted, A accepted, A proposed(2nd), B proposed, U accepted, R rejected
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from app.core.database import SessionLocal
from app.models.candidate_domain import CandidateDomain
from app.models.engagement import Engagement
from app.models.user import User, UserRole
from app.services import entity_graph
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


def _hex() -> str:
    return uuid.uuid4().hex[:10]


class MaWorld:
    def __init__(self) -> None:
        self.db = SessionLocal()
        self.entities: list[uuid.UUID] = []
        self.engagements: list[uuid.UUID] = []
        self.relations: list[uuid.UUID] = []
        self.evidence: list[uuid.UUID] = []
        self.users: list[uuid.UUID] = []
        self.domains: list[uuid.UUID] = []
        self.observer = make_observer(self.db)
        self._decider: User | None = None

    # ── primitives ──────────────────────────────────────────────────────────
    def decider(self) -> User:
        if self._decider is None:
            u = User(id=uuid.uuid4(), email=f"ma230-{_hex()}@example.invalid", full_name="ma230",
                     role=UserRole.ADMIN.value, is_active=True)
            self.db.add(u)
            self.db.commit()
            self.users.append(u.id)
            self._decider = u
        return self._decider

    def entity(self, name: str | None = None):
        e = make_entity(self.db, legal_name=name)
        self.entities.append(e.id)
        return e

    def engagement(self, subject=None, posture: str = "pre_close") -> Engagement:
        e = make_engagement(self.db, posture, subject_entity_id=subject.id if subject else None)
        self.engagements.append(e.id)
        return e

    def edge(self, subject, obj, relation: str, status: str = "confirmed", event_date: date | None = None):
        ev = make_evidence(self.db, content=f"ma230 {_hex()}".encode(), source_url=f"https://example.test/{_hex()}")
        self.evidence.append(ev.id)
        rel = entity_graph.assert_relation(
            self.db, subject_id=subject.id, object_id=obj.id, relation=relation, observer_id=self.observer.id,
            evidence_id=ev.id, quote="ma230", event_date=event_date,
            event_date_precision="day" if event_date else "unknown",
        )
        self.relations.append(rel.id)
        if status != "proposed":
            entity_graph.decide(self.db, relation_id=rel.id, status=status, user=self.decider())
        return rel

    def domain(self, entity, status: str = "accepted") -> CandidateDomain:
        name = f"ma230-{_hex()}.example.com"
        ev = make_evidence(self.db, content=f"site {_hex()}".encode(), source_url=f"https://example.test/{_hex()}")
        self.evidence.append(ev.id)
        row_id = uuid.uuid4()
        values = dict(id=row_id, entity_id=entity.id, domain=name, source="person", evidence_id=ev.id,
                      quote=f"Our website is {name}.", status=status)
        if status != "proposed":
            values["decided_at"] = datetime.now(timezone.utc)
        if status == "accepted":
            values["accepted_into"] = "estate"
        self.db.execute(CandidateDomain.__table__.insert().values(**values))
        self.db.commit()
        self.domains.append(row_id)
        return self.db.get(CandidateDomain, row_id)

    # ── the standard family ─────────────────────────────────────────────────
    def build_family(self) -> "MaWorld":
        e = self.entity
        self.S, self.A, self.B = e("Example Holdings S"), e("Fabrikam A Ltd"), e("Fabrikam B Ltd")
        self.C1, self.C2, self.C3 = e("Chain Alpha"), e("Chain Beta"), e("Chain Gamma")
        self.P, self.R, self.U = e("Proposed P"), e("Rejected R"), e("Parent U")
        self.F, self.D2 = e("Former Name F"), e("Trading Name D2")
        self.Q, self.Z = e("Proposed Q Ltd"), e("Proposed Z Trading")
        self.edge(self.A, self.S, "subsidiary_of")
        self.edge(self.A, self.B, "acquired", event_date=date(2020, 3, 1))
        self.edge(self.B, self.A, "acquired")                      # cycle
        self.edge(self.B, self.C1, "acquired")
        self.edge(self.C1, self.C2, "acquired")
        self.edge(self.C2, self.C3, "acquired")
        self.edge(self.P, self.S, "subsidiary_of", status="proposed")
        self.edge(self.R, self.S, "subsidiary_of", status="rejected")
        self.edge(self.S, self.U, "subsidiary_of")                 # U is S's parent
        self.edge(self.S, self.F, "formerly_named")
        self.edge(self.S, self.D2, "dba")
        self.edge(self.S, self.Q, "acquired", status="proposed")   # a proposed acquisition
        self.edge(self.S, self.Z, "dba", status="proposed")        # a proposed trading name
        self.E = self.engagement(self.S)
        self.N = self.engagement(None)
        self.EA = self.engagement(self.A)
        self.dom_s = self.domain(self.S)
        self.dom_a = self.domain(self.A)
        self.dom_a2 = self.domain(self.A, "proposed")
        self.dom_b = self.domain(self.B, "proposed")
        self.dom_u = self.domain(self.U)
        self.dom_r = self.domain(self.R, "rejected")
        return self

    def close(self) -> None:
        db = self.db
        db.rollback()
        db.query(CandidateDomain).filter(CandidateDomain.id.in_(self.domains)).delete(synchronize_session=False)
        db.commit()
        for eid in self.engagements:
            cleanup_engagement(db, eid)
        for rid in self.relations:
            cleanup_relation(db, rid)
        for eid in self.entities:
            cleanup_entity(db, eid)
        for fid in self.evidence:
            cleanup_evidence(db, fid)
        cleanup_observer(db, self.observer.id)
        db.query(User).filter(User.id.in_(self.users)).delete(synchronize_session=False)
        db.commit()
        db.close()
