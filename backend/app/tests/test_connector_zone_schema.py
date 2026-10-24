"""Migration 0086's constraints and triggers (planning#277 S1b connector_zone),
by raw SQL, plus `record_signal`'s connector_instance validation.

Synthetic names only. Instances are `cloudflare` (an account type, so each
needs an org). Teardown order matters: candidates (and their signals/events)
go first, because the connector FKs are RESTRICT, then the instances, then the
World.

Run with:  scripts/test.sh app/tests/test_connector_zone_schema.py
"""

import uuid

import pytest
from sqlalchemy import text

from app.models.connector_instance import ConnectorInstance
from app.models.connector_zone_clash import ConnectorZoneClash
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent, ScopeSignal
from app.services.org_discovery import candidates as cand
from app.services.org_discovery.candidates import CandidateInvalid
from app.tests import _scope_candidates
from app.tests._org_world import World, hexid
from app.tests.test_org_discovery_schema import (
    _claimed,
    _fails,
    _insert_candidate,
    _insert_event,
    _insert_signal,
    _trigger_fails,
    _update,
)


class Z:
    def __init__(self) -> None:
        self.w = World()
        self.db = self.w.db
        self.instances: list[uuid.UUID] = []

    def instance(self, org) -> ConnectorInstance:
        inst = ConnectorInstance(type="cloudflare", name=f"zone277-{hexid()}", bound_entity_id=org.id)
        self.db.add(inst)
        self.db.commit()
        self.instances.append(inst.id)
        return inst

    def evidence(self) -> uuid.UUID:
        return self.w.evidence_row().id

    def zone_signal(self, cid, via_id, inst_id, **over) -> uuid.UUID:
        values = dict(signal_type="connector_zone", anchor_kind="connector_instance",
                      anchor_connector_instance_id=inst_id, evidence_id=self.evidence(), quote="zone listing")
        values.update(over)
        return _insert_signal(self.db, cid, via_id, **values)

    def close(self) -> None:
        db = self.db
        db.rollback()
        entity_ids = list(self.w.entities)
        self.w.evidence.extend(_scope_candidates.purge(db, entity_ids=entity_ids))
        db.query(ConnectorZoneClash).filter(ConnectorZoneClash.instance_id.in_(self.instances)).delete(
            synchronize_session=False)
        db.query(ConnectorInstance).filter(ConnectorInstance.id.in_(self.instances)).delete(synchronize_session=False)
        db.commit()
        self.w.close()


@pytest.fixture
def z():
    zz = Z()
    try:
        yield zz
    finally:
        zz.close()


_COUNTS = {
    ("connector_zone_clashes", "instance_id"): text("select count(*) from connector_zone_clashes where instance_id = :v"),
    ("scope_candidate_events", "id"): text("select count(*) from scope_candidate_events where id = :v"),
    ("scope_signals", "anchor_connector_instance_id"): text(
        "select count(*) from scope_signals where anchor_connector_instance_id = :v"
    ),
    ("scope_signals", "candidate_id"): text("select count(*) from scope_signals where candidate_id = :v"),
}


def _count(db, table, col, val) -> int:
    return db.execute(_COUNTS[(table, col)], {"v": val}).scalar_one()


# ── scope_signals ───────────────────────────────────────────────────────────


def test_connector_signal_inserts_when_bound_to_the_candidates_root(z):
    root = z.w.ours()
    inst = z.instance(root)
    cid = _insert_candidate(z.db, root.id)
    sid = z.zone_signal(cid, root.id, inst.id)
    assert _count(z.db, "scope_signals", "anchor_connector_instance_id", inst.id) == 1
    assert sid is not None


def test_trigger_refuses_an_instance_bound_to_another_root(z):
    root, other = z.w.ours(), z.w.ours()
    inst_other = z.instance(other)
    inst_root = z.instance(root)
    cid = _insert_candidate(z.db, root.id)
    _trigger_fails(z.db, "must be an instance bound to the candidate", lambda: z.zone_signal(cid, root.id, inst_other.id))
    z.zone_signal(cid, root.id, inst_root.id)  # reached: the bound one is accepted
    assert _count(z.db, "scope_signals", "candidate_id", cid) == 1


def test_signal_checks_on_the_connector_anchor(z):
    root = z.w.ours()
    inst = z.instance(root)
    cid = _insert_candidate(z.db, root.id)
    # kind without the column: the BEFORE INSERT trigger fires ahead of the CHECK, so it is the refuser
    _trigger_fails(z.db, "must be an instance bound to the candidate", lambda: z.zone_signal(cid, root.id, None))
    # column with another kind (person) -- type kept admin_seed so only this CHECK is in play
    _fails(z.db, "ck_scope_signals_anchor_connector_instance",
           lambda: _insert_signal(z.db, cid, root.id, signal_type="admin_seed", anchor_kind="person",
                                  anchor_connector_instance_id=inst.id))
    # connector_zone type with another anchor
    _fails(z.db, "ck_scope_signals_connector_zone",
           lambda: _insert_signal(z.db, cid, root.id, signal_type="connector_zone", anchor_kind="person",
                                  evidence_id=z.evidence(), quote="x"))
    # connector_instance anchor with another type
    _fails(z.db, "ck_scope_signals_connector_zone",
           lambda: z.zone_signal(cid, root.id, inst.id, signal_type="admin_seed"))
    assert _count(z.db, "scope_signals", "candidate_id", cid) == 0
    z.zone_signal(cid, root.id, inst.id)  # reached: the valid combination
    assert _count(z.db, "scope_signals", "candidate_id", cid) == 1


def test_guard_refuses_changing_the_connector_anchor_but_not_last_seen_at(z):
    root = z.w.ours()
    a, b = z.instance(root), z.instance(root)
    cid = _insert_candidate(z.db, root.id)
    sid = z.zone_signal(cid, root.id, a.id)
    _trigger_fails(z.db, "only last_seen_at may change",
                   lambda: _update(z.db, ScopeSignal, sid, anchor_connector_instance_id=b.id))
    _update(z.db, ScopeSignal, sid, last_seen_at=text("now()"))
    z.db.commit()
    got = z.db.execute(text("select anchor_connector_instance_id from scope_signals where id = :i"), {"i": sid}).scalar_one()
    assert got == a.id


def test_route_uniqueness_includes_the_connector_instance(z):
    root = z.w.ours()
    a, b = z.instance(root), z.instance(root)
    cid = _insert_candidate(z.db, root.id)
    ev = z.evidence()
    z.zone_signal(cid, root.id, a.id, evidence_id=ev)
    z.zone_signal(cid, root.id, b.id, evidence_id=ev)  # differs only by instance: coexists
    assert _count(z.db, "scope_signals", "candidate_id", cid) == 2
    _fails(z.db, "uq_scope_signals_route", lambda: z.zone_signal(cid, root.id, a.id, evidence_id=ev))
    assert _count(z.db, "scope_signals", "candidate_id", cid) == 2


# ── scope_candidates ────────────────────────────────────────────────────────


def test_candidate_connector_decider_checks(z):
    root = z.w.ours()
    inst = z.instance(root)
    _fails(z.db, "ck_scope_candidates_connector_decider",
           lambda: _insert_candidate(z.db, root.id, decided_by_connector_instance_id=inst.id))
    cid = _insert_candidate(z.db, root.id, **_claimed(root.id, decided_by_connector_instance_id=inst.id))
    assert z.db.execute(text("select decided_by_id, decided_by_connector_instance_id from scope_candidates where id = :i"),
                        {"i": cid}).one() == (None, inst.id)
    _fails(z.db, "ck_scope_candidates_one_decider",
           lambda: _insert_candidate(z.db, root.id, **_claimed(root.id, decided_by_connector_instance_id=inst.id,
                                                              decided_by_id=z.w.user().id)))


# ── scope_candidate_events ──────────────────────────────────────────────────


def test_event_connector_checks_and_the_append_only_hole(z):
    root = z.w.ours()
    inst = z.instance(root)
    cid = _insert_candidate(z.db, root.id)
    _fails(z.db, "ck_scope_candidate_events_connector",
           lambda: _insert_event(z.db, cid, event="rejected", connector_instance_id=inst.id))
    _fails(z.db, "ck_scope_candidate_events_connector",
           lambda: _insert_event(z.db, cid, event="claimed", connector_instance_id=inst.id, user_id=z.w.user().id))
    # claimed, no user: allowed, and the row exists for the UPDATE below
    eid = _insert_event(z.db, cid, event="claimed", connector_instance_id=inst.id)
    other = z.instance(root)
    assert _count(z.db, "scope_candidate_events", "id", eid) == 1
    # user_id NULL and only connector_instance_id changes: the escape hatch must not admit it
    _trigger_fails(z.db, "append-only", lambda: _update(z.db, ScopeCandidateEvent, eid, connector_instance_id=other.id))
    _trigger_fails(z.db, "append-only", lambda: _update(z.db, ScopeCandidateEvent, eid, connector_instance_id=None))
    assert z.db.execute(text("select connector_instance_id from scope_candidate_events where id = :i"),
                        {"i": eid}).scalar_one() == inst.id


# ── deletes ─────────────────────────────────────────────────────────────────


def test_instance_delete_is_restricted_by_a_signal_and_cascades_to_clashes(z):
    root = z.w.ours()
    inst, plain = z.instance(root), z.instance(root)
    inst_id, plain_id = inst.id, plain.id
    cid = _insert_candidate(z.db, root.id)
    z.zone_signal(cid, root.id, inst.id)
    with pytest.raises(Exception) as exc:
        z.db.execute(text("delete from connector_instances where id = :i"), {"i": inst_id})
        z.db.commit()
    z.db.rollback()
    assert "scope_signals" in str(exc.value) and "foreign key" in str(exc.value).lower()
    assert z.db.get(ConnectorInstance, inst_id) is not None

    z.db.add(ConnectorZoneClash(instance_id=plain_id, zone="fabrikam.com", reason="claimed_by_other_org"))
    z.db.commit()
    assert _count(z.db, "connector_zone_clashes", "instance_id", plain_id) == 1
    z.db.execute(text("delete from connector_instances where id = :i"), {"i": plain_id})
    z.db.commit()
    assert _count(z.db, "connector_zone_clashes", "instance_id", plain_id) == 0


# ── connector_zone_clashes ──────────────────────────────────────────────────


def test_clash_open_row_is_unique_per_instance_and_zone(z):
    root = z.w.ours()
    inst = z.instance(root)

    def add(zone="contoso.com", resolved=False, reason="target_in_other_scope"):
        z.db.execute(text(
            "insert into connector_zone_clashes (instance_id, zone, reason, resolved_at) "
            "values (:i, :z, :r, case when :res then now() else null end)"
        ), {"i": inst.id, "z": zone, "r": reason, "res": resolved})
        z.db.commit()

    add()
    _fails(z.db, "uq_connector_zone_clashes_open", lambda: add())
    add(resolved=True)            # a resolved row coexists with the open one
    add(zone="fabrikam.com")      # another zone is independent
    _fails(z.db, "ck_connector_zone_clashes_reason", lambda: add(zone="x.example.com", reason="bogus"))
    assert _count(z.db, "connector_zone_clashes", "instance_id", inst.id) == 3


# ── record_signal ───────────────────────────────────────────────────────────


def _rs(z, root, **over):
    kw = dict(root_entity_id=root.id, value=f"zone277-{hexid()}.example.com", signal_type="connector_zone",
              anchor_kind="connector_instance", via_entity_id=root.id)
    ev = z.w.evidence_row()
    kw.update(evidence_id=ev.id, quote=kw["value"])
    kw.update(over)
    return cand.record_signal(z.db, **kw)


def test_record_signal_connector_zone_writes_the_column(z):
    root = z.w.ours()
    inst = z.instance(root)
    out = _rs(z, root, anchor_connector_instance_id=inst.id)
    z.db.commit()
    assert out.outcome == "recorded" and out.created_signal
    assert out.signal.anchor_connector_instance_id == inst.id
    assert z.db.execute(text("select anchor_connector_instance_id from scope_signals where id = :i"),
                        {"i": out.signal.id}).scalar_one() == inst.id


def test_record_signal_connector_zone_is_idempotent_per_instance(z):
    root = z.w.ours()
    inst = z.instance(root)
    ev = z.w.evidence_row()
    value = f"zone277-{hexid()}.example.com"
    first = _rs(z, root, value=value, quote=value, evidence_id=ev.id, anchor_connector_instance_id=inst.id)
    again = _rs(z, root, value=value, quote=value, evidence_id=ev.id, anchor_connector_instance_id=inst.id)
    z.db.commit()
    assert first.created_signal and not again.created_signal and first.signal.id == again.signal.id


def test_record_signal_connector_validation(z):
    root, other = z.w.ours(), z.w.ours()
    inst = z.instance(root)
    foreign = z.instance(other)

    def refused(match, **over):
        with pytest.raises(CandidateInvalid) as exc:
            _rs(z, root, **over)
        z.db.rollback()
        assert match in str(exc.value)

    refused("needs the connector instance", anchor_connector_instance_id=None)
    refused("must be bound", anchor_connector_instance_id=uuid.uuid4())
    refused("must be bound", anchor_connector_instance_id=foreign.id)
    refused("only they", signal_type="person_evidence", anchor_connector_instance_id=inst.id)
    refused("only they", anchor_kind="person", anchor_user_id=z.w.user().id)
    refused("only for a connector_instance", signal_type="person_evidence", anchor_kind="person",
            anchor_user_id=z.w.user().id, anchor_connector_instance_id=inst.id)
    # reached: nothing above wrote a row, and the valid call does
    assert z.db.query(ScopeSignal).filter(ScopeSignal.anchor_connector_instance_id.in_([inst.id, foreign.id])).count() == 0
    assert _rs(z, root, anchor_connector_instance_id=inst.id).created_signal
    z.db.commit()
