"""Migration 0083's constraints and triggers (planning#277 S1a), by raw SQL.

Each test inserts or updates through Core, bypassing the service, because the
database is what is under test. Every "must raise" test builds an otherwise
VALID row and breaks exactly one thing, then asserts WHICH constraint fired
(a test titled after a rule but satisfied by a different constraint is the
vacuous shape feedback_vacuous_tests warns about). The good path of each rule
is asserted alongside, so the failure is not simply "this table refuses
everything".

Run with:  scripts/test.sh app/tests/test_org_discovery_schema.py
"""

import importlib.util
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.models import scope_candidate as model
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent, ScopeSignal
from app.models.user import User
from app.services.org_discovery.tiers import CONTEXT, SIGNALS, STRONG, SUPPORTING, TIERS
from app.tests._org_world import World, hexid

_MIGRATION = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0083_org_scope_candidates.py"


def _migration():
    spec = importlib.util.spec_from_file_location("migration_0083", _MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


def _now():
    return datetime.now(timezone.utc)


def _constraint(exc) -> str | None:
    return getattr(getattr(exc.orig, "diag", None), "constraint_name", None)


def _value() -> str:
    return f"sc277-{hexid()}.example.com"


def _insert_candidate(db, root_id, **over) -> uuid.UUID:
    values = dict(id=uuid.uuid4(), root_entity_id=root_id, kind="domain", value=_value(), status="open")
    values.update(over)
    db.execute(ScopeCandidate.__table__.insert().values(**values))
    db.commit()
    return values["id"]


def _claimed(entity_id, **over):
    return dict(status="claimed", affiliated_entity_id=entity_id, decided_at=_now(), accepted_into="estate", **over)


def _rejected(**over):
    return dict(status="rejected", decided_at=_now(), rejection_reason="not ours", rejected_strong_types=[], **over)


def _fails(db, constraint, fn):
    with pytest.raises(IntegrityError) as exc:
        fn()
        db.commit()
    db.rollback()
    assert _constraint(exc.value) == constraint, exc.value


def _trigger_fails(db, message, fn):
    with pytest.raises(DBAPIError) as exc:
        fn()
        db.commit()
    db.rollback()
    assert message in str(exc.value.orig), exc.value


def _update(db, table, row_id, **values):
    db.execute(table.__table__.update().where(table.__table__.c.id == row_id).values(**values))


def _insert_signal(db, candidate_id, via_id, **over) -> uuid.UUID:
    values = dict(
        id=uuid.uuid4(), candidate_id=candidate_id, signal_type="admin_seed", anchor_kind="person",
        via_entity_id=via_id,
    )
    values.update(over)
    db.execute(ScopeSignal.__table__.insert().values(**values))
    db.commit()
    return values["id"]


# ── vocabularies: model, migration, tier table, and the live CHECKs agree ───


def test_model_vocabularies_equal_the_migrations_check_lists():
    m = _migration()
    assert model.CANDIDATE_KINDS == set(m.KINDS)
    assert model.CANDIDATE_STATUSES == set(m.CANDIDATE_STATUSES)
    assert model.ACCEPTED_INTO == set(m.ACCEPTED_INTO)
    assert model.SIGNAL_TYPES == set(m.SIGNAL_TYPES)
    assert model.ANCHOR_KINDS == set(m.ANCHOR_KINDS)
    assert model.EVENT_KINDS == set(m.EVENT_KINDS)


def test_tier_table_keys_equal_the_migrations_signal_type_list():
    m = _migration()
    assert set(SIGNALS) == set(m.SIGNAL_TYPES) == model.SIGNAL_TYPES
    assert len(m.SIGNAL_TYPES) == len(set(m.SIGNAL_TYPES))
    assert {s.tier for s in SIGNALS.values()} <= set(TIERS)
    # The shape the propose bar relies on: a Strong type exists with a generator.
    assert any(s.tier == STRONG and s.built for s in SIGNALS.values())
    assert all(s.family and s.description for s in SIGNALS.values())
    assert {STRONG, SUPPORTING, CONTEXT} == set(TIERS)


def test_the_live_check_constraints_carry_the_same_lists(w):
    def listed(name):
        definition = w.db.execute(
            text("select pg_get_constraintdef(oid) from pg_constraint where conname = :n"), {"n": name}
        ).scalar_one()
        import re
        return set(re.findall(r"'([a-z_0-9]+)'::text", definition))

    m = _migration()
    assert listed("ck_scope_signals_signal_type") == set(m.SIGNAL_TYPES)
    assert listed("ck_scope_signals_anchor_kind") == set(m.ANCHOR_KINDS)
    assert listed("ck_scope_candidate_events_event") == set(m.EVENT_KINDS)
    assert listed("ck_scope_candidates_status") == set(m.CANDIDATE_STATUSES)


def test_the_database_supports_nulls_not_distinct(w):
    assert int(w.db.execute(text("show server_version_num")).scalar_one()) >= 150000


# ── scope_candidates: CHECKs ────────────────────────────────────────────────


@pytest.mark.parametrize("bad", ["Upper.example.com", "https://x.example.com", "192.0.2.1", "nodot", "-a.example.com"])
def test_domain_shape(w, bad):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_domain_shape", lambda: _insert_candidate(w.db, root.id, value=bad))
    _insert_candidate(w.db, root.id)  # the good path


def test_kind_is_a_closed_list(w):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_kind", lambda: _insert_candidate(w.db, root.id, kind="asn", value="AS64500"))


def test_status_is_a_closed_list(w):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_status", lambda: _insert_candidate(w.db, root.id, status="proposed"))


def test_a_claimed_row_needs_its_affiliated_company(w):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_affiliated",
           lambda: _insert_candidate(w.db, root.id, **_claimed(None)))
    _insert_candidate(w.db, root.id, **_claimed(root.id))


def test_decided_at_is_set_iff_decided(w):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_decided_at",
           lambda: _insert_candidate(w.db, root.id, status="open", decided_at=_now()))
    _fails(w.db, "ck_scope_candidates_decided_at",
           lambda: _insert_candidate(w.db, root.id, **{**_rejected(), "decided_at": None}))


def test_a_rejection_reason_is_set_iff_rejected_and_never_blank(w):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_rejection_reason",
           lambda: _insert_candidate(w.db, root.id, status="open", rejection_reason="why"))
    _fails(w.db, "ck_scope_candidates_rejection_reason",
           lambda: _insert_candidate(w.db, root.id, **{**_rejected(), "rejection_reason": None}))
    _fails(w.db, "ck_scope_candidates_rejection_reason_nonblank",
           lambda: _insert_candidate(w.db, root.id, **{**_rejected(), "rejection_reason": "   "}))
    _insert_candidate(w.db, root.id, **_rejected())


def test_rejected_strong_types_is_set_iff_rejected(w):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_rejected_types",
           lambda: _insert_candidate(w.db, root.id, **{**_rejected(), "rejected_strong_types": None}))
    _fails(w.db, "ck_scope_candidates_rejected_types",
           lambda: _insert_candidate(w.db, root.id, status="open", rejected_strong_types=["admin_seed"]))
    _insert_candidate(w.db, root.id, **{**_rejected(), "rejected_strong_types": ["admin_seed"]})


def test_destination_columns(w):
    root = w.ours()
    eng = w.engagement("pre_close")
    _fails(w.db, "ck_scope_candidates_accepted_into",
           lambda: _insert_candidate(w.db, root.id, **{**_claimed(root.id), "accepted_into": "elsewhere"}))
    _fails(w.db, "ck_scope_candidates_claimed_destination",
           lambda: _insert_candidate(w.db, root.id, status="open", accepted_into="estate"))
    # estate naming an engagement; engagement naming none
    _fails(w.db, "ck_scope_candidates_engagement_destination",
           lambda: _insert_candidate(w.db, root.id, **{**_claimed(root.id), "engagement_id": eng.id}))
    _fails(w.db, "ck_scope_candidates_engagement_destination",
           lambda: _insert_candidate(w.db, root.id, **{**_claimed(root.id), "accepted_into": "engagement"}))
    _insert_candidate(w.db, root.id, **{**_claimed(root.id), "accepted_into": "engagement", "engagement_id": eng.id})


def test_one_row_per_root_kind_value(w):
    root, other = w.ours(), w.ours()
    v = _value()
    _insert_candidate(w.db, root.id, value=v)
    _fails(w.db, "uq_scope_candidates_root_kind_value", lambda: _insert_candidate(w.db, root.id, value=v))
    _insert_candidate(w.db, other.id, value=v)  # a different root may hold the same value


# ── scope_candidates: the guard trigger ─────────────────────────────────────


def test_root_kind_and_value_are_immutable(w):
    root, other = w.ours(), w.ours()
    cid = _insert_candidate(w.db, root.id)
    for values in ({"root_entity_id": other.id}, {"value": _value()}):
        _trigger_fails(w.db, "immutable", lambda v=values: _update(w.db, ScopeCandidate, cid, **v))
    _update(w.db, ScopeCandidate, cid, status="open")  # a same-status update is allowed
    w.db.commit()


def test_status_transitions(w):
    root = w.ours()
    clear_rejection = dict(
        status="open", decided_at=None, decided_by_id=None, rejection_reason=None, rejected_strong_types=None
    )

    # open -> claimed is allowed and claimed is terminal
    claimed_id = _insert_candidate(w.db, root.id)
    _update(w.db, ScopeCandidate, claimed_id, **_claimed(root.id))
    w.db.commit()
    for values in (
        {"status": "open", "decided_at": None, "affiliated_entity_id": None, "accepted_into": None},
        {**_rejected(), "affiliated_entity_id": None, "accepted_into": None},
    ):
        _trigger_fails(w.db, "cannot change", lambda v=values: _update(w.db, ScopeCandidate, claimed_id, **v))

    # open -> rejected -> open is allowed (the service clears the columns; the CHECKs force it)
    rid = _insert_candidate(w.db, root.id)
    _update(w.db, ScopeCandidate, rid, **_rejected())
    w.db.commit()
    _update(w.db, ScopeCandidate, rid, **clear_rejection)
    w.db.commit()
    assert w.db.execute(text("select status from scope_candidates where id = :i"), {"i": rid}).scalar_one() == "open"

    # rejected -> claimed is not a transition
    rid2 = _insert_candidate(w.db, root.id, **_rejected())
    _trigger_fails(
        w.db, "cannot change",
        lambda: _update(w.db, ScopeCandidate, rid2, **{**_claimed(root.id), "rejection_reason": None,
                                                        "rejected_strong_types": None}),
    )


def test_deleting_the_deciding_user_does_not_trip_the_guard(w):
    root = w.ours()
    uid = w.user().id
    cid = _insert_candidate(w.db, root.id, **_claimed(root.id, decided_by_id=uid))
    w.db.execute(text("delete from users where id = :i"), {"i": uid})  # ON DELETE SET NULL, performed as an UPDATE
    w.db.commit()
    w.users.remove(uid)
    assert w.db.execute(text("select decided_by_id from scope_candidates where id = :i"), {"i": cid}).scalar_one() is None


# ── scope_signals ───────────────────────────────────────────────────────────


def test_signal_type_and_anchor_kind_are_closed_lists(w):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id)
    ev = w.evidence_row()
    _fails(w.db, "ck_scope_signals_signal_type",
           lambda: _insert_signal(w.db, cid, root.id, signal_type="vibes", evidence_id=ev.id, quote="x"))
    _fails(w.db, "ck_scope_signals_anchor_kind", lambda: _insert_signal(w.db, cid, root.id, anchor_kind="hunch"))


def test_anchor_columns_follow_the_anchor_kind(w):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id)
    anchor = _insert_candidate(w.db, root.id, **_claimed(root.id))
    ev = w.evidence_row()
    kw = dict(signal_type="person_evidence", evidence_id=ev.id, quote="x")
    # (a claimed_candidate anchor with no candidate is stopped by the BEFORE INSERT trigger,
    # which runs ahead of the CHECKs)
    _trigger_fails(w.db, "must be a claimed candidate under the same root",
                   lambda: _insert_signal(w.db, cid, root.id, anchor_kind="claimed_candidate", **kw))
    _fails(w.db, "ck_scope_signals_anchor_candidate",
           lambda: _insert_signal(w.db, cid, root.id, anchor_kind="person", anchor_candidate_id=anchor, **kw))
    _fails(w.db, "ck_scope_signals_anchor_entity",
           lambda: _insert_signal(w.db, cid, root.id, anchor_kind="filer_filing", **kw))
    _fails(w.db, "ck_scope_signals_anchor_entity",
           lambda: _insert_signal(w.db, cid, root.id, anchor_kind="person", anchor_entity_id=root.id, **kw))
    _insert_signal(w.db, cid, root.id, anchor_kind="filer_filing", anchor_entity_id=root.id, **kw)


def test_evidence_is_required_except_for_an_admin_seed(w):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id)
    ev = w.evidence_row()
    _fails(w.db, "ck_scope_signals_evidence_required",
           lambda: _insert_signal(w.db, cid, root.id, signal_type="person_evidence"))
    _fails(w.db, "ck_scope_signals_quote_iff_evidence",
           lambda: _insert_signal(w.db, cid, root.id, signal_type="admin_seed", quote="stray quote"))
    _fails(w.db, "ck_scope_signals_quote_iff_evidence",
           lambda: _insert_signal(w.db, cid, root.id, signal_type="person_evidence", evidence_id=ev.id))
    _fails(w.db, "ck_scope_signals_quote_nonblank",
           lambda: _insert_signal(w.db, cid, root.id, signal_type="person_evidence", evidence_id=ev.id, quote="  "))
    _insert_signal(w.db, cid, root.id)  # an admin_seed with no evidence is fine
    _insert_signal(w.db, cid, root.id, signal_type="person_evidence", evidence_id=ev.id, quote="a quote")


def test_the_same_route_is_one_row_even_with_null_columns(w):
    """`uq_scope_signals_route` is NULLS NOT DISTINCT: an admin_seed has a
    NULL evidence and NULL anchors, and a plain UNIQUE would let it repeat."""
    root = w.ours()
    cid = _insert_candidate(w.db, root.id)
    _insert_signal(w.db, cid, root.id)
    _fails(w.db, "uq_scope_signals_route", lambda: _insert_signal(w.db, cid, root.id))


def test_a_claimed_candidate_anchor_must_be_claimed_under_the_same_root(w):
    """The DB half of the anchor-chain rule, by RAW insert (not the service)."""
    root, other = w.ours(), w.ours()
    ev = w.evidence_row()
    kw = dict(signal_type="redirect_to_claimed", anchor_kind="claimed_candidate", evidence_id=ev.id, quote="x")
    target = _insert_candidate(w.db, root.id)
    open_anchor = _insert_candidate(w.db, root.id)
    foreign_anchor = _insert_candidate(w.db, other.id, **_claimed(other.id))
    good_anchor = _insert_candidate(w.db, root.id, **_claimed(root.id))

    _trigger_fails(w.db, "must be a claimed candidate under the same root",
                   lambda: _insert_signal(w.db, target, root.id, anchor_candidate_id=open_anchor, **kw))
    _trigger_fails(w.db, "must be a claimed candidate under the same root",
                   lambda: _insert_signal(w.db, target, root.id, anchor_candidate_id=foreign_anchor, **kw))
    _trigger_fails(w.db, "cannot anchor its own signal",
                   lambda: _insert_signal(w.db, good_anchor, root.id, anchor_candidate_id=good_anchor, **kw))
    sid = _insert_signal(w.db, target, root.id, anchor_candidate_id=good_anchor, **kw)  # the path IS reachable
    assert w.db.execute(text("select count(*) from scope_signals where id = :i"), {"i": sid}).scalar_one() == 1


def test_only_last_seen_at_may_change_on_a_signal(w):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id)
    ev = w.evidence_row()
    sid = _insert_signal(w.db, cid, root.id, signal_type="person_evidence", evidence_id=ev.id, quote="a quote")
    for values in ({"quote": "edited"}, {"signal_type": "ai_mention"}, {"via_entity_id": uuid.uuid4()},
                   {"first_seen_at": _now()}):
        _trigger_fails(w.db, "only last_seen_at", lambda v=values: _update(w.db, ScopeSignal, sid, **v))
    _update(w.db, ScopeSignal, sid, last_seen_at=_now())
    w.db.commit()


def test_deleting_the_anchoring_user_nulls_the_anchor_without_tripping_the_guard(w):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id)
    uid = w.user().id
    sid = _insert_signal(w.db, cid, root.id, anchor_user_id=uid)
    w.db.execute(text("delete from users where id = :i"), {"i": uid})
    w.db.commit()
    w.users.remove(uid)
    assert w.db.execute(text("select anchor_user_id from scope_signals where id = :i"), {"i": sid}).scalar_one() is None


# ── scope_candidate_events: append-only ─────────────────────────────────────


def _insert_event(db, cid, **over) -> uuid.UUID:
    values = dict(id=uuid.uuid4(), candidate_id=cid, event="claimed")
    values.update(over)
    db.execute(ScopeCandidateEvent.__table__.insert().values(**values))
    db.commit()
    return values["id"]


def test_events_are_append_only(w):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id)
    eid = _insert_event(w.db, cid, reason="first")
    _fails(w.db, "ck_scope_candidate_events_event", lambda: _insert_event(w.db, cid, event="shrugged"))
    _trigger_fails(w.db, "append-only", lambda: _update(w.db, ScopeCandidateEvent, eid, reason="rewritten"))
    _trigger_fails(w.db, "append-only",
                   lambda: w.db.execute(text("delete from scope_candidate_events where id = :i"), {"i": eid}))
    assert w.db.execute(text("select reason from scope_candidate_events where id = :i"), {"i": eid}).scalar_one() == "first"


def test_deleting_the_acting_user_nulls_user_id_on_an_event(w):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id)
    uid = w.user().id
    eid = _insert_event(w.db, cid, user_id=uid)
    w.db.execute(text("delete from users where id = :i"), {"i": uid})
    w.db.commit()
    w.users.remove(uid)
    assert w.db.execute(text("select user_id from scope_candidate_events where id = :i"), {"i": eid}).scalar_one() is None


def test_a_user_row_is_still_deletable_after_all_this(w):
    # the control for the three SET NULL tests above: a plain user is deletable
    uid = w.user().id
    w.db.execute(text("delete from users where id = :i"), {"i": uid})
    w.db.commit()
    w.users.remove(uid)
    assert w.db.get(User, uid) is None
