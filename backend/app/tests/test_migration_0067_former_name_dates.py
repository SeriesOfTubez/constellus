"""Coverage for migration 0067 (planning#241): the backfill of
`formerly_named` event dates from each row's own stored quote.

The test database is already at head, so the rows here are seeded in the
PRE-fix state directly (`event_date` NULL, precision `unknown`) and the
migration's own `upgrade()` / `downgrade()` are run against them through
alembic's `Operations`. Both functions scan the whole table, which is fine
on the throwaway `constellus_test` database this suite refuses to run
without. Synthetic names only.

Run with:  backend/scripts/test.ps1 app/tests/test_migration_0067_former_name_dates.py
"""

import importlib.util
import json
from datetime import date
from pathlib import Path

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import select

from app.core.database import SessionLocal, engine
from app.models.entity_relation import EntityRelation
from app.models.observer import Observer
from app.services import edgar_ingest, entity_graph
from app.tests._entity_graph import (
    cleanup_entity,
    cleanup_evidence,
    cleanup_observer,
    make_entity,
    make_evidence,
    make_observer,
)

_PATH = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0067_former_name_dates.py"


def _migration():
    spec = importlib.util.spec_from_file_location("migration_0067", _PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(fn_name: str) -> None:
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            getattr(_migration(), fn_name)()


def _quote(to, **extra) -> str:
    entry = {"name": "Example Predecessor Corp", "from": "2001-01-02T05:00:00.000Z", "to": to, **extra}
    return json.dumps(entry, sort_keys=True, separators=(",", ":"))


@pytest.fixture
def seeded():
    """Rows keyed by label. Every one is `formerly_named` by the real
    `edgar_former_names` observer unless its label says otherwise."""
    db = SessionLocal()
    former_observer = db.execute(
        select(Observer).where(Observer.name == edgar_ingest.OBSERVER_FORMER_NAMES)
    ).scalar_one()
    other_observer = make_observer(db)
    evidence = make_evidence(db, content=b"planning#241 migration 0067 test submissions body")
    filer = make_entity(db)
    objects = []
    relation_ids = {}

    def add(label, *, quote, event_date=None, relation="formerly_named", observer=former_observer):
        obj = make_entity(db)
        objects.append(obj.id)
        row = entity_graph.assert_relation(
            db,
            subject_id=filer.id,
            object_id=obj.id,
            relation=relation,
            observer_id=observer.id,
            evidence_id=evidence.id,
            quote=quote,
            event_date=event_date,
            event_date_precision="day" if event_date else "unknown",
        )
        relation_ids[label] = row.id

    add("iso", quote=_quote("2015-06-30T04:00:00.000Z"))
    add("bare", quote=_quote("2012-03-31"))
    add("not_json", quote="not json at all")
    add("no_to", quote=json.dumps({"name": "Example Predecessor Corp"}))
    add("impossible_date", quote=_quote("2015-02-30T04:00:00.000Z"))
    # Already dated, and its quote says something else: never rewritten.
    add("already_dated", quote=_quote("2016-01-01T05:00:00.000Z"), event_date=date(2011, 1, 1))
    add("other_observer", quote=_quote("2014-06-30T04:00:00.000Z"), observer=other_observer)
    add("other_relation", quote=_quote("2013-06-30T04:00:00.000Z"), relation="subsidiary_of")
    db.commit()

    def state():
        db.expire_all()
        return {
            label: (row.event_date, row.event_date_precision)
            for label, rid in relation_ids.items()
            for row in [db.get(EntityRelation, rid)]
        }

    try:
        yield state
    finally:
        db.query(EntityRelation).filter(EntityRelation.id.in_(list(relation_ids.values()))).delete(
            synchronize_session=False
        )
        db.commit()
        for oid in objects:
            cleanup_entity(db, oid)
        cleanup_entity(db, filer.id)
        cleanup_evidence(db, evidence.id)
        cleanup_observer(db, other_observer.id)
        db.close()


_UNKNOWN = (None, "unknown")


def test_seeded_rows_start_in_the_pre_fix_state(seeded):
    """Precondition for the tests below: the ISO rows really are undated."""
    before = seeded()
    assert before["iso"] == _UNKNOWN
    assert before["other_observer"] == _UNKNOWN
    assert before["already_dated"] == (date(2011, 1, 1), "day")


def test_upgrade_fills_only_undated_edgar_former_name_rows_whose_quote_parses(seeded):
    _run("upgrade")
    after = seeded()
    assert after == {
        "iso": (date(2015, 6, 30), "day"),
        "bare": (date(2012, 3, 31), "day"),
        "not_json": _UNKNOWN,
        "no_to": _UNKNOWN,
        "impossible_date": _UNKNOWN,
        "already_dated": (date(2011, 1, 1), "day"),
        "other_observer": _UNKNOWN,
        "other_relation": _UNKNOWN,
    }


def test_upgrade_is_idempotent(seeded):
    _run("upgrade")
    once = seeded()
    _run("upgrade")
    assert seeded() == once


def test_downgrade_re_nulls_only_the_rows_the_old_parser_could_not_date(seeded):
    _run("upgrade")
    _run("downgrade")
    after = seeded()
    assert after["iso"] == _UNKNOWN
    # A bare-date quote was always parseable, so it keeps its date.
    assert after["bare"] == (date(2012, 3, 31), "day")
    # Its date is not its quote's date: not the backfill's doing.
    assert after["already_dated"] == (date(2011, 1, 1), "day")
    _run("upgrade")
    assert seeded()["iso"] == (date(2015, 6, 30), "day")
