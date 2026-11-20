"""A finding's exposure timeline (planning#360), at the service level: the
rules of `services/finding_timeline.build_timeline`, with no database.

`build_timeline` takes objects, so every test builds transient
`FindingCanonical` / `CveRecord` rows and `Attribution` models by hand. A test
that asserts something is ABSENT also asserts the path was reached: a sibling
that DOES produce an event sits next to it, so the check cannot pass because
the code never looked.

Synthetic data only: `Example Holdings ...` entities, `fabrikam.example.com`.

Run with:  backend/scripts/test.sh app/tests/test_finding_timeline.py
"""

import uuid
from datetime import date, datetime, timedelta, timezone

from app.models.cve_record import CveRecord
from app.models.finding_canonical import FindingCanonical
from app.schemas.attribution_chain import (
    AddressHop,
    Attribution,
    AttributionChain,
    EntityHop,
    HostHop,
    OrganizationHop,
    Ownership,
    RelationEvidence,
    ScopeHop,
)
from app.services.finding_timeline import build_timeline

_FIRST_SEEN = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)


def _finding(**kw) -> FindingCanonical:
    kw.setdefault("first_seen_at", _FIRST_SEEN)
    return FindingCanonical(**kw)


def _kinds(events) -> list[str]:
    return [e.kind for e in events]


def _one(events, kind):
    (e,) = [e for e in events if e.kind == kind]
    return e


# -- attribution builders -----------------------------------------------------


def _row(relation="acquired", event_date=date(2020, 5, 17), precision="day", source="obs_a", relation_id=None):
    return RelationEvidence(
        relation_id=relation_id or uuid.uuid4(), relation=relation, source=source,
        event_date=event_date, event_date_precision=precision, evidence_id=uuid.uuid4())


def _org(entity_id=None):
    return OrganizationHop(status="observed", entity_id=entity_id or uuid.uuid4(), name="Example Holdings A",
                           relationship="ours")


def _entity(name, relation, rows, entity_id=None):
    return EntityHop(status="observed", entity_id=entity_id or uuid.uuid4(), name=name, relation=relation,
                     evidence=rows)


def _scope(target_id=None, value="fabrikam.example.com", claimed_at=None):
    return ScopeHop(status="observed", target_id=target_id or uuid.uuid4(), target_type="domain", value=value,
                    claimed_at=claimed_at)


def _chain(*hops) -> AttributionChain:
    return AttributionChain(target_id=None, hops=[*hops, HostHop(status="observed"), AddressHop(status="observed")])


def _attr(*chains) -> Attribution:
    return Attribution(ownership=Ownership(surface="unknown"), chains=list(chains))


# -- single sources -----------------------------------------------------------


def test_each_source_gives_its_own_event_with_its_own_source():
    published = datetime(2026, 1, 10, 8, 30, tzinfo=timezone.utc)
    cve = CveRecord(cve_id="CVE-2099-000001", published_at=published, published_source="vulncheck_nvd2",
                    vulncheck_kev_date_added=date(2026, 1, 20))
    f = _finding(kev_date_added=date(2026, 2, 1),
                 ownership_confirmed_at=datetime(2026, 3, 5, 10, 0, tzinfo=timezone.utc))
    events = build_timeline(f, cve, None, "2026-03-04")
    assert _kinds(events) == [
        "cve_published", "listed_exploited_vulncheck", "listed_exploited_cisa", "first_seen", "due",
        "ownership_confirmed"]
    pub = _one(events, "cve_published")
    assert (pub.date, pub.at, pub.source, pub.precision) == (date(2026, 1, 10), published, "vulncheck_nvd2", "day")
    cisa = _one(events, "listed_exploited_cisa")
    assert (cisa.date, cisa.at, cisa.source) == (date(2026, 2, 1), None, "cisa_kev")
    vc = _one(events, "listed_exploited_vulncheck")
    assert (vc.date, vc.at, vc.source) == (date(2026, 1, 20), None, "vulncheck_kev")
    seen = _one(events, "first_seen")
    assert (seen.date, seen.at, seen.source) == (date(2026, 3, 1), _FIRST_SEEN, None)
    due = _one(events, "due")
    assert (due.date, due.at, due.source) == (date(2026, 3, 4), None, "fix_window")
    conf = _one(events, "ownership_confirmed")
    assert (conf.date, conf.at, conf.source) == (date(2026, 3, 5), datetime(2026, 3, 5, 10, 0, tzinfo=timezone.utc),
                                                 None)


def test_a_date_we_do_not_have_is_absent_never_a_null_dated_event():
    # Reached: the finding has first_seen and a CVE record that holds only a
    # VulnCheck date; the events that DO exist are built.
    cve = CveRecord(cve_id="CVE-2099-000002", vulncheck_kev_date_added=date(2026, 1, 20))
    events = build_timeline(_finding(), cve, None, None)
    assert _kinds(events) == ["listed_exploited_vulncheck", "first_seen"]
    assert all(e.date is not None for e in events)


def test_no_cve_record_leaves_out_the_cve_events_but_not_first_seen():
    f = _finding(kev_date_added=date(2026, 2, 1))
    events = build_timeline(f, None, None, None)
    assert _kinds(events) == ["listed_exploited_cisa", "first_seen"]


def test_a_cve_record_with_nothing_set_gives_no_cve_event():
    cve = CveRecord(cve_id="CVE-2099-000003")
    events = build_timeline(_finding(), cve, None, None)
    assert _kinds(events) == ["first_seen"]


# -- dates --------------------------------------------------------------------


def test_a_naive_datetime_is_read_as_utc():
    f = _finding(first_seen_at=datetime(2026, 1, 1, 23, 30))  # naive
    seen = _one(build_timeline(f, None, None, None), "first_seen")
    assert seen.date == date(2026, 1, 1)
    assert seen.at == datetime(2026, 1, 1, 23, 30, tzinfo=timezone.utc)
    assert seen.at.utcoffset() == timedelta(0)


def test_an_aware_non_utc_datetime_converts_to_the_utc_day():
    minus5 = timezone(timedelta(hours=-5))
    f = _finding(first_seen_at=datetime(2026, 1, 1, 23, 30, tzinfo=minus5))
    seen = _one(build_timeline(f, None, None, None), "first_seen")
    assert seen.date == date(2026, 1, 2)
    assert seen.at == datetime(2026, 1, 2, 4, 30, tzinfo=timezone.utc)
    assert seen.at.utcoffset() == timedelta(0)


# -- order --------------------------------------------------------------------


def test_sorted_by_date_so_a_listing_before_the_published_date_comes_first():
    cve = CveRecord(cve_id="CVE-2099-000004", published_at=datetime(2026, 1, 14, 12, 0, tzinfo=timezone.utc),
                    published_source="vulncheck_nvd2", vulncheck_kev_date_added=date(2026, 1, 10))
    events = build_timeline(_finding(), cve, None, None)
    assert _kinds(events)[:2] == ["listed_exploited_vulncheck", "cve_published"]
    assert [e.date for e in events] == sorted(e.date for e in events)


def test_the_same_day_is_ordered_by_at_with_a_day_only_event_at_midnight():
    day = date(2026, 4, 1)
    early = datetime(2026, 4, 1, 0, 0, 0, tzinfo=timezone.utc)
    late = datetime(2026, 4, 1, 15, 0, tzinfo=timezone.utc)
    # kind order alone would put cve_published before first_seen; at puts it after.
    cve = CveRecord(cve_id="CVE-2099-000005", published_at=late, published_source="vulncheck_nvd2")
    f = _finding(first_seen_at=early + timedelta(hours=1), kev_date_added=day, ownership_confirmed_at=late
                 + timedelta(hours=1))
    events = build_timeline(f, cve, None, None)
    assert _kinds(events) == ["listed_exploited_cisa", "first_seen", "cve_published", "ownership_confirmed"]
    assert {e.date for e in events} == {day}


def test_the_order_is_not_a_fixed_kind_order():
    # A due date before first seen, and CISA listing after first seen.
    f = _finding(kev_date_added=date(2026, 3, 2))
    events = build_timeline(f, None, None, "2026-02-01")
    assert _kinds(events) == ["due", "first_seen", "listed_exploited_cisa"]


# -- acquired -----------------------------------------------------------------


def _acquisition_attr(rows, relation="acquired", name="Example Holdings B", entity_id=None, acquirer_id=None):
    org = _org(acquirer_id)
    ent = _entity(name, relation, rows, entity_id)
    return _attr(_chain(org, ent, _scope())), org, ent


def test_an_acquired_hop_gives_an_event_with_the_best_rows_fields():
    rid = uuid.uuid4()
    attr, org, ent = _acquisition_attr([_row(source="obs_a", relation_id=rid)])
    e = _one(build_timeline(_finding(), None, attr, None), "acquired")
    assert (e.date, e.precision, e.at, e.source) == (date(2020, 5, 17), "day", None, "obs_a")
    assert (e.entity_id, e.entity_name, e.acquirer_id) == (ent.entity_id, "Example Holdings B", org.entity_id)
    assert e.other_dates == []


def test_subsidiary_of_gives_no_event_next_to_an_acquired_one():
    org = _org()
    sub = _entity("Example Holdings C", "subsidiary_of", [_row(relation="subsidiary_of", source="obs_sub")])
    acq = _entity("Example Holdings B", "acquired", [_row(source="obs_acq")])
    attr = _attr(_chain(org, acq, sub, _scope()))
    events = [e for e in build_timeline(_finding(), None, attr, None) if e.kind == "acquired"]
    assert [e.entity_id for e in events] == [acq.entity_id]
    # the subsidiary hop is above nothing acquired; and an acquired hop whose only row says
    # subsidiary_of gives nothing either.
    odd = _entity("Example Holdings D", "acquired", [_row(relation="subsidiary_of")])
    attr2 = _attr(_chain(_org(), acq, odd, _scope()))
    ev2 = [e for e in build_timeline(_finding(), None, attr2, None) if e.kind == "acquired"]
    assert [e.entity_id for e in ev2] == [acq.entity_id]


def test_an_undated_acquisition_gives_no_event_next_to_a_dated_one():
    org = _org()
    dated = _entity("Example Holdings B", "acquired", [_row()])
    undated = _entity("Example Holdings E", "acquired",
                      [_row(event_date=None, precision="unknown"), _row(event_date=None, precision="day")])
    attr = _attr(_chain(org, dated, undated, _scope()))
    events = [e for e in build_timeline(_finding(), None, attr, None) if e.kind == "acquired"]
    assert [e.entity_id for e in events] == [dated.entity_id]


def test_a_row_with_a_date_but_precision_unknown_does_not_count():
    org = _org()
    dated = _entity("Example Holdings B", "acquired", [_row()])
    unk = _entity("Example Holdings F", "acquired", [_row(event_date=date(2019, 1, 1), precision="unknown")])
    attr = _attr(_chain(org, dated, unk, _scope()))
    events = [e for e in build_timeline(_finding(), None, attr, None) if e.kind == "acquired"]
    assert [e.entity_id for e in events] == [dated.entity_id]
    # and beside a usable row, the unknown-precision date is not used even if it would win
    mixed = _entity("Example Holdings G", "acquired",
                    [_row(event_date=date(2018, 1, 1), precision="unknown"),
                     _row(event_date=date(2021, 1, 1), precision="year", source="obs_y")])
    e = _one(build_timeline(_finding(), None, _attr(_chain(_org(), mixed, _scope())), None), "acquired")
    assert (e.date, e.precision, e.source) == (date(2021, 1, 1), "year", "obs_y")
    assert e.other_dates == []


def test_the_most_precise_row_wins_day_over_month_over_year():
    rows = [
        _row(event_date=date(2020, 1, 1), precision="year", source="obs_year"),
        _row(event_date=date(2020, 5, 1), precision="month", source="obs_month"),
        _row(event_date=date(2020, 5, 17), precision="day", source="obs_day"),
    ]
    attr, _, _ = _acquisition_attr(rows)
    e = _one(build_timeline(_finding(), None, attr, None), "acquired")
    assert (e.date, e.precision, e.source) == (date(2020, 5, 17), "day", "obs_day")
    assert {(d.date, d.precision, d.source) for d in e.other_dates} == {
        (date(2020, 5, 1), "month", "obs_month"), (date(2020, 1, 1), "year", "obs_year")}
    # month beats year when there is no day row
    attr2, _, _ = _acquisition_attr(rows[:2])
    e2 = _one(build_timeline(_finding(), None, attr2, None), "acquired")
    assert (e2.precision, e2.source) == ("month", "obs_month")


def test_a_precision_tie_takes_the_earliest_date_whatever_the_row_order():
    later = _row(event_date=date(2020, 9, 9), precision="day", source="obs_late")
    earlier = _row(event_date=date(2020, 3, 3), precision="day", source="obs_early")
    for rows in ([later, earlier], [earlier, later]):
        attr, _, _ = _acquisition_attr(rows)
        e = _one(build_timeline(_finding(), None, attr, None), "acquired")
        assert (e.date, e.source) == (date(2020, 3, 3), "obs_early")
        assert [(d.date, d.source) for d in e.other_dates] == [(date(2020, 9, 9), "obs_late")]


def test_other_dates_hold_only_dates_that_differ_and_collapse_duplicates():
    rows = [
        _row(event_date=date(2020, 5, 17), precision="day", source="obs_best"),
        _row(event_date=date(2020, 5, 17), precision="day", source="obs_same"),   # same as best: dropped
        _row(event_date=date(2020, 5, 1), precision="month", source="obs_m1"),
        _row(event_date=date(2020, 5, 1), precision="month", source="obs_m2"),    # duplicate of m1: collapsed
        _row(event_date=date(2020, 5, 1), precision="day", source="obs_d2"),      # same date, other precision
    ]
    attr, _, _ = _acquisition_attr(rows)
    e = _one(build_timeline(_finding(), None, attr, None), "acquired")
    assert (e.date, e.precision) == (date(2020, 5, 1), "day")  # earliest of the day rows
    got = sorted((d.date, d.precision) for d in e.other_dates)
    assert got == [(date(2020, 5, 1), "month"), (date(2020, 5, 17), "day")]
    assert len(e.other_dates) == 2


def test_the_same_acquisition_on_two_chains_is_one_event():
    acquirer = _org()
    ent_id = uuid.uuid4()
    row = _row()
    extra = _entity("Example Holdings H", "acquired", [_row(event_date=date(2022, 2, 2))])
    c1 = _chain(acquirer, _entity("Example Holdings B", "acquired", [row], ent_id), _scope())
    c2 = _chain(acquirer, _entity("Example Holdings B", "acquired", [row], ent_id), extra, _scope())
    events = [e for e in build_timeline(_finding(), None, _attr(c1, c2), None) if e.kind == "acquired"]
    # Reached: the second chain was walked (its extra acquisition is there), and B is not doubled.
    assert sorted(str(e.entity_id) for e in events) == sorted([str(ent_id), str(extra.entity_id)])


def test_the_same_entity_under_two_acquirers_is_two_events():
    ent_id = uuid.uuid4()
    org1, org2 = _org(), _org()
    c1 = _chain(org1, _entity("Example Holdings B", "acquired", [_row(source="obs_1")], ent_id), _scope())
    c2 = _chain(org2, _entity("Example Holdings B", "acquired", [_row(source="obs_2")], ent_id), _scope())
    events = [e for e in build_timeline(_finding(), None, _attr(c1, c2), None) if e.kind == "acquired"]
    assert sorted(str(e.acquirer_id) for e in events) == sorted([str(org1.entity_id), str(org2.entity_id)])
    assert {e.entity_id for e in events} == {ent_id}


def test_the_acquirer_is_the_hop_above_not_always_the_organization():
    org = _org()
    mid = _entity("Example Holdings B", "acquired", [_row(source="obs_1")])
    leaf = _entity("Example Holdings C", "acquired", [_row(source="obs_2", event_date=date(2021, 2, 2))])
    events = build_timeline(_finding(), None, _attr(_chain(org, mid, leaf, _scope())), None)
    by_entity = {e.entity_id: e for e in events if e.kind == "acquired"}
    assert by_entity[mid.entity_id].acquirer_id == org.entity_id
    assert by_entity[leaf.entity_id].acquirer_id == mid.entity_id


# -- claimed ------------------------------------------------------------------


def test_a_claimed_scope_gives_an_event_with_its_target():
    at = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
    scope = _scope(claimed_at=at, value="fabrikam.example.com")
    events = build_timeline(_finding(), None, _attr(_chain(_org(), scope)), None)
    e = _one(events, "claimed")
    assert (e.date, e.at, e.source) == (date(2020, 1, 1), at, None)
    assert (e.target_id, e.target_value) == (scope.target_id, "fabrikam.example.com")


def test_a_scope_with_no_claimed_at_gives_no_event_beside_a_claimed_one():
    at = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
    claimed = _scope(claimed_at=at, value="fabrikam.example.com")
    plain = _scope(claimed_at=None, value="plain.example.com")
    attr = _attr(_chain(_org(), claimed), _chain(_org(), plain))
    events = [e for e in build_timeline(_finding(), None, attr, None) if e.kind == "claimed"]
    assert [e.target_id for e in events] == [claimed.target_id]


def test_one_claimed_event_per_target_across_chains():
    at = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
    tid = uuid.uuid4()
    other = _scope(claimed_at=at, value="other.example.com")
    c1 = _chain(_org(), _scope(target_id=tid, claimed_at=at))
    c2 = _chain(_org(), _scope(target_id=tid, claimed_at=at))
    c3 = _chain(_org(), other)
    events = [e for e in build_timeline(_finding(), None, _attr(c1, c2, c3), None) if e.kind == "claimed"]
    assert sorted(str(e.target_id) for e in events) == sorted([str(tid), str(other.target_id)])


# -- no attribution -----------------------------------------------------------


def test_no_attribution_gives_no_acquired_or_claimed_but_the_rest():
    attr, _, _ = _acquisition_attr([_row()])
    attr.chains[0].hops[2] = _scope(claimed_at=datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc))
    f = _finding(kev_date_added=date(2026, 2, 1))
    with_attr = _kinds(build_timeline(f, None, attr, "2026-03-01"))
    assert "acquired" in with_attr and "claimed" in with_attr  # reached
    without = _kinds(build_timeline(f, None, None, "2026-03-01"))
    assert without == ["listed_exploited_cisa", "due", "first_seen"]


# -- guards that back each other up -------------------------------------------


def test_an_entity_hop_not_marked_acquired_gives_no_event_even_with_an_acquired_row():
    # The hop says subsidiary_of; one of its rows says acquired (inconsistent
    # input). The hop's relation decides. A real acquired hop sits beside it.
    org = _org()
    odd = _entity("Example Holdings C", "subsidiary_of", [_row(relation="acquired", source="obs_odd")])
    real = _entity("Example Holdings B", "acquired", [_row(source="obs_real")])
    events = [e for e in build_timeline(_finding(), None, _attr(_chain(org, real, odd, _scope())), None)
              if e.kind == "acquired"]
    assert [e.entity_id for e in events] == [real.entity_id]


def test_a_row_with_unknown_precision_does_not_crash_or_count_when_it_is_the_only_one():
    org = _org()
    only_unknown = _entity("Example Holdings F", "acquired", [_row(event_date=date(2019, 1, 1), precision="unknown")])
    real = _entity("Example Holdings B", "acquired", [_row(source="obs_real")])
    events = [e for e in build_timeline(_finding(), None, _attr(_chain(org, real, only_unknown, _scope())), None)
              if e.kind == "acquired"]
    assert [e.entity_id for e in events] == [real.entity_id]


def test_a_target_seen_unclaimed_on_one_chain_is_still_claimed_from_another():
    at = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
    tid = uuid.uuid4()
    c1 = _chain(_org(), _scope(target_id=tid, claimed_at=None))
    c2 = _chain(_org(), _scope(target_id=tid, claimed_at=at))
    events = [e for e in build_timeline(_finding(), None, _attr(c1, c2), None) if e.kind == "claimed"]
    assert [(e.target_id, e.at) for e in events] == [(tid, at)]


def test_events_on_the_same_instant_come_out_in_a_fixed_order_whatever_the_input_order():
    a = _entity("Example Holdings B", "acquired", [_row(event_date=date(2021, 1, 1))])
    b = _entity("Example Holdings C", "acquired", [_row(event_date=date(2021, 1, 1))])
    org = _org()
    ca, cb = _chain(org, a, _scope()), _chain(org, b, _scope())
    fwd = build_timeline(_finding(), None, _attr(ca, cb), None)
    rev = build_timeline(_finding(), None, _attr(cb, ca), None)
    assert fwd == rev
    assert len([e for e in fwd if e.kind == "acquired"]) == 2  # reached: both on the same day
    # Two day-only events on one day: ordered by kind, not by the order they are built in.
    f = _finding(kev_date_added=date(2026, 2, 1))
    cve = CveRecord(cve_id="CVE-2099-000009", vulncheck_kev_date_added=date(2026, 2, 1))
    events = build_timeline(f, cve, None, "2026-02-01")
    assert _kinds(events) == ["due", "listed_exploited_cisa", "listed_exploited_vulncheck", "first_seen"]
