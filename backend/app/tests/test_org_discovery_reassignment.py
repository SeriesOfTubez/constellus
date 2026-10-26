"""Reassigned-away detection and its record (planning#278 S3c3a).

`detect` is pure (no DB). The writer tests use a real claimed CIDR candidate
and its Target. Synthetic data only: RFC 5737 / RFC 3849 ranges and
`EXAMPLE-*` handles.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from app.models.scope_candidate import ScopeCandidate, ScopeCandidateReassignment
from app.models.target import Target
from app.services.org_discovery import candidates as cd
from app.services.org_discovery.reassignment import (
    Reassigned,
    Registration,
    RegistryAnswer,
    detect,
    record_reassignment,
)

# Reused fixtures (a throwaway World; the cloud-ranges meta row a CIDR claim needs).
from app.tests.test_org_discovery_asn_cidr import _cidr, meta, w  # noqa: F401

P = "192.0.2.128/25"
HOLDER = "EXAMPLE-A-ARIN"

# The claimed prefix is the upper half of 192.0.2.0/24 and its parts sit above .128, outside the
# `_docaddr` pool (test_docaddr_guard R3).
# CIDRs nest or are disjoint: a registration can contain P or lie inside P but
# never overlap it partially, so there is no "partial overlap" case to test.


def org(prefix, handle=HOLDER):
    return Registration(prefix, "org", handle)


def foreign(prefix, handle="EXAMPLE-B", kind="org"):
    return Registration(prefix, kind, handle)


def answer(*regs, complete=True):
    return RegistryAnswer(complete, tuple(regs))


def r(prefix, kind="org", handle="EXAMPLE-B"):
    return Reassigned(prefix, kind, handle)


# ── indeterminate: None, never () ───────────────────────────────────────────


def test_an_incomplete_answer_is_indeterminate():
    assert detect(P, HOLDER, answer(foreign(P), complete=False)) is None
    assert detect(P, HOLDER, answer(org(P), complete=False)) is None


@pytest.mark.parametrize("bad", ["not-a-cidr", "192.0.2.1/24", "192.0.2.0/33", ""])
def test_an_unparseable_or_non_strict_claimed_prefix_is_indeterminate(bad):
    assert detect(bad, HOLDER, answer(org(P))) is None


@pytest.mark.parametrize("bad", ["garbage", "192.0.2.1/24", "198.51.100.1/24"])
def test_an_unparseable_registration_is_indeterminate_even_when_unrelated(bad):
    assert detect(P, HOLDER, answer(org(P), foreign(bad))) is None


@pytest.mark.parametrize("holder", ["", "   "])
def test_a_blank_claimed_holder_is_indeterminate(holder):
    assert detect(P, holder, answer(org(P))) is None


@pytest.mark.parametrize("reg", [
    Registration("198.51.100.0/24", "org", None),
    Registration("198.51.100.0/24", "customer", None),
    Registration("198.51.100.0/24", "unknown", "EXAMPLE-B"),
    Registration("198.51.100.0/24", "org", "  "),
    Registration("198.51.100.0/24", "unregistered", None),  # not a registry-side kind
])
def test_an_inconsistent_kind_handle_pairing_is_indeterminate_even_when_unrelated(reg):
    assert detect(P, HOLDER, answer(org(P), reg)) is None


def test_two_holders_for_the_same_prefix_is_ambiguous():
    assert detect(P, HOLDER, answer(org(P), foreign(P))) is None
    assert detect(P, HOLDER, answer(foreign(P, "EXAMPLE-B"), foreign(P, "EXAMPLE-C"))) is None


def test_the_same_registration_twice_is_not_ambiguous():
    assert detect(P, HOLDER, answer(org(P), org(P))) == ()


# ── nothing reassigned: () ──────────────────────────────────────────────────


def test_an_exact_registration_to_the_holder_is_nothing_reassigned():
    assert detect(P, HOLDER, answer(org(P))) == ()


def test_customer_kind_with_the_holders_handle_counts_as_the_holder():
    assert detect(P, HOLDER, answer(Registration(P, "customer", HOLDER))) == ()


def test_handle_case_does_not_matter():
    assert detect(P, HOLDER, answer(org(P, HOLDER.lower()))) == ()
    assert detect(P, HOLDER.lower(), answer(org(P))) == ()


def test_a_foreign_parent_over_a_more_specific_registration_to_the_holder_is_not_reported():
    assert detect(P, HOLDER, answer(foreign("192.0.0.0/16"), org(P))) == ()


def test_the_holders_parent_over_the_claimed_prefix_is_nothing_reassigned():
    assert detect(P, HOLDER, answer(org("192.0.0.0/16"))) == ()


def test_the_holder_covering_all_halves_is_nothing_reassigned():
    assert detect(P, HOLDER, answer(org("192.0.2.128/26"), org("192.0.2.192/26"))) == ()


# ── reassigned ──────────────────────────────────────────────────────────────


def test_a_whole_net_transfer_is_the_whole_prefix():
    assert detect(P, HOLDER, answer(foreign(P))) == (r(P),)


def test_a_foreign_parent_larger_than_the_prefix_yields_the_prefix_not_the_parent():
    assert detect(P, HOLDER, answer(foreign("192.0.0.0/16"))) == (r(P),)


def test_a_foreign_child_inside_a_same_holder_parent_is_only_the_child():
    got = detect("192.0.2.128/25", HOLDER, answer(org("192.0.0.0/16"), foreign("192.0.2.160/27")))
    assert got == (r("192.0.2.160/27"),)


def test_handles_are_reported_as_the_registry_wrote_them():
    assert detect(P, HOLDER, answer(foreign(P, "Example-B"))) == (r(P, handle="Example-B"),)


def test_a_hole_is_unregistered_and_collapsed():
    got = detect(P, HOLDER, answer(org("192.0.2.128/26")))
    assert got == (Reassigned("192.0.2.192/26", "unregistered", None),)
    got = detect(P, HOLDER, answer(org("192.0.2.128/27"), org("192.0.2.224/27")))
    assert got == (Reassigned("192.0.2.160/27", "unregistered", None), Reassigned("192.0.2.192/27", "unregistered", None))
    # two adjacent holes become one prefix
    got = detect(P, HOLDER, answer(org("192.0.2.128/27"), org("192.0.2.192/27")))
    assert got == (Reassigned("192.0.2.160/27", "unregistered", None), Reassigned("192.0.2.224/27", "unregistered", None))


def test_no_overlapping_registration_at_all_is_unregistered():
    assert detect(P, HOLDER, answer()) == (Reassigned(P, "unregistered", None),)
    assert detect(P, HOLDER, answer(foreign("198.51.100.0/24"))) == (Reassigned(P, "unregistered", None),)


def test_two_foreign_holders_are_two_groups_in_address_order():
    got = detect(P, HOLDER, answer(foreign("192.0.2.192/26", "EXAMPLE-C"), foreign("192.0.2.128/26", "EXAMPLE-B")))
    assert got == (r("192.0.2.128/26", handle="EXAMPLE-B"), r("192.0.2.192/26", handle="EXAMPLE-C"))


def test_one_foreign_holder_with_adjacent_pieces_is_collapsed():
    got = detect(P, HOLDER, answer(foreign("192.0.2.128/27"), foreign("192.0.2.160/27"), org("192.0.2.192/26")))
    assert got == (r("192.0.2.128/26"),)


def test_foreign_holders_and_a_hole_are_all_reported_sorted():
    got = detect(P, HOLDER, answer(org("192.0.2.128/27"), foreign("192.0.2.160/27"), foreign("192.0.2.224/27", kind="customer")))
    assert got == (
        r("192.0.2.160/27"),
        Reassigned("192.0.2.192/27", "unregistered", None),
        r("192.0.2.224/27", kind="customer"),
    )


def test_an_unknown_holder_is_kind_unknown_with_no_handle():
    got = detect(P, HOLDER, answer(Registration("192.0.2.128/26", "unknown", None), org("192.0.2.192/26")))
    assert got == (Reassigned("192.0.2.128/26", "unknown", None),)


def test_unknown_is_never_the_holder():
    assert detect(P, HOLDER, answer(Registration(P, "unknown", None))) == (Reassigned(P, "unknown", None),)


def test_ties_in_address_and_length_sort_by_kind_then_handle():
    got = detect(P, HOLDER, answer(foreign("192.0.2.128/26", "EXAMPLE-C"), foreign("192.0.2.192/26", "EXAMPLE-B")))
    assert [x.new_holder_handle for x in got] == ["EXAMPLE-C", "EXAMPLE-B"]  # address order wins over handle


def test_ipv6_works_and_a_huge_prefix_is_not_enumerated():
    start = time.monotonic()
    got = detect("2001:db8::/32", HOLDER, answer(org("2001:db8::/32"), foreign("2001:db8:1::/48")))
    assert got == (r("2001:db8:1::/48"),)
    got = detect("2001:db8::/32", HOLDER, answer(foreign("2001:db8:1::/48"), org("2001:db8:2::/48")))
    assert got is not None and r("2001:db8:1::/48") in got
    assert Reassigned("2001:db8::/48", "unregistered", None) in got
    assert time.monotonic() - start < 2


def test_a_registration_of_the_other_ip_version_is_ignored():
    assert detect(P, HOLDER, answer(org(P), foreign("2001:db8::/32"))) == ()
    assert detect("2001:db8::/32", HOLDER, answer(org("2001:db8::/32"), foreign(P))) == ()
    assert detect(P, HOLDER, answer(foreign("2001:db8::/32"))) == (Reassigned(P, "unregistered", None),)


def test_registrations_outside_the_claimed_prefix_are_ignored():
    assert detect(P, HOLDER, answer(org(P), foreign("198.51.100.0/24"), foreign("203.0.113.0/24"))) == ()


# ── the writer ──────────────────────────────────────────────────────────────

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _claim(w):
    root = w.ours()
    cand = _cidr(w, root, 5)  # 2001:db8:278:5::/64
    result = cd.claim(w.db, candidate_id=cand.id, user=w.user())
    w.track_target(result.target.value)
    w.db.commit()
    return cand


def _rows(db, cid):
    return db.execute(select(ScopeCandidateReassignment).where(ScopeCandidateReassignment.candidate_id == cid)).scalars().all()


def _snapshot(db, cand_id):
    db.expire_all()
    c = db.execute(select(ScopeCandidate).where(ScopeCandidate.id == cand_id)).scalar_one()
    t = db.execute(select(Target).where(Target.id == c.target_id)).scalar_one()
    return (
        (c.status, c.decided_at, c.target_id, c.accepted_into, c.affiliated_entity_id, c.rir_handle),
        (t.id, t.type, t.value, t.entity_id, t.verified, t.is_active if hasattr(t, "is_active") else None),
    )


def test_first_sighting_is_created_with_first_equal_last(w):
    cand = _claim(w)
    ev = w.evidence_row()
    found = Reassigned(f"{cand.value[:-3]}/65", "org", "EXAMPLE-B")
    assert record_reassignment(w.db, candidate_id=cand.id, found=found, evidence_id=ev.id, now=T0) == "created"
    w.db.commit()
    (row,) = _rows(w.db, cand.id)
    assert (row.first_detected_at, row.last_seen_at, row.evidence_id) == (T0, T0, ev.id)
    assert (row.prefix, row.new_holder_kind, row.new_holder_handle) == (found.prefix, "org", "EXAMPLE-B")


def test_a_repeat_sighting_moves_last_seen_only(w):
    cand = _claim(w)
    ev1, ev2 = w.evidence_row(), w.evidence_row()
    found = Reassigned(cand.value, "unregistered", None)  # NULL handle: the NULLS NOT DISTINCT path
    assert record_reassignment(w.db, candidate_id=cand.id, found=found, evidence_id=ev1.id, now=T0) == "created"
    later = T0 + timedelta(days=3)
    assert record_reassignment(w.db, candidate_id=cand.id, found=found, evidence_id=ev2.id, now=later) == "seen"
    w.db.commit()
    (row,) = _rows(w.db, cand.id)
    assert (row.first_detected_at, row.last_seen_at, row.evidence_id) == (T0, later, ev1.id)


def test_an_earlier_now_does_not_move_last_seen_backwards(w):
    cand = _claim(w)
    ev = w.evidence_row()
    found = Reassigned(cand.value, "org", "EXAMPLE-B")
    record_reassignment(w.db, candidate_id=cand.id, found=found, evidence_id=ev.id, now=T0)
    record_reassignment(w.db, candidate_id=cand.id, found=found, evidence_id=ev.id, now=T0 + timedelta(days=2))
    assert record_reassignment(
        w.db, candidate_id=cand.id, found=found, evidence_id=ev.id, now=T0 + timedelta(days=1)
    ) == "seen"
    w.db.commit()
    (row,) = _rows(w.db, cand.id)
    assert row.last_seen_at == T0 + timedelta(days=2)


def test_a_different_new_holder_is_a_new_row(w):
    cand = _claim(w)
    ev = w.evidence_row()
    for handle in ("EXAMPLE-B", "EXAMPLE-C"):
        out = record_reassignment(
            w.db, candidate_id=cand.id, found=Reassigned(cand.value, "org", handle), evidence_id=ev.id, now=T0
        )
        assert out == "created"
    w.db.commit()
    assert sorted(x.new_holder_handle for x in _rows(w.db, cand.id)) == ["EXAMPLE-B", "EXAMPLE-C"]


def test_recording_never_unclaims_the_candidate_or_touches_its_target(w):
    cand = _claim(w)
    before = _snapshot(w.db, cand.id)
    assert before[0][0] == "claimed" and before[0][2] is not None  # the precondition holds
    ev = w.evidence_row()
    record_reassignment(w.db, candidate_id=cand.id, found=Reassigned(cand.value, "unregistered", None),
                        evidence_id=ev.id, now=T0)
    w.db.commit()
    assert len(_rows(w.db, cand.id)) == 1  # it did record
    assert _snapshot(w.db, cand.id) == before


def test_an_open_candidate_raises_and_the_claimed_one_succeeds(w):
    root = w.ours()
    cand = _cidr(w, root, 6)  # open
    ev = w.evidence_row()
    found = Reassigned(cand.value, "org", "EXAMPLE-B")
    with pytest.raises(Exception, match="claimed cidr"):
        record_reassignment(w.db, candidate_id=cand.id, found=found, evidence_id=ev.id, now=T0)
    w.db.rollback()
    result = cd.claim(w.db, candidate_id=cand.id, user=w.user())
    w.track_target(result.target.value)
    w.db.commit()
    assert record_reassignment(w.db, candidate_id=cand.id, found=found, evidence_id=ev.id, now=T0) == "created"
    w.db.commit()


def test_a_prefix_outside_the_candidate_raises(w):
    cand = _claim(w)
    ev = w.evidence_row()
    with pytest.raises(Exception, match="claimed cidr"):
        record_reassignment(w.db, candidate_id=cand.id, found=Reassigned("2001:db8:278:6::/64", "org", "EXAMPLE-B"),
                            evidence_id=ev.id, now=T0)
    w.db.rollback()
    assert not _rows(w.db, cand.id)
