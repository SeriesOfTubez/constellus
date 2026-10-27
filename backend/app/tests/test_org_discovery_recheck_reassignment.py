"""Re-check wiring of the reassigned-away sweep (planning#278 S3c3b2, slice A).

Offline: `covering.fetch_arin` / `fetch_ripe` are replaced with spies returning
constructed `Covering` objects. Synthetic data only (RFC 3849 prefixes,
`EXAMPLE-*` handles).

Run with:  scripts/test.sh app/tests/test_org_discovery_recheck_reassignment.py
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from app.models.evidence import EvidenceBlob, EvidenceFetch
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateReassignment
from app.services import entity_graph
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import covering, ripe, runner
from app.services.org_discovery.covering import Covering
from app.services.org_discovery.generators import RirDedicatedIpResult
from app.services.org_discovery.reassignment import Registration, RegistryAnswer
from app.tests.test_org_discovery_asn_cidr import _cidr, meta, w  # noqa: F401
from app.tests.test_org_discovery_schema import _claimed, _insert_candidate

ARIN_H = "EXAMPLE-A-ARIN"
RIPE_H = "ORG-EXA1-RIPE"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _slots():
    runner._recheck_running.clear()
    yield
    runner._recheck_running.clear()


class Spy:
    """Records (prefix, fresh_since); returns a per-prefix Covering (or raises)."""

    def __init__(self):
        self.calls: list[tuple[str, datetime | None]] = []
        self.answers: dict[str, Covering | Exception] = {}

    def __call__(self, db, prefix, budget):
        self.calls.append((prefix, budget.fresh_since))
        got = self.answers.get(prefix)
        if isinstance(got, Exception):
            raise got
        return got if got is not None else complete(Registration(prefix, "org", "EXAMPLE-DEFAULT"))

    @property
    def prefixes(self):
        return [p for p, _ in self.calls]


@pytest.fixture
def spies(monkeypatch):
    a, r = Spy(), Spy()
    monkeypatch.setattr(covering, "fetch_arin", a)
    monkeypatch.setattr(covering, "fetch_ripe", r)
    return a, r


def complete(*regs, sources=(("lbl", {"k": 1}),)):
    return Covering(RegistryAnswer(True, tuple(regs)), None, tuple(sources))


def incomplete(reason="truncated"):
    return Covering(RegistryAnswer(False, ()), reason, ())


def half(prefix):
    return str(next(ipaddress.ip_network(prefix).subnets()))


def ripe_signal(w, root, cand, *, holder_kind, holder=RIPE_H, rir="ripe"):
    """A rir_contact_email_unvalidated signal whose evidence body has ripe.py's keys."""
    dom = _insert_candidate(w.db, root.id, value=f"anchor-{cand.value[-8:-3].replace(':', '')}.example.test",
                            **_claimed(root.id))
    body = {"rule": "rir_contact_email_unvalidated", "rir": rir, "holder": holder, "holder_kind": holder_kind}
    ev = entity_graph.store_evidence(
        w.db, content=json.dumps(body, sort_keys=True).encode(), content_type="application/json",
        source_url=f"https://org-discovery.invalid/generate/test/{cand.id}/{holder_kind}", fetched_at=NOW,
    )
    w.evidence.append(ev.id)
    cd.record_signal(
        w.db, root_entity_id=root.id, value=cand.value, kind="cidr", rir="ripe", rir_handle=cand.rir_handle,
        signal_type="rir_contact_email_unvalidated", anchor_kind="claimed_candidate", anchor_candidate_id=dom,
        via_entity_id=root.id, evidence_id=ev.id, quote=f"inetnum: {ipaddress.ip_network(cand.value).network_address}",
    )
    w.db.commit()


def claim(w, root, n, *, rir="arin", handle=ARIN_H):
    cand = _cidr(w, root, n, rir=rir, handle=handle)
    res = cd.claim(w.db, candidate_id=cand.id, user=w.user())
    w.track_target(res.target.value)
    w.db.commit()
    return cand


def rows(w, cid):
    w.db.expire_all()
    return w.db.execute(
        select(ScopeCandidateReassignment).where(ScopeCandidateReassignment.candidate_id == cid)
    ).scalars().all()


def evidence_count(w):
    w.db.expire_all()
    return w.db.execute(select(func.count()).select_from(EvidenceFetch)).scalar_one()


def sweep(root, fresh=NOW):
    return runner.reassignment_for_root(root.id, fresh_since=fresh)


def test_arin_reassigned_part_recorded_then_resighted(w, spies):
    arin_spy, _ = spies
    root = w.ours()
    c = claim(w, root, 1)
    part = half(c.value)
    arin_spy.answers[c.value] = complete(Registration(part, "org", "EXAMPLE-B"), Registration(c.value, "org", ARIN_H))
    res = sweep(root)
    assert (res.candidates, res.reassigned, res.parts_created, res.parts_seen, res.failed) == (1, 1, 1, 0, 0)
    (row,) = rows(w, c.id)
    assert (row.prefix, row.new_holder_kind, row.new_holder_handle) == (part, "org", "EXAMPLE-B")
    ev = w.db.get(EvidenceFetch, row.evidence_id)
    body = json.loads(bytes(w.db.get(EvidenceBlob, ev.sha256).content))
    assert body["rule"] == "rir_reassigned_away" and body["sources"] == [{"label": "lbl", "body": {"k": 1}}]
    assert body["holder_handle"] == ARIN_H and body["candidate_id"] == str(c.id)
    first = row.first_detected_at
    res2 = sweep(root)
    (row2,) = rows(w, c.id)
    assert (res2.parts_created, res2.parts_seen, res2.reassigned) == (0, 1, 1)
    assert row2.first_detected_at == first and row2.last_seen_at >= first


def test_registry_follows_rir(w, spies):
    a, r = spies
    root = w.ours()
    ca = claim(w, root, 1)
    cr = claim(w, root, 2, rir="ripe", handle=RIPE_H)
    ripe_signal(w, root, cr, holder_kind="org")
    res = sweep(root)
    assert res.candidates == 2 and res.clean + res.reassigned == 2
    assert a.prefixes == [ca.value] and r.prefixes == [cr.value]


def test_ripe_contact_held_makes_no_request_but_org_sibling_is_fetched(w, spies):
    _, r = spies
    root = w.ours()
    contact = claim(w, root, 1, rir="ripe", handle=RIPE_H)
    ripe_signal(w, root, contact, holder_kind="contact")
    org = claim(w, root, 2, rir="ripe", handle="ORG-EXA2-RIPE")
    ripe_signal(w, root, org, holder_kind="org", holder="ORG-EXA2-RIPE")
    res = sweep(root)
    assert res.candidates == 2
    assert res.indeterminate == {"contact_held": 1}
    assert r.prefixes == [org.value]
    assert not rows(w, contact.id)


def test_ripe_without_matching_signal_is_holder_unknown(w, spies):
    _, r = spies
    root = w.ours()
    none = claim(w, root, 1, rir="ripe", handle=RIPE_H)
    other = claim(w, root, 2, rir="ripe", handle="ORG-EXA3-RIPE")
    ripe_signal(w, root, other, holder_kind="org", holder="ORG-OTHER-RIPE")  # holder != rir_handle
    org = claim(w, root, 3, rir="ripe", handle="ORG-EXA4-RIPE")
    ripe_signal(w, root, org, holder_kind="org", holder="ORG-EXA4-RIPE")
    res = sweep(root)
    assert res.candidates == 3 and res.indeterminate == {"holder_unknown": 2}
    assert r.prefixes == [org.value]
    assert none.value not in r.prefixes


def test_ripe_unparseable_or_odd_kind_is_holder_unknown(w, spies):
    _, r = spies
    root = w.ours()
    c = claim(w, root, 1, rir="ripe", handle=RIPE_H)
    ripe_signal(w, root, c, holder_kind="weird")
    ok = claim(w, root, 2, rir="ripe", handle="ORG-EXA5-RIPE")
    ripe_signal(w, root, ok, holder_kind="org", holder="ORG-EXA5-RIPE")
    res = sweep(root)
    assert res.indeterminate == {"holder_unknown": 1} and r.prefixes == [ok.value]


def test_unsupported_rir_makes_no_request(w, spies):
    a, r = spies
    root = w.ours()
    c = claim(w, root, 1, rir="apnic", handle="EXAMPLE-AP")
    sib = claim(w, root, 2)
    res = sweep(root)
    assert res.candidates == 2 and res.indeterminate == {"unsupported_rir": 1}
    assert a.prefixes == [sib.value] and r.prefixes == [] and c.value not in a.prefixes


def test_incomplete_covering_writes_nothing(w, spies):
    a, _ = spies
    root = w.ours()
    c = claim(w, root, 1)
    a.answers[c.value] = incomplete("truncated")
    before = evidence_count(w)
    res = sweep(root)
    assert a.prefixes == [c.value]  # reached
    assert res.indeterminate == {"truncated": 1} and res.reassigned == 0
    assert evidence_count(w) == before and not rows(w, c.id)


def test_detect_indeterminate_writes_nothing(w, spies):
    a, _ = spies
    root = w.ours()
    c = claim(w, root, 1)
    a.answers[c.value] = complete(Registration(c.value, "org", ARIN_H), Registration(c.value, "org", "EXAMPLE-B"))
    before = evidence_count(w)
    res = sweep(root)
    assert a.prefixes == [c.value] and res.indeterminate == {"detect_indeterminate": 1}
    assert evidence_count(w) == before and not rows(w, c.id)


def test_clean_writes_no_evidence(w, spies):
    a, _ = spies
    root = w.ours()
    c = claim(w, root, 1)
    a.answers[c.value] = complete(Registration(c.value, "org", ARIN_H))
    before = evidence_count(w)
    res = sweep(root)
    assert a.prefixes == [c.value] and res.clean == 1 and res.reassigned == 0
    assert evidence_count(w) == before and not rows(w, c.id)


def test_only_claimed_cidrs_of_this_root_are_fetched(w, spies):
    a, _ = spies
    root, other = w.ours(), w.entity()
    mine = claim(w, root, 1)
    open_c = _cidr(w, root, 2, rir="arin", handle=ARIN_H)  # stays open
    rejected = _cidr(w, root, 3, rir="arin", handle=ARIN_H)
    cd.reject(w.db, candidate_id=rejected.id, user=w.user(), reason="not ours")
    w.db.commit()
    w.db.refresh(rejected)
    assert rejected.status == "rejected" and open_c.status == "open"
    other_root = w.ours(other)
    theirs = claim(w, other_root, 4)
    _insert_candidate(w.db, root.id, value="claimed-domain.example.test", **_claimed(root.id))  # a domain: not cidr
    res = sweep(root)
    assert res.candidates == 1
    assert a.prefixes == [mine.value]
    assert open_c.value not in a.prefixes and theirs.value not in a.prefixes


def test_the_claim_is_untouched_after_a_reassigned_run(w, spies):
    a, _ = spies
    root = w.ours()
    c = claim(w, root, 1)
    before = (c.status, c.target_id, c.decided_at)
    assert before[0] == "claimed" and before[1] is not None
    a.answers[c.value] = complete(Registration(c.value, "org", "EXAMPLE-B"))
    assert sweep(root).reassigned == 1
    w.db.expire_all()
    c2 = w.db.get(ScopeCandidate, c.id)
    assert (c2.status, c2.target_id, c2.decided_at) == before


def test_verify_after_claim_does_not_run_the_sweep(w, spies, monkeypatch):
    a, r = spies
    root = w.ours()
    c = claim(w, root, 1)
    dom = _insert_candidate(w.db, root.id, value="vac.example.test", **_claimed(root.id))
    reached: list = []
    monkeypatch.setattr(runner, "reverse_ip_for_claimed", lambda cid: reached.append("rev"))
    monkeypatch.setattr(runner, "rir_for_claimed", lambda cid: reached.append("rir"))
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda rid: reached.append("ded"))
    report = runner.verify_after_claim(dom)
    assert reached == ["rev", "rir", "ded"] and report is not None  # verify ran to its end
    assert a.calls == [] and r.calls == []
    assert c.id  # a claimed cidr existed in the root throughout


def _recheck_stubs(monkeypatch):
    def rir(db, domain, fresh_since=None):
        from app.services.org_discovery import arin
        return arin.ArinCollection(domain=domain, pocs_listed=0, pocs_truncated=False, pocs_not_exact=0, matched=())

    def rip(db, domain, fresh_since=None):
        return ripe.RipeCollection(
            domain=domain, docs_found=0, docs_seen=0, fulltext_truncated=False, docs_other_type=0,
            contacts_not_exact=0, matched=(), resources=(), orgs_followed=0, fetch_failed=0,
            budget_exhausted=False, invalid_handles=0, invalid=0, skipped_status=0, skipped_source=0,
        )

    monkeypatch.setattr(runner, "_rir_collect", rir)
    monkeypatch.setattr(runner, "_ripe_collect", rip)
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda r: RirDedicatedIpResult())


def test_recheck_root_fresh_since_is_one_run_level_stamp(w, spies, monkeypatch):
    a, r = spies
    _recheck_stubs(monkeypatch)
    root = w.ours()
    c1 = claim(w, root, 1)
    c2 = claim(w, root, 2, rir="ripe", handle=RIPE_H)
    ripe_signal(w, root, c2, holder_kind="org")
    runner.try_begin_recheck(root.id)
    before = datetime.now(timezone.utc)
    runner.recheck_root(root.id)
    stamps = {f for _, f in a.calls + r.calls}
    assert len(a.calls + r.calls) == 2 and len(stamps) == 1
    (fs,) = stamps
    assert fs is not None and fs >= before


def test_recheck_root_integration_populates_result_and_releases_slot(w, spies, monkeypatch):
    a, _ = spies
    _recheck_stubs(monkeypatch)
    root = w.ours()
    c = claim(w, root, 1)
    a.answers[c.value] = complete(Registration(half(c.value), "org", "EXAMPLE-B"), Registration(c.value, "org", ARIN_H))
    assert runner.try_begin_recheck(root.id)
    result = runner.recheck_root(root.id)
    assert (result.reassignment.candidates, result.reassignment.reassigned, result.reassignment.parts_created) == (1, 1, 1)
    assert len(rows(w, c.id)) == 1
    assert runner.try_begin_recheck(root.id)  # slot was released


def test_a_failing_candidate_does_not_stop_the_next(w, spies):
    a, _ = spies
    root = w.ours()
    c1, c2 = claim(w, root, 1), claim(w, root, 2)
    first, second = sorted([c1, c2], key=lambda c: c.id)
    a.answers[first.value] = RuntimeError("boom")
    a.answers[second.value] = complete(Registration(second.value, "org", "EXAMPLE-B"))
    res = sweep(root)
    assert a.prefixes == [first.value, second.value]
    assert res.failed == 1 and res.reassigned == 1
    assert len(rows(w, second.id)) == 1 and not rows(w, first.id)


def test_a_sweep_that_raises_does_not_skip_dedicated_or_the_slot(w, monkeypatch):
    _recheck_stubs(monkeypatch)
    swept: list = []
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda r: swept.append(r) or RirDedicatedIpResult())

    def boom(*a, **k):
        raise RuntimeError("sweep down")

    monkeypatch.setattr(runner, "reassignment_for_root", boom)
    root = w.ours()
    runner.try_begin_recheck(root.id)
    result = runner.recheck_root(root.id)  # does not raise
    assert swept == [root.id] and result.reassignment.candidates == 0
    assert runner.try_begin_recheck(root.id)
