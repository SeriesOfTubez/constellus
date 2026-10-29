"""Automatic rolling page capture (planning#277 S6a, hourly since S6b): `request_capture(user=None)`,
`run_automatic_sweep`, the `page_capture_skips` table and its API. Synthetic names
(fabrikam.com) only. The sweep scans EVERY open domain candidate, so each test relies on
the suite leaving none behind (the `w` fixture removes everything it makes).

Run with:  backend/scripts/test.sh app/tests/test_page_capture_sweep.py
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.database import SessionLocal
from app.models.page_capture import PageCapture, PageCaptureRequest, PageCaptureSkip
from app.models.user import UserRole
from app.services import page_capture as pc
from app.services import read_scope, wayback
from app.tests import _decision_log
from app.tests._org_world import World, client
from app.tests.test_org_discovery_schema import _claimed, _insert_candidate, _rejected
from app.tests.test_page_capture_archive import _restricted, mock_wayback, wire, NONE  # noqa: F401
from app.tests.test_page_capture_service import (  # noqa: F401 (fixtures + helpers)
    _candidate, _dom, _no_job_files, _row_for, _rows_for, env,
)


@pytest.fixture
def w(env):
    mark = _decision_log.watermark()
    world = World()
    world.cap_candidates = []
    try:
        yield world
    finally:
        world.db.rollback()
        ids = world.db.query(PageCapture.id).filter(PageCapture.candidate_id.in_(world.cap_candidates))
        world.db.query(PageCaptureRequest).filter(PageCaptureRequest.capture_id.in_(ids)).delete(
            synchronize_session=False
        )
        world.db.query(PageCapture).filter(PageCapture.candidate_id.in_(world.cap_candidates)).delete(
            synchronize_session=False
        )
        world.db.query(PageCaptureSkip).filter(PageCaptureSkip.candidate_id.in_(world.cap_candidates)).delete(
            synchronize_session=False
        )
        world.db.commit()
        world.close()
        _decision_log.cleanup_since(mark)


@pytest.fixture
def sleeps(monkeypatch):
    seen: list = []
    monkeypatch.setattr(pc, "_sleep", seen.append)
    return seen


def _skips(candidate_id) -> list[str]:
    db = SessionLocal()
    try:
        return [
            r.reason for r in db.query(PageCaptureSkip).filter(PageCaptureSkip.candidate_id == candidate_id)
            .order_by(PageCaptureSkip.id)
        ]
    finally:
        db.close()


def _captures(candidate_id) -> list[PageCapture]:
    db = SessionLocal()
    try:
        rows = db.query(PageCapture).filter(PageCapture.candidate_id == candidate_id).all()
        for r in rows:
            db.expunge(r)
        return rows
    finally:
        db.close()


# ── request_capture(user=None) ───────────────────────────────────────────────


def test_automatic_request_has_no_requester_and_manual_needs_a_user(w, env):
    c = _candidate(w)
    row = pc.request_capture(w.db, candidate_id=c.id, user=None, manual=False)
    caps = _captures(c.id)
    assert [(r.id, r.status, r.requested_by_id) for r in caps] == [(row.id, "queued", None)]  # path reached
    assert len(_no_job_files(env)) == 1

    c2 = _candidate(w)
    with pytest.raises(ValueError):
        pc.request_capture(w.db, candidate_id=c2.id, user=None, manual=True)
    assert _rows_for(c2.id) == 0 and len(_no_job_files(env)) == 1


# ── the sweep ────────────────────────────────────────────────────────────────


def test_sweep_queues_each_eligible_open_domain_and_ignores_the_rest(w, env, sleeps):
    a, b = _candidate(w), _candidate(w)
    root = w.ours()
    claimed = _insert_candidate(w.db, root.id, **_claimed(w.entity().id))
    rejected = _insert_candidate(w.db, root.id, **_rejected())
    asn = _insert_candidate(w.db, root.id, kind="asn", value="AS64500", rir="ripe", rir_handle="FABRIKAM-A")
    w.cap_candidates += [claimed, rejected, asn]

    result = pc.run_automatic_sweep()

    assert (result.candidates, result.queued, result.skipped, result.errors) == (2, 2, 0, 0)
    for c in (a, b):
        assert [r.requested_by_id for r in _captures(c.id)] == [None] and _skips(c.id) == []
    for cid in (claimed, rejected, asn):  # they exist, and got nothing
        assert _rows_for(cid) == 0 and _skips(cid) == []
    assert len(_no_job_files(env)) == 2
    assert sleeps == [pc.SWEEP_PAUSE_S]  # between the two, none after the last


def test_prefilter_skips_a_domain_captured_inside_the_window_only(w, env, sleeps):
    fresh, stale, queued = _candidate(w), _candidate(w), _candidate(w)
    _row_for(w, fresh, "done", finished_ago_days=1)
    _row_for(w, stale, "done", finished_ago_days=pc.DEFAULT_REVISIT_DAYS + 10)
    _row_for(w, queued, "queued")

    result = pc.run_automatic_sweep()

    assert (result.candidates, result.queued, result.budget) == (1, 1, 0)  # only the stale one reached the loop
    assert _rows_for(stale.id) == 2  # the old done row and the new queued one
    assert _rows_for(fresh.id) == 1 and _skips(fresh.id) == []
    assert _rows_for(queued.id) == 1 and _skips(queued.id) == []


def test_lookup_failure_is_a_skip_with_no_capture_and_no_live_job(w, env, sleeps, monkeypatch):
    c = _candidate(w, _restricted(w))
    seen = mock_wayback(monkeypatch, status=429)

    result = pc.run_automatic_sweep()

    assert len(seen) == 1  # the lookup was reached
    assert _skips(c.id) == ["archive:lookup_unavailable"]
    assert _rows_for(c.id) == 0 and _no_job_files(env) == []
    assert (result.queued, result.skipped, result.stopped_on_lookup) == (0, 1, False)
    assert sleeps == []  # the only candidate was the last: no pointless wait after it
    assert pc.SWEEP_LOOKUP_BACKOFF_S == 60


def test_three_consecutive_lookup_failures_stop_the_sweep(w, env, sleeps, monkeypatch):
    cs = [_candidate(w, _restricted(w)) for _ in range(5)]
    seen = mock_wayback(monkeypatch, status=429)

    result = pc.run_automatic_sweep()

    assert len(seen) == 3
    reasons = sorted(r for c in cs for r in _skips(c.id))
    assert reasons == ["archive:lookup_unavailable"] * 3  # no "not attempted" rows for the other two
    assert all(_rows_for(c.id) == 0 for c in cs) and _no_job_files(env) == []
    assert (result.skipped, result.stopped_on_lookup, result.queued) == (3, True, 0)
    assert sleeps == [60, 60]  # no pause after the stopping failure


def test_a_non_lookup_outcome_resets_the_consecutive_counter(w, env, sleeps, monkeypatch):
    """fail, fail, success, fail, fail: never three in a row, so nothing is stopped."""
    cs = [_candidate(w, _restricted(w)) for _ in range(5)]
    order = {c.id: i for i, c in enumerate(sorted(cs, key=lambda c: str(c.id)))}
    calls = []

    def fake(db, *, candidate_id, user, manual):
        calls.append(candidate_id)
        if order[candidate_id] == 2:
            return None
        raise pc.CaptureRefused("archive:lookup_unavailable")

    monkeypatch.setattr(pc, "request_capture", fake)
    result = pc.run_automatic_sweep()
    assert len(calls) == 5 and not result.stopped_on_lookup and (result.queued, result.skipped) == (1, 4)


def test_a_non_lookup_refusal_resets_the_consecutive_counter(w, env, sleeps, monkeypatch):
    """fail, fail, gate refusal, fail, fail: never three lookup failures in a row, so nothing is stopped."""
    cs = sorted([_candidate(w) for _ in range(5)], key=lambda c: str(c.id))
    rules = {c.id: "archive:lookup_unavailable" for c in cs}
    rules[cs[2].id] = "candidate:no_relationship"
    calls = []

    def fake(db, *, candidate_id, user, manual):
        calls.append(candidate_id)
        raise pc.CaptureRefused(rules[candidate_id])

    monkeypatch.setattr(pc, "request_capture", fake)
    result = pc.run_automatic_sweep()
    assert len(calls) == 5 and (result.stopped_on_lookup, result.skipped) == (False, 5)
    assert sorted(r for c in cs for r in _skips(c.id)) == ["archive:lookup_unavailable"] * 4 + ["candidate:no_relationship"]


def test_a_gate_refusal_is_recorded_with_its_rule(w, env, sleeps, monkeypatch):
    import types

    c = _candidate(w)
    gate_calls = []

    def deny(db, *, candidate, root):  # a relationship-less root cannot be built (DB constraint): stub the verdict
        gate_calls.append(candidate.id)
        return types.SimpleNamespace(allowed=False, rule_fired="candidate:no_relationship")

    monkeypatch.setattr(pc, "authorise_candidate_browse", deny)

    result = pc.run_automatic_sweep()

    assert gate_calls == [c.id]  # the gate was reached for this candidate
    assert result.skipped == 1 and result.queued == 0
    assert _skips(c.id) == ["candidate:no_relationship"]
    assert _rows_for(c.id) == 0 and sleeps == []


def test_an_unexpected_error_does_not_stop_the_sweep(w, env, sleeps, monkeypatch):
    cs = sorted([_candidate(w), _candidate(w)], key=lambda c: str(c.id))
    real = pc.request_capture

    def flaky(db, *, candidate_id, user, manual):
        if candidate_id == cs[0].id:
            raise RuntimeError("boom")
        return real(db, candidate_id=candidate_id, user=user, manual=manual)

    monkeypatch.setattr(pc, "request_capture", flaky)
    result = pc.run_automatic_sweep()

    assert result.errors == 1 and result.queued == 1  # the failing one was reached, the next still ran
    assert _rows_for(cs[0].id) == 0 and _skips(cs[0].id) == []
    assert [r.status for r in _captures(cs[1].id)] == ["queued"]


def test_a_failing_skip_write_does_not_kill_the_sweep(w, env, sleeps, monkeypatch):
    cs = sorted([_candidate(w), _candidate(w)], key=lambda c: str(c.id))
    real = pc.request_capture
    attempted = []

    def refuse_first(db, *, candidate_id, user, manual):
        attempted.append(candidate_id)
        if candidate_id == cs[0].id:
            raise pc.CaptureRefused("candidate:no_relationship")
        return real(db, candidate_id=candidate_id, user=user, manual=manual)

    def broken_skip(db, candidate_id, rule):
        raise RuntimeError("disk full")

    monkeypatch.setattr(pc, "request_capture", refuse_first)
    monkeypatch.setattr(pc, "_record_skip", broken_skip)
    result = pc.run_automatic_sweep()

    assert attempted == [c.id for c in cs]  # the refusal was reached, and the next was still tried
    assert (result.errors, result.queued, result.skipped) == (1, 1, 0)
    assert [r.status for r in _captures(cs[1].id)] == ["queued"] and _skips(cs[0].id) == []


# ── rolling hourly behaviour (planning#277 S6b step c) ───────────────────────


class Recorder:
    """request_capture stand-in: records the candidate ids asked for; optional per-call rule."""

    def __init__(self, monkeypatch, rules=None):
        self.calls: list = []
        self.rules = rules or {}
        monkeypatch.setattr(pc, "request_capture", self._fake)

    def _fake(self, db, *, candidate_id, user, manual):
        self.calls.append(candidate_id)
        rule = self.rules.get(candidate_id)
        if rule:
            raise pc.CaptureRefused(rule)
        return None


def test_not_configured_does_nothing_and_writes_no_rows(w, env, sleeps, monkeypatch, caplog):
    c = _candidate(w)
    rec = Recorder(monkeypatch)
    monkeypatch.delenv("CAPTURE_PROXY_KEY")
    with caplog.at_level("INFO", logger=pc.log.name):
        result = pc.run_automatic_sweep()
    assert rec.calls == [] and result.not_configured is True and result.queued == 0
    assert _skips(c.id) == [] and _rows_for(c.id) == 0
    assert [r.getMessage() for r in caplog.records if "not set up" in r.getMessage()] == [
        "page_capture: automatic capture is not set up (no capture proxy key); nothing to do"
    ]
    monkeypatch.setenv("CAPTURE_PROXY_KEY", "k" * 32)  # same fixture, configured: it IS requested
    result = pc.run_automatic_sweep()
    assert c.id in rec.calls and result.not_configured is False


def test_retry_windows_after_a_recorded_refusal(w, env, sleeps, monkeypatch):
    lookup_recent, lookup_old, other_recent, other_old = (_candidate(w) for _ in range(4))
    _add_skip(w, lookup_recent, "archive:lookup_unavailable", 2 * 60)
    _add_skip(w, lookup_old, "archive:lookup_unavailable", 25 * 60)
    _add_skip(w, other_recent, "candidate:no_relationship", 6 * 24 * 60)
    _add_skip(w, other_old, "candidate:no_relationship", 8 * 24 * 60)
    rec = Recorder(monkeypatch)
    result = pc.run_automatic_sweep()
    assert set(rec.calls) == {lookup_old.id, other_old.id}
    assert result.candidates == 2 and result.queued == 2


def test_a_persistent_non_lookup_refusal_writes_one_skip_row_over_two_runs(w, env, sleeps, monkeypatch):
    c, other = _candidate(w), _candidate(w)
    rec = Recorder(monkeypatch, {c.id: "candidate:no_relationship"})
    pc.run_automatic_sweep()
    assert c.id in rec.calls and other.id in rec.calls  # first run reached both
    first = len(rec.calls)
    pc.run_automatic_sweep()
    assert rec.calls[first:] == [other.id]  # c is no longer selected; the other still is (ran again: fake queues nothing)
    assert _skips(c.id) == ["candidate:no_relationship"]


def test_lookup_stop_leaves_the_untried_due_with_no_rows(w, env, sleeps, monkeypatch):
    cs = sorted([_candidate(w) for _ in range(4)], key=lambda c: str(c.id))
    for c in cs:  # equal never-captured ordering falls back to id
        pass
    rec = Recorder(monkeypatch, {c.id: "archive:lookup_unavailable" for c in cs[:3]})
    result = pc.run_automatic_sweep()
    assert rec.calls == [c.id for c in cs[:3]] and result.stopped_on_lookup is True
    assert _skips(cs[3].id) == []
    rec.calls.clear()
    pc.run_automatic_sweep()  # the three are inside their 1-day window; the fourth is due
    assert rec.calls == [cs[3].id]


def test_time_limit_stops_the_run_and_the_rest_stay_due(w, env, sleeps, monkeypatch):
    cs = sorted([_candidate(w) for _ in range(3)], key=lambda c: str(c.id))
    rec = Recorder(monkeypatch)
    ticks = {"n": 0}

    def fake_clock():
        ticks["n"] += 1
        return 0 if ticks["n"] <= 3 else pc.SWEEP_TIME_LIMIT_S + 1  # start, before 1st, before 2nd

    monkeypatch.setattr(pc, "_monotonic", fake_clock)
    result = pc.run_automatic_sweep()
    assert rec.calls == [c.id for c in cs[:2]] and result.out_of_time is True


def test_never_captured_goes_before_an_old_capture(w, env, sleeps, monkeypatch):
    # The never-captured one gets the LARGER id, so an id-only order would put it last.
    old, never = sorted((_candidate(w), _candidate(w)), key=lambda c: str(c.id))
    _row_for(w, old, "done", finished_ago_days=pc.DEFAULT_REVISIT_DAYS + 10)
    rec = Recorder(monkeypatch)
    pc.run_automatic_sweep()
    assert rec.calls == [never.id, old.id]


def test_an_abandoned_deal_is_not_captured_while_our_own_root_is(w, env, sleeps, monkeypatch):
    ours = _candidate(w)
    dead_root, eng = w.deal()
    eng.posture = "abandoned"
    w.db.commit()
    dead = _candidate(w, dead_root)
    live_root, _eng = w.deal()
    live = _candidate(w, live_root)
    rec = Recorder(monkeypatch)
    pc.run_automatic_sweep()
    assert ours.id in rec.calls and live.id in rec.calls and dead.id not in rec.calls


# ── API ──────────────────────────────────────────────────────────────────────


def _skips_get(candidate_id, headers, **params):
    return client.get(f"/api/organizations/candidates/{candidate_id}/capture-skips", headers=headers, params=params)


def _add_skip(w, c, reason, ago_minutes):
    w.db.add(PageCaptureSkip(
        candidate_id=c.id, domain=c.value, reason=reason,
        skipped_at=datetime.now(timezone.utc) - timedelta(minutes=ago_minutes),
    ))
    w.db.commit()


def test_api_lists_skips_newest_first_with_plain_messages(w, env):
    c = _candidate(w)
    _add_skip(w, c, "archive:lookup_unavailable", 30)
    _add_skip(w, c, "capture:revisit_budget", 20)
    _add_skip(w, c, "some:future_rule", 10)

    r = _skips_get(c.id, w.headers(role=UserRole.VIEWER.value))

    assert r.status_code == 200, r.text
    body = r.json()
    assert [b["reason"] for b in body] == ["some:future_rule", "capture:revisit_budget", "archive:lookup_unavailable"]
    assert body[0]["message"] == "A live visit to this candidate is not allowed."
    assert body[1]["message"] == "This domain was captured recently; it can be re-captured manually."
    assert body[2]["message"] == (
        "The snapshot service could not be reached, so nothing was captured. "
        "It will be tried again automatically within a day."
    )
    assert all(b["message"] != b["reason"] for b in body)
    assert len(_skips_get(c.id, w.headers(), limit=2).json()) == 2
    assert _skips_get(c.id, w.headers(), limit=51).status_code == 422


def test_api_invisible_candidate_gets_the_same_status_as_the_captures_get(w, env, monkeypatch):
    c = _candidate(w)
    _add_skip(w, c, "capture:revisit_budget", 1)
    h = w.headers()
    monkeypatch.setattr(read_scope, "domain_clause", lambda user, sc: sc.id != c.id)
    captures = client.get(f"/api/organizations/candidates/{c.id}/captures", headers=h)
    assert captures.status_code == 404
    assert _skips_get(c.id, h).status_code == captures.status_code
    assert _skips_get(c.id, {}).status_code == client.get(f"/api/organizations/candidates/{c.id}/captures").status_code


def test_api_manual_post_lookup_failure_uses_the_new_wording(w, env, monkeypatch):
    mock_wayback(monkeypatch, status=429)
    root, _eng = w.deal()
    c = _candidate(w, root)
    r = client.post(f"/api/organizations/candidates/{c.id}/captures", headers=w.headers())
    assert r.status_code == 503
    assert r.json()["detail"]["message"].endswith("It will be tried again automatically within a day.")


def test_migration_0096_is_the_chain_head_after_0095():
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "alembic" / "versions" / "0096_page_capture_skips.py").read_text()
    assert re.search(r'^down_revision = "0095"$', src, re.M) and re.search(r'^revision = "0096"$', src, re.M)
