"""Background runs of the verifiers (planning#277 S1b).

Each entry point takes ids only, opens its OWN session and closes it in
`finally`, so it is safe as a `BackgroundTasks` target (the request's session
is closed by then) and must never be called inside a request transaction.

## Transaction ownership

This module owns its session. `domain_facts.collect` commits (the WHOIS
cache), so facts are collected BEFORE a pair's unit of work begins, never in
the middle of one. Each pair is its own unit of work: `verify_pair` then
`commit`; a failure rolls back, is counted, and the next pair still runs. The
candidate and anchor rows are re-loaded by id for every pair, since a status
may have changed between pairs.

`rir_for_claimed` runs two registries, ARIN then RIPE, each its own
independent session-owned pair of steps (a failure in one never stops the
other). In each, the collector flushes the RIR cache rows, which are COMMITTED
before any signal is written (a failed signal write must not lose a fetch that
already cost a rate-limited request); then `record_arin` / `record_ripe`
writes the signals, and this module commits. Neither is a single unit of work:
`entity_graph.store_evidence` commits once per record (as in
`record_reverse_ip`), so a failure rolls back only the record in progress; the
earlier ones stay, each complete. The claimed candidate is re-loaded between
the two steps, since the commit expired it and its status may have changed.

## Manual Re-check (`recheck_root`, planning#278 S3c2)

Re-asks ARIN and RIPE for the whole root: one run-level `fresh_since` (taken at
the start) is passed to every domain's RIR steps, so cache rows older than the
run are refetched and a key repeated inside the run is fetched once. The RIR
steps run per claimed domain; then every CLAIMED CIDR candidate is re-checked
prefix-first (planning#278 S3c3b2): the registry its own `rir` names is asked
what holds that space now, and each reassigned-away part is recorded
(`reassignment_for_root`). A RIPE candidate held by a contact (or whose holder
kind is not on record) is skipped without a request, an incomplete answer
writes nothing, and the record never un-claims or touches the Target. Then the
dedicated-IP sweep runs once. An in-process slot (`try_begin_recheck`) keeps one
Re-check per root at a time. The claim follow-up (`verify_after_claim`) does not
run the reassignment sweep.

## Facts cache

One `dict[str, DomainFacts]` per run: a domain is looked up once however many
pairs it appears in.

Logs carry counts only; a domain is data about an organization and stays out
of INFO.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.evidence import EvidenceBlob, EvidenceFetch
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.services import entity_graph
from app.services.org_discovery import (
    arin, covering, domain_facts, generators, reassignment, ripe, rir_fetch, verifiers,
)
from app.services.org_discovery.generators import ReverseIpResult, RirDedicatedIpResult
from app.services.org_discovery.domain_facts import DomainFacts

log = logging.getLogger(__name__)


@dataclass
class VerifyReport:
    pairs_checked: int = 0
    signals_recorded: int = 0
    signals_resighted: int = 0
    pairs_failed: int = 0
    candidates_skipped: int = 0  # not open (or gone) when the run reached it


def _collect(db: Session, domain: str) -> DomainFacts:
    """The one place the runner reaches the network (tests replace it)."""
    return domain_facts.collect(db, domain)


def _rir_collect(db: Session, domain: str, fresh_since: datetime | None = None) -> arin.ArinCollection:
    """The one place the RIR generator reaches the network (tests replace it)."""
    return arin.collect(db, domain, rir_fetch.Budget(fresh_since=fresh_since))


def _ripe_collect(db: Session, domain: str, fresh_since: datetime | None = None) -> ripe.RipeCollection:
    """The one place the RIPE generator reaches the network (tests replace it).
    Its own Budget: a separate registry with a separate rate limit."""
    return ripe.collect(db, domain, rir_fetch.Budget(fresh_since=fresh_since))


def _facts(db: Session, cache: dict[str, DomainFacts], domain: str) -> DomainFacts:
    found = cache.get(domain)
    if found is None:
        found = cache[domain] = _collect(db, domain)
    return found


def _run_pair(
    db: Session, cache: dict[str, DomainFacts], report: VerifyReport,
    *, candidate_id: uuid.UUID, anchor_id: uuid.UUID,
) -> None:
    """One (open candidate, claimed anchor) pair as its own unit of work."""
    try:
        # Facts first: `collect` commits, so it must not run over pending writes.
        candidate = db.get(ScopeCandidate, candidate_id)
        anchor = db.get(ScopeCandidate, anchor_id)
        if (
            candidate is None or anchor is None or candidate.status != "open" or anchor.status != "claimed"
            or candidate.kind != "domain" or anchor.kind != "domain"
        ):
            report.candidates_skipped += 1
            return
        cf = _facts(db, cache, candidate.value)
        af = _facts(db, cache, anchor.value)
        # `collect` committed and expired the rows: re-load before the write.
        candidate = db.get(ScopeCandidate, candidate_id)
        anchor = db.get(ScopeCandidate, anchor_id)
        report.pairs_checked += 1
        outcomes = verifiers.verify_pair(
            db, candidate=candidate, anchor=anchor, candidate_facts=cf, anchor_facts=af, observer_id=None,
        )
        db.commit()
        for o in outcomes:
            if o.created_signal:
                report.signals_recorded += 1
            else:
                report.signals_resighted += 1
    except Exception:
        db.rollback()
        report.pairs_failed += 1
        log.exception("org-discovery verifier pair failed candidate=%s anchor=%s", candidate_id, anchor_id)


def _summary(run: str, report: VerifyReport) -> None:
    log.info(
        "org-discovery %s pairs_checked=%d signals_recorded=%d signals_resighted=%d pairs_failed=%d "
        "candidates_skipped=%d",
        run, report.pairs_checked, report.signals_recorded, report.signals_resighted, report.pairs_failed,
        report.candidates_skipped,
    )


def _claimed_ids(
    db: Session, root_entity_id: uuid.UUID, *, excluding: uuid.UUID | None = None,
) -> list[uuid.UUID]:
    stmt = select(ScopeCandidate.id).where(
        ScopeCandidate.root_entity_id == root_entity_id,
        ScopeCandidate.kind == "domain",
        ScopeCandidate.status == "claimed",
    )
    if excluding is not None:
        stmt = stmt.where(ScopeCandidate.id != excluding)
    return list(db.execute(stmt.order_by(ScopeCandidate.id)).scalars())


def verify_new_candidates(candidate_ids: list[uuid.UUID]) -> VerifyReport:
    """Each still-open candidate in `candidate_ids` against every claimed
    candidate in its root."""
    report = VerifyReport()
    cache: dict[str, DomainFacts] = {}
    db = SessionLocal()
    try:
        for candidate_id in candidate_ids:
            candidate = db.get(ScopeCandidate, candidate_id)
            if candidate is None or candidate.status != "open" or candidate.kind != "domain":
                report.candidates_skipped += 1
                continue
            root_id = candidate.root_entity_id
            anchors = _claimed_ids(db, root_id, excluding=candidate_id)
            db.rollback()  # end the read transaction before `collect` commits
            for anchor_id in anchors:
                _run_pair(db, cache, report, candidate_id=candidate_id, anchor_id=anchor_id)
    finally:
        db.close()
    _summary("verify_new_candidates", report)
    return report


def verify_after_claim(claimed_candidate_id: uuid.UUID) -> VerifyReport:
    """Every open candidate in the claimed candidate's root against it.
    Anything not open is never selected, so it is not counted as skipped; a
    candidate that stops being open mid-run is."""
    report = VerifyReport()
    cache: dict[str, DomainFacts] = {}
    root_id: uuid.UUID | None = None
    db = SessionLocal()
    try:
        anchor = db.get(ScopeCandidate, claimed_candidate_id)
        if anchor is None or anchor.status != "claimed" or anchor.kind != "domain":
            report.candidates_skipped += 1
        else:
            root_id = anchor.root_entity_id  # captured while the session is open
            open_ids = list(db.execute(
                select(ScopeCandidate.id).where(
                    ScopeCandidate.root_entity_id == anchor.root_entity_id,
                    ScopeCandidate.kind == "domain",
                    ScopeCandidate.status == "open",
                ).order_by(ScopeCandidate.id)
            ).scalars())
            db.rollback()
            for candidate_id in open_ids:
                _run_pair(db, cache, report, candidate_id=candidate_id, anchor_id=claimed_candidate_id)
    finally:
        db.close()
    _summary("verify_after_claim", report)
    # Reverse IP for the newly claimed domain (part C): after this session is
    # closed, since it opens its own; it must never fail the claim's follow-up.
    try:
        reverse_ip_for_claimed(claimed_candidate_id)
    except Exception:
        log.exception("org-discovery reverse-IP after claim failed candidate=%s", claimed_candidate_id)
    # RIR (ARIN) resources for the claimed domain's contacts: likewise its own
    # session, likewise unable to fail the follow-up.
    try:
        rir_for_claimed(claimed_candidate_id)
    except Exception:
        log.exception("org-discovery RIR after claim failed candidate=%s", claimed_candidate_id)
    # Last: the dedicated-IP sweep of the root's open CIDR candidates, which
    # may have just been created by the RIR step. Its own session, likewise
    # unable to fail the follow-up.
    if root_id is not None:
        try:
            dedicated_ip_for_root(root_id)
        except Exception:
            log.exception("org-discovery dedicated-IP after claim failed candidate=%s", claimed_candidate_id)
    return report


def dedicated_ip_for_root(root_entity_id: uuid.UUID) -> RirDedicatedIpResult:
    """The dedicated-IP generator for one root, as one unit of work in its own
    session. `record_rir_dedicated_ip` stores evidence, which commits inside
    it, so this is a session owner. A failure rolls back and yields the empty
    result."""
    result = RirDedicatedIpResult()
    db = SessionLocal()
    try:
        try:
            result = generators.record_rir_dedicated_ip(db, root_entity_id=root_entity_id, observer_id=None)
            db.commit()
        except Exception:
            db.rollback()
            result = RirDedicatedIpResult()
            log.exception("org-discovery dedicated-IP failed root=%s", root_entity_id)
    finally:
        db.close()
    log.info(
        "org-discovery dedicated_ip_for_root claimed_domains=%d ips_checked=%d no_claim=%d not_dedicated=%d "
        "outside_candidates=%d signals_recorded=%d signals_resighted=%d invalid=%d conflict=%d",
        result.claimed_domains, result.ips_checked, result.no_claim, result.not_dedicated,
        result.outside_candidates, result.signals_recorded, result.signals_resighted, result.invalid,
        result.conflict,
    )
    return result


def reverse_ip_for_claimed(claimed_candidate_id: uuid.UUID) -> ReverseIpResult:
    """Reverse-IP generator for one claimed candidate, as one unit of work in
    its own session. `record_reverse_ip` calls the pDNS lookup, which commits
    inside it, so this is a session owner. Any lead it creates is then
    verified against the root's claimed domains."""
    result = ReverseIpResult()
    db = SessionLocal()
    try:
        try:
            claimed = db.get(ScopeCandidate, claimed_candidate_id)
            if claimed is not None and claimed.status == "claimed" and claimed.kind == "domain":
                result = generators.record_reverse_ip(db, claimed=claimed, observer_id=None)
            db.commit()
        except Exception:
            db.rollback()
            result = ReverseIpResult()
            log.exception("org-discovery reverse-IP failed candidate=%s", claimed_candidate_id)
    finally:
        db.close()
    if result.created_candidate_ids:
        verify_new_candidates(result.created_candidate_ids)
    log.info(
        "org-discovery reverse_ip_for_claimed ips_checked=%d not_dedicated=%d no_claim=%d "
        "signals_recorded=%d signals_resighted=%d skipped_inactive_or_previous_tenant=%d "
        "no_claimed_history=%d invalid=%d candidates_created=%d",
        result.ips_checked, result.not_dedicated, result.no_claim, result.signals_recorded,
        result.signals_resighted, result.skipped_inactive_or_previous_tenant, result.no_claimed_history,
        result.invalid,
        len(result.created_candidate_ids),
    )
    return result


@dataclass
class RirRunResult:
    arin: arin.ArinRecordResult = field(default_factory=arin.ArinRecordResult)
    ripe: ripe.RipeRecordResult = field(default_factory=ripe.RipeRecordResult)


def _rir_step(registry: str, claimed_candidate_id: uuid.UUID, collect: Callable, record: Callable, empty: Callable):
    """One registry as its own session-owned unit: collect (cache committed),
    re-load and re-check the claimed candidate, record, commit. Any failure
    rolls back and yields the empty result."""
    result = empty()
    db = SessionLocal()
    try:
        try:
            claimed = db.get(ScopeCandidate, claimed_candidate_id)
            if claimed is None or claimed.status != "claimed" or claimed.kind != "domain":
                return result
            domain = claimed.value
            db.rollback()  # end the read before the fetch commits
            collection = collect(db, domain)
            db.commit()  # the cache rows, kept even if the signal step fails
            claimed = db.get(ScopeCandidate, claimed_candidate_id)
            if claimed is None or claimed.status != "claimed":
                return result
            result = record(db, claimed=claimed, collection=collection, observer_id=None)
            db.commit()
        except Exception:
            db.rollback()
            result = empty()
            log.exception("org-discovery RIR failed registry=%s candidate=%s", registry, claimed_candidate_id)
            return result
    finally:
        db.close()
    return result


def rir_for_claimed(claimed_candidate_id: uuid.UUID, *, fresh_since: datetime | None = None) -> RirRunResult:
    """ARIN, then RIPE, generators for one claimed domain, each in its own
    session (see the module docstring). The fetch (which commits its cache
    rows) runs before any signal write; the signals are then one unit of work.
    `fresh_since` (a manual Re-check's run start) makes the collectors refetch
    cache rows older than it; None (the claim follow-up) uses the cache as is.
    Created ASN/CIDR candidates are NOT run through the domain verifiers (they
    are not domains). The collectors are looked up at call time so tests can
    replace the seams."""
    a = _rir_step(
        "arin", claimed_candidate_id, lambda db, d: _rir_collect(db, d, fresh_since=fresh_since), arin.record_arin, arin.ArinRecordResult,
    )
    log.info(
        "org-discovery rir_for_claimed pocs_listed=%d pocs_truncated=%s pocs_not_exact=%d fetch_failed=%d "
        "budget_exhausted=%s invalid_handles=%d nets_failed=%d signals_recorded=%d signals_resighted=%d "
        "candidates_created=%d orgs_holding_nothing=%d invalid=%d holder_conflict=%d context_recorded=%d "
        "context_no_candidate=%d",
        a.pocs_listed, a.pocs_truncated, a.pocs_not_exact, a.fetch_failed,
        a.budget_exhausted, a.invalid_handles, sum(a.nets_failed.values()),
        a.signals_recorded, a.signals_resighted, len(a.created_candidate_ids),
        a.orgs_holding_nothing, a.invalid, a.holder_conflict, a.context_recorded,
        a.context_no_candidate,
    )
    r = _rir_step(
        "ripe", claimed_candidate_id, lambda db, d: _ripe_collect(db, d, fresh_since=fresh_since), lambda db, **kw: ripe.record_ripe(db, **kw),
        ripe.RipeRecordResult,
    )
    log.info(
        "org-discovery rir_for_claimed_ripe docs_found=%d fulltext_truncated=%s contacts_not_exact=%d "
        "fetch_failed=%d budget_exhausted=%s invalid_handles=%d skipped_status=%d skipped_source=%d "
        "resources_failed=%d signals_recorded=%d signals_resighted=%d candidates_created=%d "
        "holders_holding_nothing=%d invalid=%d holder_conflict=%d context_recorded=%d context_no_candidate=%d",
        r.docs_found, r.fulltext_truncated, r.contacts_not_exact, r.fetch_failed, r.budget_exhausted,
        r.invalid_handles, r.skipped_status, r.skipped_source, sum(r.resources_failed.values()),
        r.signals_recorded, r.signals_resighted, len(r.created_candidate_ids), r.holders_holding_nothing,
        r.invalid, r.holder_conflict, r.context_recorded, r.context_no_candidate,
    )
    return RirRunResult(arin=a, ripe=r)


# In-process Re-check slot: one manual Re-check per root at a time. A guard, not
# a setting. A slot whose background task never ran (process died, task dropped)
# is reclaimable after RECHECK_STALE_AFTER_S.
_recheck_lock = threading.Lock()
_recheck_running: dict[uuid.UUID, float] = {}
RECHECK_STALE_AFTER_S = 2 * 60 * 60


def try_begin_recheck(root_entity_id: uuid.UUID) -> bool:
    """Take the root's Re-check slot; False if a younger one is held."""
    with _recheck_lock:
        started = _recheck_running.get(root_entity_id)
        if started is not None and time.monotonic() - started < RECHECK_STALE_AFTER_S:
            return False
        _recheck_running[root_entity_id] = time.monotonic()
        return True


def end_recheck(root_entity_id: uuid.UUID) -> None:
    with _recheck_lock:
        _recheck_running.pop(root_entity_id, None)


@dataclass
class ReassignmentSweepResult:
    candidates: int = 0  # claimed cidr candidates considered
    clean: int = 0  # complete answer, nothing reassigned
    reassigned: int = 0  # candidates with at least one part
    parts_created: int = 0
    parts_seen: int = 0
    failed: int = 0  # an exception in that candidate's unit of work
    indeterminate: dict[str, int] = field(default_factory=dict)  # by reason


def _indeterminate(result: ReassignmentSweepResult, reason: str) -> None:
    result.indeterminate[reason] = result.indeterminate.get(reason, 0) + 1


def _ripe_holder_kind(db: Session, candidate: ScopeCandidate) -> str | None:
    """The holder kind of a RIPE claim, read from the candidate's OWN signal
    evidence (never inferred from the handle's shape): "org" only when every
    matching body says org, "contact" when any does, None when unknown."""
    rows = db.execute(
        select(EvidenceBlob.content)
        .join(EvidenceFetch, EvidenceFetch.sha256 == EvidenceBlob.sha256)
        .join(ScopeSignal, ScopeSignal.evidence_id == EvidenceFetch.id)
        .where(
            ScopeSignal.candidate_id == candidate.id,
            ScopeSignal.signal_type == "rir_contact_email_unvalidated",
            ScopeSignal.evidence_id.is_not(None),
        )
    ).scalars().all()
    kinds: set = set()
    for content in rows:
        try:
            body = json.loads(bytes(content))
        except ValueError:
            continue
        if isinstance(body, dict) and body.get("rir") == "ripe" and body.get("holder") == candidate.rir_handle:
            kind = body.get("holder_kind")
            kinds.add(kind if isinstance(kind, str) else None)
    if "contact" in kinds:
        return "contact"
    if kinds == {"org"}:
        return "org"
    return None


def _reassignment_evidence_url(rir: str, prefix: str, handle: str) -> str:
    segs = ("rir_reassigned_away", rir, prefix, handle)
    return "https://org-discovery.invalid/recheck/" + "/".join(
        x.replace("/", "_").replace(" ", "") for x in segs
    )


def _reassignment_unit(
    db: Session, candidate_id: uuid.UUID, root_entity_id: uuid.UUID, fresh_since: datetime,
    result: ReassignmentSweepResult,
) -> None:
    candidate = db.get(ScopeCandidate, candidate_id)
    if (
        candidate is None or candidate.root_entity_id != root_entity_id
        or candidate.kind != "cidr" or candidate.status != "claimed"
    ):
        return
    rir = candidate.rir
    if rir == "arin":
        fetch = covering.fetch_arin
    elif rir == "ripe":
        fetch = covering.fetch_ripe
    else:
        _indeterminate(result, "unsupported_rir")
        return
    if rir == "ripe":
        kind = _ripe_holder_kind(db, candidate)
        if kind == "contact":
            _indeterminate(result, "contact_held")
            return
        if kind != "org":
            _indeterminate(result, "holder_unknown")
            return
    prefix, handle = candidate.value, candidate.rir_handle
    db.rollback()  # end the read transaction before the registry fetch commits its cache rows
    budget = rir_fetch.Budget(fresh_since=fresh_since)
    cov = fetch(db, prefix, budget)
    if cov.reason is not None:
        _indeterminate(result, cov.reason)
        return
    found = reassignment.detect(prefix, handle, cov.answer)
    if found is None:
        _indeterminate(result, "detect_indeterminate")
        return
    if not found:
        result.clean += 1
        return
    body = {
        "rule": "rir_reassigned_away", "rir": rir, "candidate_id": str(candidate_id), "prefix": prefix,
        "holder_handle": handle,
        "reassigned": [
            {"prefix": f.prefix, "new_holder_kind": f.new_holder_kind, "new_holder_handle": f.new_holder_handle}
            for f in found
        ],
        "sources": [{"label": label, "body": b} for label, b in cov.sources],
    }
    now = datetime.now(timezone.utc)
    # `store_evidence` COMMITS, so it is not inside any savepoint.
    evidence = entity_graph.store_evidence(
        db, content=json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        content_type="application/json",
        source_url=_reassignment_evidence_url(rir, prefix, handle or ""),
        fetched_at=now, origin="fetched",
    )
    created = seen = 0
    for part in found:
        outcome = reassignment.record_reassignment(
            db, candidate_id=candidate_id, found=part, evidence_id=evidence.id, now=now,
        )
        if outcome == "created":
            created += 1
        else:
            seen += 1
    db.commit()
    result.reassigned += 1
    result.parts_created += created
    result.parts_seen += seen


def reassignment_for_root(root_entity_id: uuid.UUID, *, fresh_since: datetime) -> ReassignmentSweepResult:
    """Every claimed CIDR candidate of the root, prefix-first against its own
    registry (see the module docstring). Each candidate is its own unit of work
    in its own session (`store_evidence` commits); a failure rolls back, is
    counted, and the next candidate still runs. Counts only in logs."""
    result = ReassignmentSweepResult()
    db = SessionLocal()
    try:
        ids = list(db.execute(
            select(ScopeCandidate.id).where(
                ScopeCandidate.root_entity_id == root_entity_id,
                ScopeCandidate.kind == "cidr",
                ScopeCandidate.status == "claimed",
            ).order_by(ScopeCandidate.id)
        ).scalars())
    finally:
        db.close()
    for cid in ids:
        result.candidates += 1
        db = SessionLocal()
        try:
            try:
                _reassignment_unit(db, cid, root_entity_id, fresh_since, result)
                db.commit()
            except Exception:
                db.rollback()
                result.failed += 1
                log.exception("org-discovery reassignment failed candidate=%s", cid)
        finally:
            db.close()
    log.info(
        "org-discovery reassignment_for_root candidates=%d clean=%d reassigned=%d parts_created=%d "
        "parts_seen=%d failed=%d indeterminate=%d",
        result.candidates, result.clean, result.reassigned, result.parts_created, result.parts_seen,
        result.failed, sum(result.indeterminate.values()),
    )
    return result


@dataclass
class RecheckResult:
    claimed_domains: int = 0
    domains_failed: int = 0
    runs: list[RirRunResult] = field(default_factory=list)
    reassignment: ReassignmentSweepResult = field(default_factory=ReassignmentSweepResult)
    dedicated: RirDedicatedIpResult = field(default_factory=RirDedicatedIpResult)


def recheck_root(root_entity_id: uuid.UUID) -> RecheckResult:
    """Manual Re-check of one root: every claimed domain's ARIN and RIPE steps
    with a run-level `fresh_since`, then the dedicated-IP sweep once. The CALLER
    holds the slot (`try_begin_recheck`); this function releases it in `finally`.
    Opens its own sessions (see the module docstring); never call it inside a
    request transaction."""
    result = RecheckResult()
    try:
        fresh_since = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            ids = _claimed_ids(db, root_entity_id)
        finally:
            db.close()
        result.claimed_domains = len(ids)
        for cid in ids:
            try:
                result.runs.append(rir_for_claimed(cid, fresh_since=fresh_since))
            except Exception:
                result.domains_failed += 1
                log.exception("org-discovery re-check RIR failed candidate=%s", cid)
        try:
            result.reassignment = reassignment_for_root(root_entity_id, fresh_since=fresh_since)
        except Exception:
            log.exception("org-discovery re-check reassignment sweep failed root=%s", root_entity_id)
        try:
            result.dedicated = dedicated_ip_for_root(root_entity_id)
        except Exception:
            log.exception("org-discovery re-check dedicated-IP failed root=%s", root_entity_id)
    finally:
        end_recheck(root_entity_id)
    log.info(
        "org-discovery recheck_root claimed_domains=%d domains_failed=%d rir_signals_recorded=%d "
        "candidates_created=%d reassigned=%d parts_created=%d dedicated_signals_recorded=%d",
        result.claimed_domains, result.domains_failed,
        sum(r.arin.signals_recorded + r.ripe.signals_recorded for r in result.runs),
        sum(len(r.arin.created_candidate_ids) + len(r.ripe.created_candidate_ids) for r in result.runs),
        result.reassignment.reassigned, result.reassignment.parts_created,
        result.dedicated.signals_recorded,
    )
    return result
