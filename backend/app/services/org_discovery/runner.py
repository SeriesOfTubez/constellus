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

## Facts cache

One `dict[str, DomainFacts]` per run: a domain is looked up once however many
pairs it appears in.

Logs carry counts only; a domain is data about an organization and stays out
of INFO.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.scope_candidate import ScopeCandidate
from app.services.org_discovery import domain_facts, generators, verifiers
from app.services.org_discovery.generators import ReverseIpResult
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
        if candidate is None or anchor is None or candidate.status != "open" or anchor.status != "claimed":
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


def _claimed_ids(db: Session, root_entity_id: uuid.UUID, *, excluding: uuid.UUID) -> list[uuid.UUID]:
    return list(db.execute(
        select(ScopeCandidate.id).where(
            ScopeCandidate.root_entity_id == root_entity_id,
            ScopeCandidate.status == "claimed",
            ScopeCandidate.id != excluding,
        ).order_by(ScopeCandidate.id)
    ).scalars())


def verify_new_candidates(candidate_ids: list[uuid.UUID]) -> VerifyReport:
    """Each still-open candidate in `candidate_ids` against every claimed
    candidate in its root."""
    report = VerifyReport()
    cache: dict[str, DomainFacts] = {}
    db = SessionLocal()
    try:
        for candidate_id in candidate_ids:
            candidate = db.get(ScopeCandidate, candidate_id)
            if candidate is None or candidate.status != "open":
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
    db = SessionLocal()
    try:
        anchor = db.get(ScopeCandidate, claimed_candidate_id)
        if anchor is None or anchor.status != "claimed":
            report.candidates_skipped += 1
        else:
            open_ids = list(db.execute(
                select(ScopeCandidate.id).where(
                    ScopeCandidate.root_entity_id == anchor.root_entity_id,
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
    return report


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
            if claimed is not None and claimed.status == "claimed":
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
