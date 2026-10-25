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

## Facts cache

One `dict[str, DomainFacts]` per run: a domain is looked up once however many
pairs it appears in.

Logs carry counts only; a domain is data about an organization and stays out
of INFO.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.scope_candidate import ScopeCandidate
from app.services.org_discovery import arin, domain_facts, generators, ripe, rir_fetch, verifiers
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


def _rir_collect(db: Session, domain: str) -> arin.ArinCollection:
    """The one place the RIR generator reaches the network (tests replace it)."""
    return arin.collect(db, domain, rir_fetch.Budget())


def _ripe_collect(db: Session, domain: str) -> ripe.RipeCollection:
    """The one place the RIPE generator reaches the network (tests replace it).
    Its own Budget: a separate registry with a separate rate limit."""
    return ripe.collect(db, domain, rir_fetch.Budget())


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


def _claimed_ids(db: Session, root_entity_id: uuid.UUID, *, excluding: uuid.UUID) -> list[uuid.UUID]:
    return list(db.execute(
        select(ScopeCandidate.id).where(
            ScopeCandidate.root_entity_id == root_entity_id,
            ScopeCandidate.kind == "domain",
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
    db = SessionLocal()
    try:
        anchor = db.get(ScopeCandidate, claimed_candidate_id)
        if anchor is None or anchor.status != "claimed" or anchor.kind != "domain":
            report.candidates_skipped += 1
        else:
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


def rir_for_claimed(claimed_candidate_id: uuid.UUID) -> RirRunResult:
    """ARIN, then RIPE, generators for one claimed domain, each in its own
    session (see the module docstring). The fetch (which commits its cache
    rows) runs before any signal write; the signals are then one unit of work.
    Created ASN/CIDR candidates are NOT run through the domain verifiers (they
    are not domains). The collectors are looked up at call time so tests can
    replace the seams."""
    a = _rir_step(
        "arin", claimed_candidate_id, lambda db, d: _rir_collect(db, d), arin.record_arin, arin.ArinRecordResult,
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
        "ripe", claimed_candidate_id, lambda db, d: _ripe_collect(db, d), lambda db, **kw: ripe.record_ripe(db, **kw),
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
