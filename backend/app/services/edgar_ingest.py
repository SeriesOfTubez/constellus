"""app.services.edgar_ingest — SEC EDGAR submissions ingest (planning#213,
L4 slice 1).

Given a CIK, pulls `data.sec.gov`'s submissions JSON (plus any paged
`filings.files[]` continuation) and writes two kinds of rows, EACH through
the one function that is allowed to write it:

  - `formerNames` entries become `formerly_named` `EntityRelation` rows,
    written ONLY through `entity_graph.assert_relation` — never a raw
    insert, so the "auto-confirm requires a granted observer, never a
    status set by the caller" invariant (migration 0061) holds here exactly
    as it does for every other writer of that table.
  - 8-K / 8-K/A filings whose item list intersects `LINEAGE_ITEMS` become
    `EntityFilingEvent` rows — an EVENT, never a relation. **Decided,
    2026-09-24 (see planning#213's decisions comment): the submissions JSON
    has no counterparty, and item 2.01 means "completion of acquisition OR
    disposition", so there is no object entity and no direction to assert.
    A person, or #214/#215, supplies the counterparty later.**

`www.sec.gov` is never fetched by slice 1 — only `data.sec.gov`, via
`app.services.sec_edgar`.

## Slice 2 (planning#213, 2026-09-25 decisions): EX-21 + the Business
   Combinations footnote

Two more observers, both **ungranted** (`confirms_relations=false`, unlike
`edgar_former_names`): `edgar_ex21` and `edgar_10k_footnote`, both fetching
`www.sec.gov` — the HTML filing index and the documents it lists — via the
same `app.services.sec_edgar` client, widened to that host.

  - **EX-21 → a snapshot plus one proposal.** Each 10-K's EX-21 exhibit
    rows are stored VERBATIM in `entity_subsidiary_listings` (never a
    diff — the year-over-year comparison is a query over these rows). Per
    distinct (filer, exact name, exact jurisdiction), exactly ONE
    `subsidiary_of` relation is proposed, at its FIRST appearance across
    all 10-Ks (processed **oldest filing_date first**, so "first" is well
    defined), citing that EX-21 as evidence. A new row may be an
    acquisition OR a newly formed subsidiary, so nothing is labelled
    `acquired`, and — since the observer is ungranted — `assert_relation`
    never auto-confirms it either.
  - **The Business Combinations (or Acquisitions) footnote → a stored
    section, NO relations at all.** Located by `edgar_html.find_business_
    combinations_section`'s rule — prefer a `Note N`/`N.`-prefixed match,
    LAST among those; otherwise the LAST bare match (planning#220 defect 3,
    refined 2026-09-26 from the research method's original "always take
    the LAST heading match", which a live run showed can pick a bare
    table-cell column header instead of the real note — see that
    function's own docstring) — over the PRIMARY 10-K document's own bytes
    as evidence. Naming the deals in that text is planning#215's job.
  - **History = all 10-Ks** the submissions JSON lists (`filings.recent`
    plus every paged `files[]` entry), never just `recent`. `10-K/A`
    amendments are deliberately excluded (see `_collect_annual_reports`):
    they rarely carry their own EX-21 and would let a later amendment's
    filing_date beat the ORIGINAL 10-K's for "first appearance".
  - **A per-document fetch failure skips that document and continues —
    it does NOT abort the ingest** (planning#220 defect 1, decided
    2026-09-26: a live run's first 10-K, from a filer with pre-2001
    history, named a legacy EX-21 exhibit that 404s, and the un-caught
    `SecNotFound` killed the whole run before it ever reached a modern
    filing). `SecNotFound` counts `documents_not_found`; any other
    exhausted `SecFetchError` (5xx/timeout) counts `documents_fetch_
    failed`. The two exceptions are a 403 (`SecForbidden`) and an
    exhausted 429 (`SecRateLimited`) — both **abort** `ingest_cik`, because
    skip-and-continue would just keep hitting an endpoint that has already
    told this client to stop, across every remaining filing. This applies
    to the EX-21 exhibit fetch, the primary/footnote document fetch, AND
    the per-filing `-index.htm` fetch alike (see each's own try/except).

`app.services.edgar_html` does all the stdlib `html.parser` work (the
documents-table locate, the EX-21 row parse, and the text-rendering +
heading-match port of the research method's `extract_bc.js`) — this module
stays orchestration: which filings, which documents, which rows get
written where, and the same "never a raw insert, never an upsert that sets
status" discipline slice 1 established.

## The scoped-exact-reuse rule extends to EX-21, over a DIFFERENT table

`formerly_named`'s reuse lookup (below) queries `entity_relations` itself.
EX-21's reuse lookup queries `entity_subsidiary_listings` instead — the
prior row's `subsidiary_entity_id`, scoped by `filer_entity_id` AND exact
`(name, jurisdiction)` (NULL jurisdiction matching NULL via `IS NOT
DISTINCT FROM`) — because a subsidiary's identity here is "this filer once
listed this exact name at this exact jurisdiction", not "this filer once
asserted a relation to this name" (a listing row can exist with NO relation
at all, for a heading or self-name row that was never stored, or for a
relation a person later rejected — the relation's status is irrelevant to
whether the SAME subsidiary identity is reused next year). The
status-blind "does a relation already exist" skip (same shape as slice 1's
§4.7) is a SEPARATE check, over `entity_relations`, keyed on (subject=
subsidiary entity, object=filer, relation, observer) — not filtered by
evidence, so a person's rejection survives a re-ingest here exactly as it
does for `formerly_named`.

## Former-name entity reuse is scoped and exact — read this before touching
   step 4 below

The object of a `formerly_named` relation is reused ONLY when a row already
exists with the EXACT tuple (this CIK's entity as subject, relation=
`formerly_named`, THIS observer, object's `legal_name` byte-identical to
the candidate name) — regardless of that row's `status` or `evidence_id`.
This is not a deduplication nicety; it is load-bearing. The submissions
JSON changes shape every time a new filing lands, so a naive
"insert-if-new-evidence" ingest would, on every re-ingest, see "new
evidence, no relation from THIS evidence yet" and insert a fresh
auto-confirmed row for a former name a person had already REJECTED —
silently undoing that person's decision every time SEC publishes a filing.
The scoped-existence check makes the object lookup keyed on the relation
tuple, not on the evidence, so a rejected row's mere existence (any status)
suppresses a repeat insert forever. `test_edgar_ingest.py`'s
`test_person_rejected_relation_survives_reingest` is written to FAIL if
this skip is removed (see mutation M1 in the spec's mutation table).

There is no OTHER name lookup anywhere in this module — no global
`legal_name` search, no cross-CIK matching. Two different CIKs sharing a
former name always get two distinct former-name `OrgEntity` rows.

## Posture — through `observer_permitted`, never around it

Both seeded observers are `noise_class = 'silent'` (the query goes to the
SEC, never the counterparty), so `posture.observer_permitted` never denies
either of them today. This module still calls it, per-observer, for every
ingest — not because today's answer is ever `False`, but because "AI raises
attention, never scope, never lowers" applies to code paths as much as to
individual decisions: a future noise-class change or a future posture value
must not have to be re-wired into this module to take effect. If BOTH
observers are denied, `ingest_cik` makes no HTTP request at all.

## `SEC_USER_AGENT` — required, validated here, never in `Settings`

`require_user_agent()` lives here rather than on `app.core.config.Settings`
so a missing/invalid value never blocks ordinary app startup (`Settings()`
constructs regardless) — it only blocks the one code path that needs it,
and it blocks it BEFORE any HTTP request, not after a wasted round trip.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.engagement import Engagement
from app.models.entity_filing_event import EntityFilingEvent
from app.models.entity_filing_section import EntityFilingSection
from app.models.entity_relation import EntityRelation
from app.models.entity_subsidiary_listing import EntitySubsidiaryListing
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.services import candidate_domains, edgar_html, entity_graph, posture, sec_edgar

log = logging.getLogger(__name__)

# Module-level observer-name constants (this module IS the code the #198
# lesson says to seed observers alongside — see migration 0062's docstring).
# No existing `*_OBSERVERS` constant precedent was found elsewhere in this
# codebase for a module owning more than one observer, so these follow the
# established single-observer `_OBSERVER_NAME` pattern (e.g.
# `hosting_classifier._OBSERVER_NAME`), just two of them, public because the
# API layer (`app/api/entities.py`'s posture test hook) needs to name one.
OBSERVER_FORMER_NAMES = "edgar_former_names"
OBSERVER_8K_ITEMS = "edgar_8k_items"
OBSERVER_EX21 = "edgar_ex21"
OBSERVER_FOOTNOTE = "edgar_10k_footnote"
# planning#216 (migration 0064) — the filer's own website, read from the
# same primary 10-K document the footnote reader uses.
OBSERVER_WEBSITE = "edgar_10k_website"

# 10-K405 is the pre-2003 EDGAR form id for an on-time 10-K with the (now
# retired) Item 405 box checked — still a plain annual report, so it is
# processed identically to "10-K". `10-K/A` (any amendment) is deliberately
# EXCLUDED: an amendment rarely carries its own EX-21, and including it
# risks a LATER amendment's filing_date winning "first appearance" over the
# ORIGINAL 10-K's earlier one for a subsidiary that was already listed
# there (planning#213 slice 2 spec, §3).
ANNUAL_REPORT_FORMS: frozenset[str] = frozenset({"10-K", "10-K405"})

# Versioned so a future extraction rewrite is never confused with this
# one's documented limitation (see `EntityFilingSection`'s docstring): the
# LAST heading match can land on a later, unrelated mention.
SECTION_EXTRACTION_METHOD = "last_heading_match_v1"

# 2.01 = Completion of Acquisition or Disposition of Assets (covers BOTH
# directions — this is exactly why an 8-K becomes an event, not a labelled
# relation). 5.01 = Change in Control of Registrant — the FILER was the one
# absorbed or spun off. Item 1.01 (Entry into a Material Definitive
# Agreement) is deliberately excluded: material agreements include credit
# facilities and routine commercial contracts, so it is noise for lineage
# purposes (planning#213 decisions comment, 2026-09-24).
LINEAGE_ITEMS: frozenset[str] = frozenset({"2.01", "5.01"})

_CIK_INPUT_RE = re.compile(r"^[0-9]{1,10}$")
_ACCESSION_RE = re.compile(r"^[0-9]{10}-[0-9]{2}-[0-9]{6}$")

_UA_MAX_LEN = 200


class EdgarNotConfigured(Exception):
    """`SEC_USER_AGENT` is unset or fails validation. Raised before any I/O."""


class EdgarObserversMissing(Exception):
    """One or both seeded observers (migration 0062) are missing. Fails
    closed — this module never creates them on the fly."""


@dataclass
class IngestResult:
    entity_id: uuid.UUID | None
    pages_fetched: int = 0
    former_names_asserted: int = 0
    former_names_skipped: int = 0
    events_inserted: int = 0
    events_existing: int = 0
    malformed_skipped: int = 0
    denied: list[str] = field(default_factory=list)

    # ── slice 2 (planning#213, 2026-09-25) ──────────────────────────────────
    annual_reports_seen: int = 0
    ex21_docs: int = 0
    ex21_missing: int = 0
    # Not named in the spec's own §3 field enumeration, but §4 explicitly
    # requires counting it ("count ex21_unparsed") and a required test
    # (§7) asserts it — a spec inconsistency resolved conservatively by
    # adding the field rather than dropping the count. See the report's
    # answer 3.
    ex21_unparsed: int = 0
    # Same story: §4 says heading/self-name rows are "not stored... Count
    # them in the result" but names no field. Added for the same reason.
    ex21_heading_rows_skipped: int = 0
    subsidiary_rows: int = 0
    subsidiaries_proposed: int = 0
    subsidiaries_skipped: int = 0
    sections_stored: int = 0
    sections_existing: int = 0
    sections_not_found: int = 0
    # planning#216: candidate domains from the 10-K's own website sentence.
    website_candidates_proposed: int = 0
    website_candidates_existing: int = 0
    oversize_skipped: int = 0
    # A document filename (from the index or the `primaryDocument` fallback)
    # that fails `sec_edgar.is_valid_filename` — never requested.
    invalid_filename_skipped: int = 0

    # ── planning#220 (2026-09-26): per-document fetch failures that skip
    # and continue, rather than aborting the whole ingest (defect 1) ──────
    # A per-document fetch (EX-21 exhibit, primary/footnote doc, or the
    # filing's own -index.htm) that 404s. `SecNotFound` is not a
    # `SecFetchError` subclass, so it is counted separately from
    # `documents_fetch_failed` below.
    documents_not_found: int = 0
    # A per-document fetch that exhausted retries with a plain
    # `SecFetchError` (5xx/timeout exhaustion). A 403 (`SecForbidden`) or an
    # exhausted 429 (`SecRateLimited`) is NEVER counted here — both abort
    # the whole ingest instead (see `ingest_cik`'s module docstring).
    documents_fetch_failed: int = 0


def normalise_cik(cik: str) -> str:
    """`^[0-9]{1,10}$`, then zero-padded to 10 digits. Anything else raises
    `ValueError`. Public (not `_normalise_cik`) because `app/api/entities.py`
    validates synchronously before returning 422, and calling a private
    helper across a module boundary is worse than naming it properly."""
    if not isinstance(cik, str) or not _CIK_INPUT_RE.match(cik):
        raise ValueError(f"cik must be 1 to 10 digits, got {cik!r}")
    return cik.zfill(10)


def require_user_agent() -> None:
    """Valid means: set, non-empty after strip, contains '@', length <= 200,
    no CR/LF. Raises `EdgarNotConfigured` otherwise. Public for the same
    reason as `normalise_cik` — the API layer calls this synchronously
    before accepting a request."""
    ua = settings.sec_user_agent
    if ua is None:
        raise EdgarNotConfigured(
            "SEC_USER_AGENT is not set. SEC EDGAR ingest refuses to run without a "
            "descriptive contact string (SEC fair-access policy)."
        )
    if "\r" in ua or "\n" in ua:
        raise EdgarNotConfigured("SEC_USER_AGENT must not contain CR or LF.")
    stripped = ua.strip()
    if not stripped or "@" not in stripped or len(stripped) > _UA_MAX_LEN:
        raise EdgarNotConfigured(
            "SEC_USER_AGENT is set but invalid: it must be non-empty after "
            "stripping, contain '@', and be at most 200 characters."
        )


def _document_filename(cell: str) -> str:
    """planning#220 defect 2 (2026-09-26): an index `Document` cell for an
    inline-XBRL filing's main document renders as `<a href="/ix?doc=...">
    x10k.htm</a> <span>iXBRL</span>` — the viewer link's OWN visible text
    (the real filename) plus the trailing `iXBRL` badge both land in the
    same rendered table cell (`app.services.edgar_html`'s row collector
    space-joins a row's cell text), so the cell reads `"x10k.htm iXBRL"`,
    not the bare filename. Strip whitespace; if the cell has 2+
    whitespace-separated tokens and the LAST token is EXACTLY `iXBRL`
    (case-sensitive — EDGAR's own viewer badge is always this exact
    casing, not `ixbrl` or `IXBRL`), return the text before it, stripped.
    Otherwise return the stripped cell unchanged — nothing else is
    stripped, so an ordinary non-iXBRL filename (`form10k.htm`) or a
    single-token oddity (a cell reading only `iXBRL`, with no filename at
    all) both pass through untouched, and `is_valid_filename` is left to
    reject whatever comes out the other end."""
    stripped = cell.strip()
    tokens = stripped.split()
    if len(tokens) >= 2 and tokens[-1] == "iXBRL":
        return stripped[: -len(tokens[-1])].strip()
    return stripped


def _parse_event_date(raw: str | None) -> tuple[date | None, str]:
    if not raw:
        return None, "unknown"
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date(), "day"
    except (ValueError, TypeError):
        return None, "unknown"


def _parse_date_only(raw: str | None) -> date | None:
    """`filing_date`/`report_date` need a plain `date | None`, not the
    `(date, precision)` pair `_parse_event_date` returns for a relation's
    `event_date` — both tables' date columns carry no precision column of
    their own."""
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def _collect_annual_reports(array: dict, *, evidence_id: uuid.UUID) -> list[dict]:
    """Extract 10-K/10-K405 entries (excluding `/A` amendments — see
    `ANNUAL_REPORT_FORMS`'s own comment) from ONE parallel-array block
    (`filings.recent`, or one paged `files[]` entry's already-parsed JSON).
    Each returned dict carries `evidence_id` (the fetch that CONTAINED this
    entry — the main submissions fetch for `recent`, that page's own fetch
    for a page — mirroring `_process_filing_array`'s per-array evidence_id
    parameter) so the caller can sort ALL of them together, across
    `recent` and every page, before deciding processing order. A row whose
    `filing_date` fails to parse is silently dropped — not spelled out by
    the spec's malformed-row handling (which only names the 8-K accession
    CHECK), but "first appearance" ordering has no sensible fallback for an
    unparseable date, so dropping it (rather than crashing the whole
    ingest, or sorting it arbitrarily) is the conservative reading;
    documented in the report's answer 3."""
    forms = array.get("form") or []
    accessions = array.get("accessionNumber") or []
    filing_dates = array.get("filingDate") or []
    report_dates = array.get("reportDate") or []
    primary_docs = array.get("primaryDocument") or []
    n = min(len(forms), len(accessions), len(filing_dates))

    out: list[dict] = []
    for i in range(n):
        form = forms[i]
        if form not in ANNUAL_REPORT_FORMS:
            continue
        filing_date_val = _parse_date_only(filing_dates[i])
        if filing_date_val is None:
            continue
        out.append(
            {
                "form": form,
                "accession": accessions[i],
                "filing_date": filing_date_val,
                "report_date": _parse_date_only(report_dates[i]) if i < len(report_dates) else None,
                "primary_document": primary_docs[i] if i < len(primary_docs) else None,
                "evidence_id": evidence_id,
            }
        )
    return out


def _load_observer(db: Session, name: str) -> Observer | None:
    return db.execute(select(Observer).where(Observer.name == name)).scalar_one_or_none()


def _existing_entity_by_cik(db: Session, cik: str) -> OrgEntity | None:
    return db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one_or_none()


def _is_passive_only_for_entity(db: Session, entity: OrgEntity | None) -> bool:
    """`entity` may be `None` (the CIK has never been ingested before) —
    that is the ordinary case for a first ingest, and it means "nothing to
    restrict" (no engagement can point at an entity that does not exist
    yet), matching `posture.posture_restricts(None) == False`."""
    if entity is None:
        return False
    engagements: Iterable[Engagement] = db.execute(
        select(Engagement).where(Engagement.subject_entity_id == entity.id)
    ).scalars().all()
    return any(posture.posture_restricts(e.posture) for e in engagements)


def _process_former_names(
    db: Session,
    *,
    entity: OrgEntity,
    current_name: str,
    former_names: list[dict],
    observer: Observer,
    main_evidence_id: uuid.UUID,
    result: IngestResult,
) -> None:
    for entry in former_names:
        name = (entry.get("name") or "").strip()
        if not name or name == current_name:
            result.former_names_skipped += 1
            continue

        # ── the scoped, exact reuse lookup (see module docstring) ──────────
        # Load-bearing: ANY existing row on this exact tuple — regardless of
        # its status or evidence — suppresses a repeat insert. This is what
        # keeps a person's rejection from being silently re-proposed on the
        # next re-ingest (mutation M1 removes this and must fail a test).
        already = db.execute(
            select(EntityRelation.id)
            .join(OrgEntity, EntityRelation.object_id == OrgEntity.id)
            .where(
                EntityRelation.subject_id == entity.id,
                EntityRelation.relation == "formerly_named",
                EntityRelation.observer_id == observer.id,
                OrgEntity.legal_name == name,
            )
        ).first()
        if already is not None:
            result.former_names_skipped += 1
            continue

        former_entity = OrgEntity(id=uuid.uuid4(), legal_name=name, cik=None)
        db.add(former_entity)
        db.commit()

        event_date, precision = _parse_event_date(entry.get("to"))
        entity_graph.assert_relation(
            db,
            subject_id=entity.id,
            object_id=former_entity.id,
            relation="formerly_named",
            observer_id=observer.id,
            evidence_id=main_evidence_id,
            quote=json.dumps(entry, sort_keys=True, separators=(",", ":")),
            event_date=event_date,
            event_date_precision=precision,
        )
        result.former_names_asserted += 1


def _process_filing_array(
    db: Session,
    *,
    entity: OrgEntity,
    observer: Observer,
    evidence_id: uuid.UUID,
    array: dict,
    result: IngestResult,
) -> None:
    forms = array.get("form") or []
    accessions = array.get("accessionNumber") or []
    filing_dates = array.get("filingDate") or []
    items_list = array.get("items") or []
    n = min(len(forms), len(accessions), len(filing_dates), len(items_list))

    for i in range(n):
        form = forms[i]
        if form not in ("8-K", "8-K/A"):
            continue
        item_set = set((items_list[i] or "").split(","))
        if not (item_set & LINEAGE_ITEMS):
            continue

        accession = accessions[i]
        if not isinstance(accession, str) or not _ACCESSION_RE.match(accession):
            result.malformed_skipped += 1
            continue

        try:
            filing_date_val = datetime.strptime(filing_dates[i], "%Y-%m-%d").date()
        except (ValueError, TypeError):
            # Not spelled out in the spec's malformed-row handling, which
            # only names the accession CHECK — but `filing_date` is NOT
            # NULL with no CHECK of its own, so an unparseable date would
            # otherwise raise inside the INSERT rather than being counted
            # and skipped like every other malformed row. Same conservative
            # treatment as the accession check, documented in the report's
            # answer 3 (a decision the spec did not make).
            result.malformed_skipped += 1
            continue

        inserted_id = db.execute(
            pg_insert(EntityFilingEvent.__table__)
            .values(
                id=uuid.uuid4(),
                entity_id=entity.id,
                observer_id=observer.id,
                evidence_id=evidence_id,
                form=form,
                accession_number=accession,
                filing_date=filing_date_val,
                items=items_list[i],
            )
            .on_conflict_do_nothing(constraint="uq_entity_filing_events_entity_accession")
            .returning(EntityFilingEvent.id)
        ).scalar()
        db.commit()
        if inserted_id is not None:
            result.events_inserted += 1
        else:
            result.events_existing += 1


def _process_ex21_for_filing(
    db: Session,
    *,
    entity: OrgEntity,
    normalised_cik: str,
    observer: Observer,
    index_rows: list[dict],
    report: dict,
    result: IngestResult,
) -> None:
    """Locate and process ONE 10-K's EX-21 exhibit, given its ALREADY
    fetched and parsed documents-table index (`index_rows`, never `None`
    here — the caller only invokes this when the index was fetched and
    parsed successfully). `report` is one entry from
    `_collect_annual_reports`. Located **by the index `Type` cell,
    NEVER by filename** — a filer can name the exhibit file anything."""
    ex21_index_rows = [r for r in index_rows if (r.get("Type") or "").strip().startswith("EX-21")]
    if not ex21_index_rows:
        result.ex21_missing += 1
        return

    # EVERY EX-21-typed row is processed (an EX-21.1 and an EX-21.2 can list
    # different subsidiaries); the listing key carries `exhibit_type`, so
    # their rows never collide.
    for chosen in ex21_index_rows:
        raw_document = (chosen.get("Document") or "").strip()
        filename = _document_filename(raw_document) if raw_document else ""
        exhibit_type = (chosen.get("Type") or "").strip()
        if not sec_edgar.is_valid_filename(filename):
            result.invalid_filename_skipped += 1
            continue

        # ── planning#220 defect 1 (2026-09-26): per-document fetch
        # failures skip and continue; a 403/exhausted-429 aborts the whole
        # ingest instead. ORDER MATTERS: SecDocumentTooLarge and the two
        # abort classes are all SecFetchError subclasses, so the abort
        # re-raise must come before the generic SecFetchError catch-all.
        try:
            doc_content, _doc_ct, doc_fetched_at, doc_url = sec_edgar.fetch_filing_document(
                normalised_cik, report["accession"], filename
            )
        except sec_edgar.SecDocumentTooLarge:
            result.oversize_skipped += 1
            continue
        except (sec_edgar.SecForbidden, sec_edgar.SecRateLimited):
            raise
        except sec_edgar.SecNotFound:
            result.documents_not_found += 1
            continue
        except sec_edgar.SecFetchError:
            result.documents_fetch_failed += 1
            continue

        evidence = entity_graph.store_evidence(
            db, content=doc_content, content_type="text/html", source_url=doc_url, fetched_at=doc_fetched_at
        )
        result.ex21_docs += 1

        rows = edgar_html.parse_ex21_rows(doc_content.decode("utf-8", errors="replace"))
        if rows is None:
            # No <tr> at all — a plain paragraph/`<pre>` list. Guessing at
            # paragraph parsing is explicitly out of scope for this slice.
            result.ex21_unparsed += 1
            continue

        row_index = 0
        for cells in rows:
            name = cells[0]
            if edgar_html.is_heading_row(cells) or name == entity.legal_name:
                result.ex21_heading_rows_skipped += 1
                continue

            jurisdiction = cells[1] if len(cells) >= 2 else None
            this_row_index = row_index
            row_index += 1

            # ── scoped exact reuse, over entity_subsidiary_listings (see module
            # docstring's "The scoped-exact-reuse rule extends to EX-21") ───────
            existing_subsidiary_id = db.execute(
                select(EntitySubsidiaryListing.subsidiary_entity_id)
                .where(
                    EntitySubsidiaryListing.filer_entity_id == entity.id,
                    EntitySubsidiaryListing.name == name,
                    EntitySubsidiaryListing.jurisdiction.is_not_distinct_from(jurisdiction),
                    EntitySubsidiaryListing.subsidiary_entity_id.is_not(None),
                )
                .limit(1)
            ).scalar()

            if existing_subsidiary_id is not None:
                subsidiary_id = existing_subsidiary_id
            else:
                subsidiary_id = uuid.uuid4()
                db.add(OrgEntity(id=subsidiary_id, legal_name=name, cik=None))
                db.commit()

            inserted_listing_id = db.execute(
                pg_insert(EntitySubsidiaryListing.__table__)
                .values(
                    id=uuid.uuid4(),
                    filer_entity_id=entity.id,
                    observer_id=observer.id,
                    evidence_id=evidence.id,
                    accession_number=report["accession"],
                    exhibit_type=exhibit_type,
                    filing_date=report["filing_date"],
                    report_date=report["report_date"],
                    row_index=this_row_index,
                    name=name,
                    jurisdiction=jurisdiction,
                    cells=cells,
                    subsidiary_entity_id=subsidiary_id,
                )
                .on_conflict_do_nothing(constraint="uq_entity_subsidiary_listings_filer_accession_exhibit_row")
                .returning(EntitySubsidiaryListing.id)
            ).scalar()
            db.commit()
            if inserted_listing_id is not None:
                result.subsidiary_rows += 1

            # ── status-blind skip (§4.3 — same shape as slice 1's §4.7 for
            # formerly_named): ANY existing row on this exact tuple, whatever
            # its status or evidence, suppresses a repeat proposal. This is
            # what keeps a person's rejection from being silently re-proposed
            # the next time this subsidiary's name reappears in a later year's
            # EX-21 (mutation M1 removes this and must fail a test).
            already = db.execute(
                select(EntityRelation.id).where(
                    EntityRelation.subject_id == subsidiary_id,
                    EntityRelation.object_id == entity.id,
                    EntityRelation.relation == "subsidiary_of",
                    EntityRelation.observer_id == observer.id,
                )
            ).first()
            if already is not None:
                result.subsidiaries_skipped += 1
                continue

            entity_graph.assert_relation(
                db,
                subject_id=subsidiary_id,
                object_id=entity.id,
                relation="subsidiary_of",
                observer_id=observer.id,
                evidence_id=evidence.id,
                quote=" | ".join(cells),
                event_date=report["report_date"] or report["filing_date"],
                event_date_precision="day",
            )
            result.subsidiaries_proposed += 1


def _process_primary_document_for_filing(
    db: Session,
    *,
    entity: OrgEntity,
    normalised_cik: str,
    footnote_observer: Observer | None,
    website_observer: Observer | None,
    index_rows: list[dict] | None,
    report: dict,
    result: IngestResult,
) -> None:
    """Fetch ONE 10-K's primary document once, then run each permitted
    reader over it: the Business Combinations / Acquisitions footnote
    (`footnote_observer`) and the filer's own website sentence
    (`website_observer`, planning#216). A `None` observer means that
    reader is denied by posture (the caller decides). `index_rows` may be `None` (the index itself could not be
    fetched/parsed — see `ingest_cik`'s loop) — the submissions JSON's
    `primaryDocument` fallback needs no index at all.

    planning#220 defect 2 (2026-09-26): the index `Document` cell goes
    through `_document_filename` first (stripping a trailing iXBRL viewer
    token — see that helper's docstring). If the result is empty OR fails
    `is_valid_filename`, `report["primary_document"]` is tried next.
    `invalid_filename_skipped` is counted only when a NON-EMPTY filename
    (the index cell OR the fallback) is invalid; `sections_not_found` is
    counted when there is no usable filename anywhere. A filename that
    fails `is_valid_filename` is NEVER requested."""
    filename = ""
    if index_rows is not None:
        for row in index_rows:
            if (row.get("Type") or "").strip() == report["form"]:
                raw_document = (row.get("Document") or "").strip()
                filename = _document_filename(raw_document) if raw_document else ""
                break

    if not filename or not sec_edgar.is_valid_filename(filename):
        fallback_raw = report.get("primary_document")
        fallback = fallback_raw.strip() if isinstance(fallback_raw, str) else ""
        if not fallback:
            # Nothing usable from either source. If the index cell DID
            # produce a non-empty (but invalid) name and there is simply no
            # primaryDocument to fall back to, that is still an invalid
            # filename we found and refused to request — not "nothing was
            # found at all" — so it is counted as invalid_filename_skipped,
            # matching that counter's own general meaning ("from the index
            # or the fallback"). Only a truly empty index resolution with
            # no fallback counts as sections_not_found (today's behaviour).
            # See the report's answer 3 — the spec names only the other two
            # branches explicitly.
            if filename:
                result.invalid_filename_skipped += 1
            else:
                result.sections_not_found += 1
            return
        if not sec_edgar.is_valid_filename(fallback):
            result.invalid_filename_skipped += 1
            return
        filename = fallback

    # ── planning#220 defect 1 (2026-09-26): see `_process_ex21_for_filing`'s
    # identical comment — order matters, abort classes re-raise first.
    try:
        doc_content, _doc_ct, doc_fetched_at, doc_url = sec_edgar.fetch_filing_document(
            normalised_cik, report["accession"], filename
        )
    except sec_edgar.SecDocumentTooLarge:
        result.oversize_skipped += 1
        return
    except (sec_edgar.SecForbidden, sec_edgar.SecRateLimited):
        raise
    except sec_edgar.SecNotFound:
        result.documents_not_found += 1
        return
    except sec_edgar.SecFetchError:
        result.documents_fetch_failed += 1
        return

    evidence = entity_graph.store_evidence(
        db, content=doc_content, content_type="text/html", source_url=doc_url, fetched_at=doc_fetched_at
    )

    lines = edgar_html.render_text_lines(doc_content.decode("utf-8", errors="replace"))
    if website_observer is not None:
        _propose_websites(
            db, entity=entity, observer=website_observer, evidence_id=evidence.id, lines=lines, report=report, result=result
        )
    if footnote_observer is not None:
        _store_footnote_section(
            db, entity=entity, observer=footnote_observer, evidence_id=evidence.id, lines=lines, report=report, result=result
        )


def _propose_websites(
    db: Session,
    *,
    entity: OrgEntity,
    observer: Observer,
    evidence_id: uuid.UUID,
    lines: list[str],
    report: dict,
    result: IngestResult,
) -> None:
    """planning#216: every domain this 10-K names as the filer's own
    website becomes (or re-cites) a PROPOSED candidate — never a target."""
    for domain, quote in edgar_html.find_website_mentions(lines):
        inserted = candidate_domains.propose_from_filing(
            db,
            entity_id=entity.id,
            domain=domain,
            observer=observer,
            evidence_id=evidence_id,
            quote=quote,
            filing_date=report["filing_date"],
        )
        if inserted:
            result.website_candidates_proposed += 1
        else:
            result.website_candidates_existing += 1


def _store_footnote_section(
    db: Session,
    *,
    entity: OrgEntity,
    observer: Observer,
    evidence_id: uuid.UUID,
    lines: list[str],
    report: dict,
    result: IngestResult,
) -> None:
    located = edgar_html.find_business_combinations_section(lines)
    if located is None:
        result.sections_not_found += 1
        return

    start, end, heading, match_count = located
    text = "\n".join(lines[start:end])

    inserted_id = db.execute(
        pg_insert(EntityFilingSection.__table__)
        .values(
            id=uuid.uuid4(),
            entity_id=entity.id,
            observer_id=observer.id,
            evidence_id=evidence_id,
            accession_number=report["accession"],
            form=report["form"],
            filing_date=report["filing_date"],
            report_date=report["report_date"],
            section="business_combinations",
            extraction=SECTION_EXTRACTION_METHOD,
            heading=heading,
            heading_match_count=match_count,
            start_line=start,
            end_line=end,
            text=text,
        )
        .on_conflict_do_nothing(constraint="uq_entity_filing_sections_entity_accession_section")
        .returning(EntityFilingSection.id)
    ).scalar()
    db.commit()
    if inserted_id is not None:
        result.sections_stored += 1
    else:
        result.sections_existing += 1


def ingest_cik(db: Session, cik: str) -> IngestResult:
    """Fetch and ingest one CIK's submissions JSON. Never touches
    `targets`, domains or scans, and never maps a name to an entity except
    the scoped lookups in `_process_former_names` (over `entity_relations`)
    and `_process_ex21_for_filing` (over `entity_subsidiary_listings`).

    Per-document fetch failures (an EX-21 exhibit, a primary/footnote
    document, or one filing's own index page) are skipped and counted —
    `documents_not_found` / `documents_fetch_failed` on the returned
    `IngestResult` — rather than raised (planning#220 defect 1). The two
    exceptions still propagate out of this function and ABORT the ingest:
    `sec_edgar.SecForbidden` (403) and `sec_edgar.SecRateLimited` (429
    exhausted), plus anything raised fetching the submissions JSON or its
    paged continuations (unchanged from slice 1 — that happens before the
    per-filing loop this paragraph describes)."""
    normalised_cik = normalise_cik(cik)
    require_user_agent()

    former_names_observer = _load_observer(db, OBSERVER_FORMER_NAMES)
    events_observer = _load_observer(db, OBSERVER_8K_ITEMS)
    ex21_observer = _load_observer(db, OBSERVER_EX21)
    footnote_observer = _load_observer(db, OBSERVER_FOOTNOTE)
    website_observer = _load_observer(db, OBSERVER_WEBSITE)
    if None in (former_names_observer, events_observer, ex21_observer, footnote_observer, website_observer):
        raise EdgarObserversMissing(
            f"seeded observers {OBSERVER_FORMER_NAMES!r}/{OBSERVER_8K_ITEMS!r}/"
            f"{OBSERVER_EX21!r}/{OBSERVER_FOOTNOTE!r}/{OBSERVER_WEBSITE!r} not found "
            "(migrations 0062/0063/0064 not applied?) — refusing rather than creating them on the fly."
        )

    existing_entity = _existing_entity_by_cik(db, normalised_cik)
    passive_only = _is_passive_only_for_entity(db, existing_entity)

    former_names_permitted = posture.observer_permitted(
        passive_only=passive_only, noise_class=former_names_observer.noise_class
    )
    events_permitted = posture.observer_permitted(
        passive_only=passive_only, noise_class=events_observer.noise_class
    )
    ex21_permitted = posture.observer_permitted(passive_only=passive_only, noise_class=ex21_observer.noise_class)
    footnote_permitted = posture.observer_permitted(
        passive_only=passive_only, noise_class=footnote_observer.noise_class
    )
    website_permitted = posture.observer_permitted(
        passive_only=passive_only, noise_class=website_observer.noise_class
    )

    denied: list[str] = []
    if not former_names_permitted:
        denied.append(former_names_observer.name)
    if not events_permitted:
        denied.append(events_observer.name)
    if not ex21_permitted:
        denied.append(ex21_observer.name)
    if not footnote_permitted:
        denied.append(footnote_observer.name)
    if not website_permitted:
        denied.append(website_observer.name)

    result = IngestResult(entity_id=existing_entity.id if existing_entity else None, denied=denied)

    if not any((former_names_permitted, events_permitted, ex21_permitted, footnote_permitted, website_permitted)):
        # All FIVE signals denied — no HTTP request at all.
        return result

    content, content_type, fetched_at, url = sec_edgar.fetch_submissions(normalised_cik)
    main_fetch = entity_graph.store_evidence(
        db, content=content, content_type=content_type, source_url=url, fetched_at=fetched_at
    )
    data = json.loads(content)
    current_name = data["name"]

    # ── entity upsert — never updates an existing row's legal_name ─────────
    db.execute(
        pg_insert(OrgEntity.__table__)
        .values(id=uuid.uuid4(), legal_name=current_name, cik=normalised_cik)
        .on_conflict_do_nothing(constraint="uq_org_entities_cik")
    )
    db.commit()
    entity = db.execute(select(OrgEntity).where(OrgEntity.cik == normalised_cik)).scalar_one()
    result.entity_id = entity.id

    # ── paged filings.files[] — fetched when ANY of 8-K / EX-21 / footnote
    # is permitted: all three need the full filing history past `filings.
    # recent` (slice 2 spec §3 — widened from slice 1's "events-only"
    # condition, which former names alone still never triggers).
    pages: list[tuple[dict, uuid.UUID]] = []
    if events_permitted or ex21_permitted or footnote_permitted or website_permitted:
        for file_entry in (data.get("filings", {}).get("files") or []):
            name = file_entry.get("name")
            page_content, page_content_type, page_fetched_at, page_url = sec_edgar.fetch_submissions_page(name)
            page_fetch = entity_graph.store_evidence(
                db, content=page_content, content_type=page_content_type, source_url=page_url, fetched_at=page_fetched_at
            )
            pages.append((json.loads(page_content), page_fetch.id))
            result.pages_fetched += 1

    if former_names_permitted:
        _process_former_names(
            db,
            entity=entity,
            current_name=current_name,
            former_names=data.get("formerNames") or [],
            observer=former_names_observer,
            main_evidence_id=main_fetch.id,
            result=result,
        )

    if events_permitted:
        recent = data.get("filings", {}).get("recent") or {}
        _process_filing_array(
            db, entity=entity, observer=events_observer, evidence_id=main_fetch.id, array=recent, result=result
        )
        for page_data, page_evidence_id in pages:
            _process_filing_array(
                db, entity=entity, observer=events_observer, evidence_id=page_evidence_id, array=page_data, result=result
            )

    if ex21_permitted or footnote_permitted or website_permitted:
        recent = data.get("filings", {}).get("recent") or {}
        annual_reports = _collect_annual_reports(recent, evidence_id=main_fetch.id)
        for page_data, page_evidence_id in pages:
            annual_reports.extend(_collect_annual_reports(page_data, evidence_id=page_evidence_id))
        # "First appearance" (§4) needs a total order across ALL 10-Ks —
        # recent plus every page — not per-array. `list.sort` is stable, so
        # same-date entries keep their (recent-before-pages) discovery
        # order rather than being reshuffled arbitrarily.
        annual_reports.sort(key=lambda r: r["filing_date"])

        for report in annual_reports:
            result.annual_reports_seen += 1
            accession = report["accession"]
            if not isinstance(accession, str) or not _ACCESSION_RE.match(accession):
                # Same conservative treatment as the 8-K malformed-accession
                # skip (§4's malformed-row handling only names that CHECK
                # explicitly) — an annual report entry whose own accession
                # cannot build a valid URL is silently skipped rather than
                # raising. Documented in the report's answer 3.
                continue

            index_rows: list[dict] | None = None
            try:
                index_content, _idx_ct, _idx_fetched_at, _idx_url = sec_edgar.fetch_filing_index(
                    normalised_cik, accession
                )
                index_rows = edgar_html.parse_index_table(index_content.decode("utf-8", errors="replace"))
            except sec_edgar.SecDocumentTooLarge:
                # The INDEX page itself was oversize — vanishingly unlikely
                # in practice (real index pages are tiny) and untested;
                # documented in the report's answer 3. Both signals fall
                # back to whatever they can do without it (footnote still
                # tries the `primaryDocument` fallback below; EX-21 has none
                # and is simply skipped for this filing).
                result.oversize_skipped += 1
                index_rows = None
            except (sec_edgar.SecForbidden, sec_edgar.SecRateLimited):
                # planning#220 defect 1: abort the whole ingest, same as a
                # per-document 403/exhausted-429 — see the module docstring.
                raise
            except sec_edgar.SecNotFound:
                # planning#220 (the #220 blocker itself, live-run observed
                # on an exhibit rather than the index, but the same shape):
                # skip this filing's index, carry on exactly as the
                # oversize-index path above does.
                result.documents_not_found += 1
                index_rows = None
            except sec_edgar.SecFetchError:
                result.documents_fetch_failed += 1
                index_rows = None

            if ex21_permitted:
                if index_rows is not None:
                    _process_ex21_for_filing(
                        db,
                        entity=entity,
                        normalised_cik=normalised_cik,
                        observer=ex21_observer,
                        index_rows=index_rows,
                        report=report,
                        result=result,
                    )
                # else: no index to locate the EX-21 by Type — nothing
                # further to do for this filing's EX-21 signal.

            if footnote_permitted or website_permitted:
                _process_primary_document_for_filing(
                    db,
                    entity=entity,
                    normalised_cik=normalised_cik,
                    footnote_observer=footnote_observer if footnote_permitted else None,
                    website_observer=website_observer if website_permitted else None,
                    index_rows=index_rows,
                    report=report,
                    result=result,
                )

    return result
