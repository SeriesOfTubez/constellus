"""Shared fixture helpers for SEC EDGAR ingest tests (planning#213, L4
slice 1). Mirrors `_entity_graph.py`'s pattern: throwaway rows, invented
names/CIKs only (`feedback_real_customer_data` — never a real company or a
real CIK).

## Synthetic CIKs

`make_cik(db)` draws from `uuid4().int`, formats as 10 digits, and forces
the first two digits to "99" — real SEC CIKs are assigned sequentially from
a much lower range (Apple's is 0000320193; the live counter is still well
under 2,000,000), so no `99##########`-prefixed value can collide with a
real filer. It also re-draws on a collision with an existing `org_entities.
cik` row, per the spec.

## Cleanup

`cleanup_cik(db, cik)` deletes everything one `ingest_cik(db, cik)` call (or
a test seeding the same shape by hand) could have created, in FK-safe
order: `entity_relations` (by subject) -> `entity_subsidiary_listings` /
`entity_filing_sections` / `entity_filing_events` (by filer/entity) ->
`evidence_fetches`/`evidence_blobs` (found by CIK appearing in
`source_url`, since every URL this slice fetches — both `data.sec.gov`'s
zero-padded `CIK##########` form AND `www.sec.gov`'s UNPADDED `int(cik10)`
path segment — embeds the CIK as a decimal substring) -> former-name/
subsidiary `org_entities` (the relations'/listings' objects) -> the main
entity. Never deletes the seeded `edgar_former_names`/`edgar_8k_items`/
`edgar_ex21`/`edgar_10k_footnote` observer rows — those are migration-
owned, not test-owned.

## planning#213 slice 2 (EX-21 + Business Combinations footnote)

`index_html`, `ex21_table_html`, `ex21_paragraph_html`, and
`annual_report_body_html` build the synthetic HTML fixtures slice 2's
tests route through `httpx.MockTransport`, keyed by the request PATH (see
`test_edgar_ingest.py`'s `_Slice2RoutedTransport`) rather than the exact
URL string, since `www.sec.gov`'s directory path embeds the UNPADDED CIK
and the no-dash accession, both derived, not hand-typed, in these tests.
"""

import uuid

from sqlalchemy import select

from app.models.entity_filing_event import EntityFilingEvent
from app.models.entity_filing_section import EntityFilingSection
from app.models.entity_relation import EntityRelation
from app.models.entity_subsidiary_listing import EntitySubsidiaryListing
from app.models.org_entity import OrgEntity
from app.tests._entity_graph import cleanup_evidence


def make_cik(db) -> str:
    while True:
        cik = "99" + f"{uuid.uuid4().int % 10**8:08d}"
        exists = db.execute(select(OrgEntity.id).where(OrgEntity.cik == cik)).first()
        if exists is None:
            return cik


def cleanup_cik(db, cik: str | None) -> None:
    if cik is None:
        return

    entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one_or_none()

    other_entity_ids: set[uuid.UUID] = set()
    if entity is not None:
        # Relations where this entity is EITHER side: `formerly_named` has
        # it as subject, `subsidiary_of` (slice 2) has it as OBJECT (the
        # filer) — "subject subsidiary_of object" reads "subject is a
        # subsidiary of object", so the filer is always the object there.
        relations = db.execute(
            select(EntityRelation).where(
                (EntityRelation.subject_id == entity.id) | (EntityRelation.object_id == entity.id)
            )
        ).scalars().all()
        for r in relations:
            other_entity_ids.add(r.object_id if r.subject_id == entity.id else r.subject_id)
        if relations:
            db.query(EntityRelation).filter(EntityRelation.id.in_([r.id for r in relations])).delete(
                synchronize_session=False
            )
            db.commit()

        listings = db.execute(
            select(EntitySubsidiaryListing).where(EntitySubsidiaryListing.filer_entity_id == entity.id)
        ).scalars().all()
        for listing in listings:
            if listing.subsidiary_entity_id is not None:
                other_entity_ids.add(listing.subsidiary_entity_id)
        if listings:
            db.query(EntitySubsidiaryListing).filter(
                EntitySubsidiaryListing.id.in_([listing.id for listing in listings])
            ).delete(synchronize_session=False)
            db.commit()

        # planning#216: candidate domains cite this CIK's evidence and
        # reference the entity (both RESTRICT) — delete them first.
        from app.models.candidate_domain import CandidateDomain

        db.query(CandidateDomain).filter(CandidateDomain.entity_id == entity.id).delete(synchronize_session=False)
        db.commit()

        sections = db.execute(
            select(EntityFilingSection).where(EntityFilingSection.entity_id == entity.id)
        ).scalars().all()
        if sections:
            db.query(EntityFilingSection).filter(
                EntityFilingSection.id.in_([s.id for s in sections])
            ).delete(synchronize_session=False)
            db.commit()

        events = db.execute(select(EntityFilingEvent).where(EntityFilingEvent.entity_id == entity.id)).scalars().all()
        if events:
            db.query(EntityFilingEvent).filter(EntityFilingEvent.id.in_([e.id for e in events])).delete(
                synchronize_session=False
            )
            db.commit()

    # Every URL this slice fetches embeds the CIK:
    # `data.sec.gov`'s zero-padded `.../CIK<cik>.json` /
    # `.../CIK<cik>-submissions-NNN.json` form, AND (slice 2) `www.sec.gov`'s
    # UNPADDED `int(cik10)` directory-path segment
    # (`.../Archives/edgar/data/<unpadded>/...`). A plain `contains(cik)`
    # substring search already catches BOTH shapes for every CIK this test
    # suite ever generates (`make_cik`'s "99"-prefixed 10-digit strings have
    # no leading zero, so `int(cik) == cik` as text always) — the SECOND
    # search on `str(int(cik))` below is a no-op today but keeps this
    # function correct if a caller ever passes a CIK with a real leading
    # zero (never done here: a low, zero-padded CIK value risks resembling
    # an actual registrant, which `feedback_real_customer_data` treats as
    # sensitive by default — see `test_cleanup_finds_both_url_shapes` and
    # the report's answer 3 for why that specific scenario is not tested).
    from app.models.evidence import EvidenceFetch

    unpadded = str(int(cik))
    candidates = {cik, unpadded}
    fetch_ids_seen: set[uuid.UUID] = set()
    for candidate in candidates:
        fetch_rows = db.execute(select(EvidenceFetch).where(EvidenceFetch.source_url.contains(candidate))).scalars().all()
        for f in fetch_rows:
            if f.id in fetch_ids_seen:
                continue
            fetch_ids_seen.add(f.id)
            cleanup_evidence(db, f.id)

    if other_entity_ids:
        db.query(OrgEntity).filter(OrgEntity.id.in_(other_entity_ids)).delete(synchronize_session=False)
        db.commit()

    if entity is not None:
        db.query(OrgEntity).filter(OrgEntity.id == entity.id).delete(synchronize_session=False)
        db.commit()


# ── planning#213 slice 2 HTML fixture builders ──────────────────────────────
#
# Deliberately low-level (raw `<tr>`/`<td>` string assembly, not a
# structured row -> dict helper) so a test can place an HTML entity or an
# NBSP exactly where the spec's required test needs one, rather than this
# module guessing which cell should carry it.


def tr(*cells: str) -> str:
    """One `<tr>` from raw (already-HTML) cell contents — a test controls
    entity/NBSP placement by passing e.g. `"Example &amp; Co LLC"` or
    `"Delaware&nbsp;"` directly as a cell string."""
    return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def html_table(*trs: str) -> str:
    return "<html><body><table>" + "".join(trs) + "</table></body></html>"


def index_html(rows: list[dict]) -> str:
    """A minimal `-index.htm` documents table. Each dict in `rows` may set
    any of `Seq`/`Description`/`Document`/`Type`/`Size`; a missing key
    renders as an empty cell — real index pages sometimes leave `Size`
    blank for a directory-only entry."""
    header_cols = ["Seq", "Description", "Document", "Type", "Size"]
    header = tr(*header_cols)
    body = "".join(tr(*(str(row.get(c, "")) for c in header_cols)) for row in rows)
    return html_table(header + body)


def ex21_paragraph_html() -> str:
    """An EX-21 with NO `<tr>` at all — a plain paragraph list, the
    `ex21_unparsed` trigger (spec §4: "Do not guess at paragraph parsing in
    this slice")."""
    return (
        "<html><body>"
        "<p>Subsidiaries of the Registrant</p>"
        "<p>Example Sub One LLC, a Delaware limited liability company</p>"
        "<p>Example Sub Two Inc, a Nevada corporation</p>"
        "</body></html>"
    )


def text_block_html(lines: list[str]) -> str:
    """Wraps each line in its own `<p>` — `edgar_html.render_text_lines`
    emits one line per block-level element, so this directly controls the
    line list a section-extraction test will see."""
    return "<html><body>" + "".join(f"<p>{line}</p>" for line in lines) + "</body></html>"
