import ipaddress
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredFinding
from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.models.finding_canonical import FindingCanonical
from app.models.tag_rule import TagRule
from app.services.finding_category import categorize, extract_cve_id
from app.services.tag_service import apply_rules_preloaded, merge_tags

log = logging.getLogger(__name__)


def write_findings(
    db: Session,
    scan_run_id: uuid.UUID,
    findings: list[DiscoveredFinding],
    new_canonical_ids_out: list[uuid.UUID] | None = None,
) -> set[uuid.UUID]:
    """Persist a batch of discovered findings to the canonical schema.

    Upserts findings_canonical rows (one per unique
    (asset, finding_type, source, fingerprint)) and emits has_finding
    edges from each asset_canonical row to its finding_canonical row.

    Pass `new_canonical_ids_out` to receive the ids of any truly-new
    rows (not re-observations). The notification dispatcher uses this
    to fire only on first-time inserts.

    Returns the set of canonical finding IDs touched (new + updated).
    The executor accumulates these across chunks to populate
    scan_runs.finding_count at run completion.

    scan_run_id is currently unused — the legacy `findings` hypertable
    that stored per-run observation rows was dropped after readers
    moved to canonical. The parameter is retained so callers don't have
    to change.
    """
    if not findings:
        return set()

    now = datetime.now(timezone.utc)

    # ── 1. Resolve each finding's asset to a canonical_id ─────────────────────
    asset_canonical_map = _resolve_asset_canonicals(db, findings)

    # ── 2. Upsert findings_canonical; build {fingerprint key → id} ────────────
    canonical_ids = _upsert_findings_canonical(
        db, findings, asset_canonical_map, now,
        new_ids_out=new_canonical_ids_out,
    )

    # ── 3. Emit has_finding edges: asset_canonical → finding_canonical ────────
    _emit_has_finding_edges(db, canonical_ids, now)

    db.commit()
    return set(canonical_ids.values())


# ── Internal: canonical / edge helpers ────────────────────────────────────────

def _infer_asset_type(value: str) -> str:
    """IPv4/IPv6 literals are ip_address; everything else is dns_record."""
    try:
        ipaddress.ip_address(value)
        return "ip_address"
    except ValueError:
        return "dns_record"


def _fingerprint_for(f: DiscoveredFinding) -> str:
    """Source-specific uniqueness key for findings_canonical.

      - explicit detail.fingerprint, when a producer pins one (e.g. the
        exposure analyzer's port-stable exposed-service:{port})
      - cve_id, when present (Shodan CVEs, Nuclei CVE templates)
      - detail.shodan_tag for Shodan classification findings
      - detail.template_id for Nuclei (non-CVE) findings
      - finding_type + title as a last-resort fallback
    """
    detail = f.detail or {}
    if detail.get("fingerprint"):
        return str(detail["fingerprint"])

    if f.cve_id:
        return f.cve_id

    if f.source == "shodan" and detail.get("shodan_tag"):
        return str(detail["shodan_tag"])

    nuclei_tags: list[str] = detail.get("tags", []) if detail else []
    cve_id = extract_cve_id(nuclei_tags, detail.get("template_id", ""))
    if cve_id:
        return cve_id

    template_id = detail.get("template_id")
    if template_id:
        return str(template_id)

    return f"{f.finding_type}:{f.title}"


def _resolve_asset_canonicals(
    db: Session,
    findings: list[DiscoveredFinding],
) -> dict[int, uuid.UUID]:
    """Resolve each finding to its canonical asset id. Returns {id(finding):
    canonical_id} — keyed by object identity, not asset_value, because a
    single batch can contain multiple findings that share the same
    asset_value string but must resolve to different assets (e.g. a
    hostname's A and AAAA dns_record rows). Keying by the string alone would
    silently collapse them onto whichever one happened to resolve last.

    A finding with `asset_id` set is resolved directly from that — the
    producer already holds the specific AssetCanonical row, so there's
    nothing to look up. Everything else falls back to the
    (inferred_type, value) lookup below, matching prior behavior (with a
    fallback to the other asset_type if the inferred one isn't found —
    handles edge cases where Nuclei targets a hostname that exists only as
    a dns_record, etc.)."""
    if not findings:
        return {}

    unresolved = [f for f in findings if f.asset_id is None]
    values = {f.asset_value for f in unresolved}

    by_key: dict[tuple[str, str], uuid.UUID] = {}
    by_value: dict[str, uuid.UUID] = {}
    if values:
        rows = db.query(AssetCanonical.id, AssetCanonical.asset_type, AssetCanonical.value).filter(
            AssetCanonical.value.in_(values)
        ).all()
        # Map by both (type, value) and by value-only (fallback if inferred type misses)
        by_key = {(r.asset_type, r.value): r.id for r in rows}
        for r in rows:
            # Prefer ip_address over dns_record when both exist for the same string
            # (rare — only IP literals can collide, and inference already handles that)
            if r.value not in by_value or r.asset_type == "ip_address":
                by_value[r.value] = r.id

    result: dict[int, uuid.UUID] = {}
    for f in findings:
        if f.asset_id is not None:
            result[id(f)] = f.asset_id
            continue
        atype = _infer_asset_type(f.asset_value)
        canonical_id = by_key.get((atype, f.asset_value)) or by_value.get(f.asset_value)
        if canonical_id:
            result[id(f)] = canonical_id
        else:
            log.debug(
                "No canonical asset for finding on %s (type=%s) — skipping canonical write",
                f.asset_value, atype,
            )
    return result


def _upsert_findings_canonical(
    db: Session,
    findings: list[DiscoveredFinding],
    asset_canonical_map: dict[int, uuid.UUID],
    now: datetime,
    new_ids_out: list[uuid.UUID] | None = None,
) -> dict[tuple, uuid.UUID]:
    """Upsert one canonical row per (asset, finding_type, source, fingerprint).
    Returns {(asset_canonical_id, finding_type, source, fingerprint): id}.

    If new_ids_out is provided, append the ids of any rows we inserted (i.e.
    truly-new findings, not re-observations) to it. Used by the notification
    dispatcher to fire only on first-time inserts.
    """
    unique: dict[tuple, DiscoveredFinding] = {}
    fingerprint_for_finding: dict[id, str] = {}
    for f in findings:
        asset_id = asset_canonical_map.get(id(f))
        if not asset_id:
            continue
        fp = _fingerprint_for(f)
        fingerprint_for_finding[id(f)] = fp
        key = (asset_id, f.finding_type, f.source, fp)
        # Last write wins for in-batch duplicates — same finding observed twice
        # in one phase is fine; we keep the latest payload.
        unique[key] = f

    if not unique:
        return {}

    # FOR UPDATE serializes (blocks, doesn't fail) any concurrent writer
    # touching the same rows — planning#86: without it, two concurrent
    # enrichers read-modify-writing the same row (e.g. severity refresh vs.
    # reopen-on-resolved) can lose one side's update.
    existing_rows = (
        db.query(FindingCanonical)
        .filter(
            tuple_(
                FindingCanonical.asset_canonical_id,
                FindingCanonical.finding_type,
                FindingCanonical.source,
                FindingCanonical.fingerprint,
            ).in_(list(unique.keys()))
        )
        .with_for_update()
        .all()
    )
    existing_map = {
        (r.asset_canonical_id, r.finding_type, r.source, r.fingerprint): r
        for r in existing_rows
    }

    finding_rules = (
        db.query(TagRule)
        .filter(TagRule.entity_type == "finding", TagRule.enabled == True)  # noqa: E712
        .all()
    )

    # Build rows for keys not seen above, but insert defensively (ON
    # CONFLICT DO NOTHING) rather than a plain bulk insert — a concurrent
    # transaction may insert the same (asset, finding_type, source,
    # fingerprint) key between our SELECT and our INSERT, and a plain
    # INSERT would raise IntegrityError and abort the whole batch.
    to_insert: dict[tuple, FindingCanonical] = {}
    for key, f in unique.items():
        if key in existing_map:
            continue
        asset_id, finding_type, source, fingerprint = key
        nuclei_tags: list[str] = f.detail.get("tags", []) if f.detail else []
        template_id: str = f.detail.get("template_id", "") if f.detail else ""
        cve_id = f.cve_id or extract_cve_id(nuclei_tags, template_id)
        category = "cve" if cve_id else (f.category or categorize(nuclei_tags))
        new_row = FindingCanonical(
            id=uuid.uuid4(),
            asset_canonical_id=asset_id,
            finding_type=finding_type,
            source=source,
            fingerprint=fingerprint,
            severity=f.severity,
            title=f.title,
            description=f.description,
            detail=f.detail or {},
            state="open",
            category=category,
            cve_id=cve_id,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            cvss_version=f.cvss_version,
            cwe=f.cwe,
            first_seen_at=now,
            last_seen_at=now,
        )
        if finding_rules:
            new_row.tags = merge_tags([], apply_rules_preloaded(finding_rules, new_row))
        to_insert[key] = new_row

    result: dict[tuple, uuid.UUID] = {}
    if to_insert:
        inserted_ids = _defensive_insert_findings(db, list(to_insert.values()))
        for key, new_row in to_insert.items():
            if key in inserted_ids:
                result[key] = inserted_ids[key]
                if new_ids_out is not None:
                    new_ids_out.append(inserted_ids[key])
                continue
            # Lost the race — a concurrent transaction inserted this finding
            # first. Re-fetch it locked and fold our observation into it via
            # the merge loop below instead of losing our data or raising.
            asset_id, finding_type, source, fingerprint = key
            locked = (
                db.query(FindingCanonical)
                .filter(
                    FindingCanonical.asset_canonical_id == asset_id,
                    FindingCanonical.finding_type == finding_type,
                    FindingCanonical.source == source,
                    FindingCanonical.fingerprint == fingerprint,
                )
                .with_for_update()
                .first()
            )
            if locked is not None:
                existing_map[key] = locked

    for key, f in unique.items():
        if key not in existing_map:
            continue
        row = existing_map[key]
        nuclei_tags: list[str] = f.detail.get("tags", []) if f.detail else []
        template_id: str = f.detail.get("template_id", "") if f.detail else ""
        cve_id = f.cve_id or extract_cve_id(nuclei_tags, template_id)
        category = "cve" if cve_id else (f.category or categorize(nuclei_tags))

        row.last_seen_at = now
        # Refresh fields that may have updated since first observation
        if f.severity and f.severity != row.severity:
            row.severity = f.severity
        if f.title:
            row.title = f.title
        if f.description is not None:
            row.description = f.description
        if f.detail:
            row.detail = f.detail
        if f.cvss_score is not None:
            row.cvss_score = f.cvss_score
        if f.cvss_vector is not None:
            row.cvss_vector = f.cvss_vector
        if f.cvss_version is not None:
            row.cvss_version = f.cvss_version
        if f.cwe is not None:
            row.cwe = f.cwe
        if cve_id and not row.cve_id:
            row.cve_id = cve_id
        if category and not row.category:
            row.category = category
        # If a previously resolved finding is observed again, reopen it
        if row.state == "resolved":
            row.state = "open"
            row.resolved_at = None
        result[key] = row.id

    # Flush so subsequent edge inserts see the new canonical rows — the
    # polymorphic-FK trigger queries them by id.
    db.flush()
    return result


def _defensive_insert_findings(
    db: Session,
    new_rows: list[FindingCanonical],
) -> dict[tuple, uuid.UUID]:
    """INSERT new finding rows with ON CONFLICT DO NOTHING against
    findings_canonical's single named unique constraint. Returns
    {(asset_canonical_id, finding_type, source, fingerprint): id} for rows
    actually inserted — any row NOT in the returned dict lost a race to a
    concurrent transaction inserting the same key; the caller re-fetches it.
    """
    if not new_rows:
        return {}

    stmt = (
        pg_insert(FindingCanonical.__table__)
        .values([_finding_row_values(r) for r in new_rows])
        .on_conflict_do_nothing(constraint="uq_findings_canonical_fingerprint")
        .returning(
            FindingCanonical.id,
            FindingCanonical.asset_canonical_id,
            FindingCanonical.finding_type,
            FindingCanonical.source,
            FindingCanonical.fingerprint,
        )
    )
    inserted: dict[tuple, uuid.UUID] = {}
    for row in db.execute(stmt):
        inserted[(row.asset_canonical_id, row.finding_type, row.source, row.fingerprint)] = row.id
    return inserted


def _finding_row_values(row: FindingCanonical) -> dict:
    return {
        "id": row.id,
        "asset_canonical_id": row.asset_canonical_id,
        "finding_type": row.finding_type,
        "source": row.source,
        "fingerprint": row.fingerprint,
        "severity": row.severity,
        "title": row.title,
        "description": row.description,
        "detail": row.detail or {},
        "state": row.state,
        "category": row.category,
        "cve_id": row.cve_id,
        "cvss_score": row.cvss_score,
        "cvss_vector": row.cvss_vector,
        "cvss_version": row.cvss_version,
        "cwe": row.cwe,
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
        "tags": row.tags or [],
    }


def _emit_has_finding_edges(
    db: Session,
    canonical_ids: dict[tuple, uuid.UUID],
    now: datetime,
) -> None:
    """Emit one has_finding edge per (asset_canonical → finding_canonical)."""
    if not canonical_ids:
        return

    edges: list[dict] = []
    for (asset_id, _ftype, _source, _fp), finding_id in canonical_ids.items():
        edges.append({
            "source_type": "asset_canonical",
            "source_id": asset_id,
            "target_type": "finding_canonical",
            "target_id": finding_id,
            "edge_type": "has_finding",
            "first_seen_at": now,
            "last_seen_at": now,
        })

    stmt = pg_insert(AssetEdge.__table__).values(edges)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_asset_edges_unique",
        set_={"last_seen_at": now},
    )
    db.execute(stmt)
