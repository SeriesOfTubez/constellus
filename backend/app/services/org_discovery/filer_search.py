"""Find SEC filers whose 10-K contains a domain (planning#277 S1a).

A pure lookup: no DB writes, no evidence stored, no signal recorded. The
result is a HINT for the person adding an organization ("a 10-K filed
<date> contains \"<domain>\""); they decide which filer, if any, is theirs.
The filer's own ingest after Finish stores everything it reads.

What the response is trusted for, and what it is not:

- CIK and accession are validated by shape and re-built into our own links;
  nothing from the response is ever fetched or followed.
- `display_name` is DISPLAY ONLY: it prefills the organization name in the
  UI and is never matched against anything. (This module reads it from the
  EFTS JSON as a dict key and never passes it anywhere that finds a domain.)
- This module never records a signal; `tests/test_org_discovery_invariants.py`
  asserts it neither imports nor calls `record_signal`.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.org_entity import OrgEntity
from app.services import registrant_link, sec_edgar
from app.services.org_discovery import candidates

log = logging.getLogger(__name__)

MAX_FILERS = 10
MAX_FILINGS_PER_FILER = 3
_CIK_RE = re.compile(r"^\d{10}$")
_ACCESSION_RE = re.compile(r"^\d{10}-\d{2}-\d{6}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CIK_SUFFIX_RE = re.compile(r"\s*\(CIK \d{1,10}\)\s*$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_DISPLAY = 200


@dataclass
class MatchedFiling:
    form: str
    file_date: str
    accession: str


@dataclass
class FilingStats:
    total_filings: int
    first_filing: str | None
    last_filing: str | None
    latest_10k: str | None
    # True when older filings live in paged files whose counts are used but
    # whose rows were not fetched.
    partial: bool


@dataclass
class FilerHit:
    cik: str
    display_name: str | None
    edgar_url: str
    matched_filings: list[MatchedFiling] = field(default_factory=list)
    stats: FilingStats | None = None
    # The existing organization-graph entity with this CIK, if any.
    entity_id: uuid.UUID | None = None


def _clean_date(raw: object) -> str | None:
    if not isinstance(raw, str) or not _DATE_RE.match(raw):
        return None
    try:
        date.fromisoformat(raw)
    except ValueError:
        return None
    return raw


def _clean_display(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    text = _CONTROL_RE.sub(" ", _CIK_SUFFIX_RE.sub("", raw)).strip()
    return text[:_MAX_DISPLAY] or None


def parse_hits(body: bytes) -> dict[str, dict]:
    """`{cik10: {"display_name", "filings": {accession: MatchedFiling}}}` from
    an EFTS body, skipping anything that fails shape validation."""
    data = json.loads(body)
    found: dict[str, dict] = {}
    for hit in (data.get("hits") or {}).get("hits") or []:
        source = hit.get("_source") if isinstance(hit, dict) else None
        if not isinstance(source, dict):
            continue
        accession = source.get("adsh")
        file_date = _clean_date(source.get("file_date"))
        form = source.get("form")
        if not (isinstance(accession, str) and _ACCESSION_RE.match(accession) and file_date and isinstance(form, str)):
            continue
        ciks = source.get("ciks") if isinstance(source.get("ciks"), list) else []
        names = source.get("display_names") if isinstance(source.get("display_names"), list) else []
        for i, raw_cik in enumerate(ciks):
            cik = raw_cik.zfill(10) if isinstance(raw_cik, str) and raw_cik.isdigit() and len(raw_cik) <= 10 else None
            if cik is None or not _CIK_RE.match(cik):
                continue
            entry = found.setdefault(cik, {"display_name": None, "filings": {}})
            if entry["display_name"] is None and len(names) == len(ciks):
                entry["display_name"] = _clean_display(names[i])
            entry["filings"].setdefault(
                accession, MatchedFiling(form=form[:20], file_date=file_date, accession=accession)
            )
    return found


def _stats(cik: str) -> FilingStats | None:
    """Filing stats from the filer's submissions JSON, or None on any
    failure (logged): one unreachable filer must not fail the search."""
    try:
        content, _ct, _at, _url = sec_edgar.fetch_submissions(cik)
        data = json.loads(content)
        facts = registrant_link.summarise_submissions(data)
        filings = data.get("filings") or {}
        recent = filings.get("recent") or {}
        files = [f for f in (filings.get("files") or []) if isinstance(f, dict)]
        total = len(recent.get("form") or [])
        for f in files:
            count = f.get("filingCount")
            if isinstance(count, int) and count > 0:
                total += count
        return FilingStats(
            total_filings=total,
            first_filing=facts.first_filing,
            last_filing=facts.last_filing,
            latest_10k=facts.last_annual_report,
            partial=bool(files),
        )
    except (sec_edgar.SecFetchError, sec_edgar.SecNotFound, ValueError, TypeError, AttributeError) as exc:
        log.warning("filer search: no filing stats for a candidate filer (%s)", type(exc).__name__)
        return None


def search_by_domain(db: Session, domain: str) -> list[FilerHit]:
    """Filers whose 10-K contains `domain`, most recently matching first.
    Raises `CandidateInvalid` for a non-domain and the `sec_edgar` errors
    for an SEC failure (the caller maps them)."""
    domain = candidates.normalise_domain(domain)
    body, _ct, _at, _url = sec_edgar.search_full_text(domain)
    grouped = parse_hits(body)

    ranked = sorted(
        grouped.items(),
        key=lambda kv: max(f.file_date for f in kv[1]["filings"].values()),
        reverse=True,
    )[:MAX_FILERS]
    existing = {
        cik: entity_id
        for cik, entity_id in db.execute(
            select(OrgEntity.cik, OrgEntity.id).where(OrgEntity.cik.in_([cik for cik, _ in ranked]))
        ).all()
    } if ranked else {}

    hits: list[FilerHit] = []
    for cik, entry in ranked:
        filings = sorted(entry["filings"].values(), key=lambda f: (f.file_date, f.accession), reverse=True)
        hits.append(FilerHit(
            cik=cik,
            display_name=entry["display_name"],
            edgar_url=f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}",
            matched_filings=filings[:MAX_FILINGS_PER_FILER],
            stats=_stats(cik),
            entity_id=existing.get(cik),
        ))
    return hits


def describe_match(hit: FilerHit, domain: str) -> list[str]:
    """The "why it matched" lines: a 10-K filed <date> contains "<domain>"."""
    return [f'a {f.form} filed {f.file_date} contains "{domain}"' for f in hit.matched_filings]
