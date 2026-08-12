"""Takeover fingerprint layer — planning#104, epic#81 Phase B Layer 2.

The classic CNAME -> SaaS subdomain-takeover case, detected by nuclei's
`takeover` template tag. Nuclei already runs these templates on every scan
(`takeover` is in nuclei_tag_filter.BASELINE_TAGS — unconditionally included,
no scan-config change needed here). This module's job is entirely downstream:
find the resulting takeover-tagged findings and surface them as the
high-confidence signal that Layer 4 (dangling_dns_analyzer, planning#105)
promotes into a High-severity dangling_dns finding.

Deliberately narrow: this is the ONLY detector Phase B trusts for the
CDN/SaaS-CNAME path (absence of domain-affinity on a shared edge is normal,
so only a fingerprint signature is conclusive there — see the epic's
"affinity decision model").
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.finding_canonical import FindingCanonical

_TAKEOVER_TAG = "takeover"
_NUCLEI_SOURCE = "nuclei"


def find_takeover_signal(db: Session, asset_id: uuid.UUID, since: datetime) -> dict[str, Any] | None:
    """Return the strongest takeover signal on `asset_id`, or None.

    Scoped to nuclei findings freshly observed this run (last_seen_at >=
    since) — mirrors exposure_analyzer's freshness gate so a stale takeover
    tag from weeks ago (nuclei didn't re-confirm it) doesn't indefinitely
    drive a High finding on its own.
    """
    rows = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.asset_canonical_id == asset_id,
            FindingCanonical.source == _NUCLEI_SOURCE,
            FindingCanonical.last_seen_at >= since,
        )
        .all()
    )

    for row in rows:
        detail = row.detail or {}
        tags = detail.get("tags") or []
        if _TAKEOVER_TAG not in tags:
            continue
        return {
            "finding_id": row.id,
            "template_id": detail.get("template_id"),
            "title": row.title,
            "matched_at": detail.get("matched_at"),
        }

    return None
