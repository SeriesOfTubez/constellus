"""Shared-hosting / datacenter classification — planning#107, epic#81 Phase D.

Two free, keyless, provider-agnostic signals for "is this origin IP the kind
of shared multi-tenant infrastructure where an exposure/CVE finding likely
isn't this org's problem to fix":

  - `classify_ip` — ipapi.is's `is_datacenter`/`company` classification.
    Answers "is this a hosting/datacenter network at all" (vs. residential/
    enterprise-owned) — a cheap pre-filter, NOT a shared-vs-dedicated
    distinction (it can't tell an IONOS shared box from a single-tenant AWS
    EC2 instance; both read as "hosting"). Free tier: 1000 req/day, no key.
    Cached long-term on the ip_address asset itself — this classification is
    very stable (an IP rarely changes which network/ASN owns it).

  - `reverse_ip_domains` — HackerTarget's reverse-IP lookup, returning every
    domain historically observed resolving to this IP. Hundreds of unrelated
    domains is definitionally a shared-hosting signal, regardless of which
    of them are still live today (there's no last-seen date in this data —
    see epic#81 Phase D doc §5.1/§5.2 for why that's fine: liveness gets
    proven separately, by corroborate_liveness's SNI probe, not inferred
    from this list). Free tier is genuinely scarce (~20 lookups/day) — cached
    long-term per-IP and budget-capped so a burst of eligible findings can't
    exhaust the day's quota.

Both fail soft: any error, timeout, or unconfigured state returns an empty/
negative result, never raises. Neither call is spent unless the caller has
already decided the IP is worth the expense (shared_infra_verifier's gate —
not-CDN + Layer 1 already ambiguous — keeps this population small).
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.models.asset_canonical import AssetCanonical
from app.services.claim_emitter import get_current_claim, upsert_single_claim

log = logging.getLogger(__name__)

_IPAPI_URL = "https://api.ipapi.is/"
_HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/"

_HOSTING_CLASS_TTL = timedelta(days=30)
_REVERSE_IP_TTL = timedelta(days=14)

# This module is the "hosting_classifier" observer for both claim types it
# writes (planning#144 L3a) — hosting_class (classify_ip) and reverse_ip
# (reverse_ip_domains): both are TTL caches on the ip_address asset that used
# to live in asset_metadata, now claims. No separate observer exists for the
# reverse-IP lookup; it's the same producer module.
_OBSERVER_NAME = "hosting_classifier"
_HOSTING_CLASS_CLAIM_TYPE = "hosting_class"
_REVERSE_IP_CLAIM_TYPE = "reverse_ip"

# HackerTarget's free tier is ~20 lookups/day. Stay well under it so a burst
# of eligible findings in one scan can't exhaust the day's quota — the rest
# fail soft to "not attempted" and corroboration falls back to Shodan-only
# candidates.
_REVERSE_IP_DAILY_BUDGET = 15
_budget_date: str | None = None
_budget_used = 0


@dataclass
class HostingClass:
    is_datacenter: bool
    company_name: str | None = None
    asn: int | None = None
    # False only when the lookup itself failed/was unattempted (no
    # ip_address asset row, network error, quota exhaustion) — distinct
    # from a genuine "checked, and it's not a datacenter" determination.
    # Callers that cache derived state on top of this (e.g.
    # shared_infra_verifier.classify_ip_ownership) must not treat
    # attempted=False the same as a real is_datacenter=False, or a
    # transient failure gets mislabeled and cached as a stable fact
    # (planning#113 Fable review, finding 2).
    attempted: bool = True


def _get_ip_asset(db: Session, ip: str) -> AssetCanonical | None:
    return (
        db.query(AssetCanonical)
        .filter(AssetCanonical.asset_type == "ip_address", AssetCanonical.value == ip)
        .first()
    )


def classify_ip(db: Session, ip: str) -> HostingClass:
    """Is `ip` a hosting/datacenter network? Cached as a `hosting_class`
    claim on the ip_address asset (planning#144 L3a — moved off
    asset_metadata), long TTL — this rarely changes."""
    asset = _get_ip_asset(db, ip)
    if asset is None:
        return HostingClass(is_datacenter=False, attempted=False)

    claim = get_current_claim(db, asset.id, _OBSERVER_NAME, _HOSTING_CLASS_CLAIM_TYPE)
    if claim is not None:
        age = datetime.now(timezone.utc) - claim.last_observed_at
        if age < _HOSTING_CLASS_TTL:
            cached = claim.claim_value
            return HostingClass(
                is_datacenter=bool(cached.get("is_datacenter")),
                company_name=cached.get("company_name"),
                asn=cached.get("asn"),
            )

    try:
        resp = connector_get(_IPAPI_URL, params={"q": ip}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        log.debug("hosting_classifier: ipapi.is lookup failed for %s", ip, exc_info=True)
        return HostingClass(is_datacenter=False, attempted=False)

    result = HostingClass(
        is_datacenter=bool(data.get("is_datacenter")),
        company_name=(data.get("company") or {}).get("name"),
        asn=(data.get("asn") or {}).get("asn"),
    )

    now = datetime.now(timezone.utc)
    upsert_single_claim(
        db, asset.id, _OBSERVER_NAME, _HOSTING_CLASS_CLAIM_TYPE,
        {
            "is_datacenter": result.is_datacenter,
            "company_name": result.company_name,
            "asn": result.asn,
        },
        now,
    )
    db.commit()
    return result


def reverse_ip_domains(db: Session, ip: str) -> list[str]:
    """Domains historically observed resolving to `ip` (HackerTarget).
    Cached as a `reverse_ip` claim on the ip_address asset (planning#144
    L3a — moved off asset_metadata), long TTL. Returns [] on any failure,
    budget exhaustion, or unconfigured state — never raises; callers already
    treat an empty candidate list as "couldn't corroborate via this
    source." Signature unchanged — origin_corroboration.py calls this."""
    asset = _get_ip_asset(db, ip)
    if asset is None:
        return []

    claim = get_current_claim(db, asset.id, _OBSERVER_NAME, _REVERSE_IP_CLAIM_TYPE)
    if claim is not None:
        age = datetime.now(timezone.utc) - claim.last_observed_at
        if age < _REVERSE_IP_TTL:
            cached = claim.claim_value.get("domains")
            if isinstance(cached, list):
                return list(cached)

    if not _spend_reverse_ip_budget():
        log.info("hosting_classifier: reverse-IP daily budget exhausted, skipping %s", ip)
        return []

    try:
        resp = connector_get(_HACKERTARGET_URL, params={"q": ip}, timeout=15)
        resp.raise_for_status()
        text = resp.text.strip()
    except Exception:
        log.debug("hosting_classifier: HackerTarget lookup failed for %s", ip, exc_info=True)
        return []

    # HackerTarget returns plain-text errors (e.g. "API count exceeded...")
    # with no distinguishing status code — a line with a space is never a
    # bare domain, so this cheaply filters those out without over-fitting
    # to a specific error string.
    domains = [line for line in text.splitlines() if line and " " not in line]

    now = datetime.now(timezone.utc)
    upsert_single_claim(db, asset.id, _OBSERVER_NAME, _REVERSE_IP_CLAIM_TYPE, {"domains": domains}, now)
    db.commit()
    return domains


def _spend_reverse_ip_budget() -> bool:
    """True and decrements the daily budget if any remains; False if
    today's quota is already spent. Process-local (in-memory), resets on
    date change — matches the module-level cache convention used elsewhere
    (cve_enrichment._kev_cache, vulncheck_enrichment._cache)."""
    global _budget_date, _budget_used
    today = datetime.now(timezone.utc).date().isoformat()
    if _budget_date != today:
        _budget_date = today
        _budget_used = 0
    if _budget_used >= _REVERSE_IP_DAILY_BUDGET:
        return False
    _budget_used += 1
    return True
