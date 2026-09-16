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
    very stable (an IP rarely changes which network/ASN owns it). As of
    2026-09-15 the keyless free tier no longer returns `is_datacenter` at
    all, so in production this lookup now always reports `attempted=False`;
    planning#178 replaces the data source.

  - `reverse_ip_domains` — mnemonic passive DNS (planning#180), returning the
    domains observed resolving to this IP. Many unrelated domains is
    definitionally a shared-hosting signal.

    This replaced HackerTarget, which was keyless but capped at ~20
    lookups/day. mnemonic is also keyless and allows 1000/day + 10/min, and
    it returns something HackerTarget structurally could not: per-record
    `firstSeenTimestamp` / `lastSeenTimestamp`.

    Those dates retire a workaround rather than porting it. The old docstring
    argued the absence of a last-seen date was fine because liveness is proven
    separately (epic#81 Phase D §5.1/§5.2, corroborate_liveness's SNI probe).
    That reasoning stands for *liveness*, but it left "shared" unable to
    distinguish an IP serving 200 domains today from a recycled address whose
    200 domains were all last seen in 2019. With dates we separate CURRENTLY
    shared from HISTORICALLY shared, and the claim records which (`sharing`).
    scanme.nmap.org's host is the worked example: 7 domains total, none seen
    in the last year.

Both fail soft: any error, timeout, or unconfigured state returns an empty/
negative result, never raises. Neither call is spent unless the caller has
already decided the IP is worth the expense (shared_infra_verifier's gate —
not-CDN + Layer 1 already ambiguous — keeps this population small).
"""

import logging
import re
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.models.asset_canonical import AssetCanonical
from app.services.claim_emitter import get_current_claim, upsert_single_claim

log = logging.getLogger(__name__)

_IPAPI_URL = "https://api.ipapi.is/"
_MNEMONIC_URL = "https://api.mnemonic.no/pdns/v3/"

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

# mnemonic's published limits for unauthenticated use are 10 requests/minute
# and 1000/day. planning#180 commits us to honouring BOTH in code rather than
# just documenting them, so keep headroom under each: an overrun is how a free
# public service stops being available to everyone.
_MNEMONIC_PER_MINUTE = 8
_MNEMONIC_PER_DAY = 900
_minute_calls: deque[float] = deque()
_budget_date: str | None = None
_budget_used = 0

# Above this many domains an IP is shared infrastructure, and which particular
# domains they are stops being informative. Deliberately well below the
# "hundreds" the shared-hosting case looks like, and above the handful a
# dedicated host accumulates from its own aliases.
_SHARED_DOMAIN_THRESHOLD = 25

# A record not seen within this window is history, not current tenancy. This
# is the distinction HackerTarget could not express at all.
_ACTIVE_WINDOW = timedelta(days=365)

# Cap on domains pulled in one request. The response carries the true total in
# `count` regardless, so truncating the list never distorts the verdict.
_MAX_DOMAINS = 100


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


def _company_name(value) -> str | None:
    """ipapi.is free tier returns `company` as a bare string (planning#177)."""
    return value if isinstance(value, str) and value else None


def _asn_number(value) -> int | None:
    """Free tier returns `asn` as a display string — "AS63949 Akamai
    Technologies, Inc." — so pull the leading AS number out of it. The org
    name trailing it is deliberately ignored: it is not always the same as
    `company`, and reconciling the two is out of scope (planning#177)."""
    if not isinstance(value, str):
        return None
    match = re.match(r"\s*AS(\d+)", value)
    return int(match.group(1)) if match else None


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

    # The free tier (no API key — which is all we have) dropped
    # `is_datacenter` entirely, and the parse used to sit outside the guard
    # above, so a vendor schema change escaped as an AttributeError instead
    # of the fail-soft this function already implements (planning#177).
    #
    # Absent is NOT False. Without this field the lookup cannot answer the
    # question it exists to answer, so it is an unattempted lookup — which
    # is what `attempted=False` means, and what stops the caller caching it
    # (shared_infra_verifier.py, planning#113 Fable review finding 2).
    # Defaulting it to False instead is exactly what made a broken
    # dependency read as a policy denial in `authorisation_decisions`.
    # planning#178 replaces this data source.
    if not isinstance(data, dict) or "is_datacenter" not in data:
        log.warning(
            "hosting_classifier: ipapi.is returned an unusable schema for %s "
            "(no is_datacenter; keys=%s) — treating as an unattempted lookup, "
            "not a negative (planning#177)",
            ip,
            sorted(data) if isinstance(data, dict) else type(data).__name__,
        )
        return HostingClass(is_datacenter=False, attempted=False)

    try:
        result = HostingClass(
            is_datacenter=bool(data["is_datacenter"]),
            company_name=_company_name(data.get("company")),
            asn=_asn_number(data.get("asn")),
        )
    except Exception:
        log.warning(
            "hosting_classifier: could not parse ipapi.is response for %s "
            "(keys=%s) — unattempted, not a negative (planning#177)",
            ip, sorted(data), exc_info=True,
        )
        return HostingClass(is_datacenter=False, attempted=False)

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
    """Domains observed resolving to `ip` (mnemonic passive DNS, planning#180).

    Cached as a `reverse_ip` claim on the ip_address asset (planning#144
    L3a — moved off asset_metadata), long TTL. Returns [] on any failure,
    budget exhaustion, or unconfigured state — never raises; callers already
    treat an empty candidate list as "couldn't corroborate via this
    source." Signature unchanged — origin_corroboration.py calls this.

    The return value stays a plain list of domain names, but the claim it
    writes carries more than that, so a consumer wanting the shared-hosting
    verdict reads the claim instead of calling this and spends no quota:

        count         total domains on the address, per mnemonic, even when
                      the fetched page was truncated
        domains       the fetched names (<= _MAX_DOMAINS)
        records       per-domain first_seen / last_seen, ISO-8601
        active_count  how many were seen within _ACTIVE_WINDOW
        truncated     whether count exceeds len(domains)
        sharing       dedicated | shared | historically_shared | unknown

    `sharing` is the point of the migration: see _sharing_verdict.
    """
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
        log.info("hosting_classifier: mnemonic budget exhausted, skipping %s", ip)
        return []

    # One request, not two. planning#180 proposes `limit=1` + the top-level
    # `count` as a quota trick, and it is the right call for a consumer that
    # only wants the shared-vs-dedicated verdict. Ours wants the domains too
    # (origin_corroboration probes them as corroboration candidates), and the
    # same response carries `count` whether limit is 1 or 100 — so asking for
    # the page up front costs exactly one call and yields both. A consumer that
    # needs only the verdict reads it off the cached claim and spends nothing.
    try:
        resp = connector_get(
            f"{_MNEMONIC_URL}{ip}", params={"limit": _MAX_DOMAINS}, timeout=15
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception:
        log.debug("hosting_classifier: mnemonic lookup failed for %s", ip, exc_info=True)
        return []

    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        log.warning(
            "hosting_classifier: mnemonic returned an unusable schema for %s (keys=%s) "
            "— treating as unattempted, not as 'no domains' (planning#177's lesson)",
            ip, sorted(payload) if isinstance(payload, dict) else type(payload).__name__,
        )
        return []

    now = datetime.now(timezone.utc)
    records = _parse_pdns_records(payload["data"], ip)
    domains = [r["domain"] for r in records]

    # `count` is the authoritative total even when the page is truncated, so
    # the verdict is never distorted by _MAX_DOMAINS.
    total = payload.get("count")
    if not isinstance(total, int) or total < 0:
        total = len(domains)

    active = [r for r in records if _is_active(r["last_seen"], now)]
    truncated = total > len(domains)

    claim_value = {
        "source": "mnemonic",
        "count": total,
        "domains": domains,
        "records": records,
        # Over the fetched page only — a lower bound when `truncated`. See
        # _sharing_verdict, which is why that distinction is load-bearing.
        "active_count": len(active),
        "truncated": truncated,
        "sharing": _sharing_verdict(total, len(active), truncated),
    }
    upsert_single_claim(db, asset.id, _OBSERVER_NAME, _REVERSE_IP_CLAIM_TYPE, claim_value, now)
    db.commit()
    return domains


def _parse_pdns_records(data: list, ip: str) -> list[dict]:
    """Forward A/AAAA records whose answer is `ip`, as {domain, first_seen, last_seen}.

    Filtered on rrtype and answer rather than trusted wholesale: the endpoint
    answers "what is known about this address", which can include records where
    the address is the query rather than the answer, and those are not domains
    hosted here.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for rec in data:
        if not isinstance(rec, dict):
            continue
        if str(rec.get("rrtype", "")).lower() not in ("a", "aaaa"):
            continue
        if rec.get("answer") != ip:
            continue
        domain = rec.get("query")
        if not isinstance(domain, str) or not domain or domain in seen:
            continue
        seen.add(domain)
        out.append({
            "domain": domain,
            "first_seen": _epoch_ms(rec.get("firstSeenTimestamp")),
            "last_seen": _epoch_ms(rec.get("lastSeenTimestamp")),
        })
    return out


def _epoch_ms(value) -> str | None:
    """mnemonic's timestamps are epoch milliseconds; store them as ISO-8601."""
    if not isinstance(value, (int, float)) or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _is_active(last_seen: str | None, now: datetime) -> bool:
    if not last_seen:
        return False
    try:
        return (now - datetime.fromisoformat(last_seen)) <= _ACTIVE_WINDOW
    except ValueError:
        return False


def _sharing_verdict(total: int, active_count: int, truncated: bool) -> str:
    """currently shared vs historically shared vs dedicated.

    `historically_shared` is the value this data source exists to make
    possible: an address with 200 domains that have not resolved here in years
    is a recycled address, not a live shared host, and treating it as shared
    infrastructure would wrongly reject findings that really are the
    customer's.

    But it is an assertion that ALL the sharing is old, and that can only be
    made from a complete view. `active_count` is computed over the fetched page
    only, so on a truncated response it is a LOWER BOUND, not a measurement —
    the unseen records could all be current. Live check that caught this:
    a major CDN's anycast address returned count=332, of which we fetch 100,
    of which 6 were active — which read as `historically_shared` for about the
    most heavily shared kind of address there is.

    So when the page is truncated we refuse the historical claim and call it
    shared. That is the safe direction: mistaking live shared infra for a
    recycled address produces FALSE ATTRIBUTION — blaming a customer for
    someone else's box — which is the failure mode this product cannot afford.
    The reverse error only costs us a finding we declined to attribute.
    """
    if total <= 0:
        return "unknown"
    if active_count > _SHARED_DOMAIN_THRESHOLD:
        return "shared"
    if total <= _SHARED_DOMAIN_THRESHOLD:
        return "dedicated"
    if truncated:
        return "shared"
    return "historically_shared"


def _spend_reverse_ip_budget() -> bool:
    """True (and spends one call) if BOTH of mnemonic's published limits allow
    it; False otherwise.

    Two windows, because satisfying only the daily cap would still let a burst
    of eligible findings in one scan blow straight through 10/min:
      - per-day: a counter that resets on UTC date change.
      - per-minute: a sliding window of call timestamps, trimmed on each call.

    Process-local, matching the module-level cache convention used elsewhere
    (cve_enrichment._kev_cache, vulncheck_enrichment._cache). Note the
    consequence: N worker processes enforce N times the limit between them.
    That was equally true of the HackerTarget budget this replaces, and the
    real fix is the background enricher of planning#181, which gives this one
    owner instead of one per process.
    """
    global _budget_date, _budget_used
    today = datetime.now(timezone.utc).date().isoformat()
    if _budget_date != today:
        _budget_date = today
        _budget_used = 0
    if _budget_used >= _MNEMONIC_PER_DAY:
        return False

    tick = time.monotonic()
    while _minute_calls and tick - _minute_calls[0] >= 60.0:
        _minute_calls.popleft()
    if len(_minute_calls) >= _MNEMONIC_PER_MINUTE:
        return False

    _minute_calls.append(tick)
    _budget_used += 1
    return True
