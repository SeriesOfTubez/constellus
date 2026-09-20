"""Shared-hosting / datacenter classification — planning#107, epic#81 Phase D.

Two free, keyless, provider-agnostic signals for "is this origin IP the kind
of shared multi-tenant infrastructure where an exposure/CVE finding likely
isn't this org's problem to fix":

  - `classify_ip` answers "is this address provider-run hosting
    infrastructure, and whose", from the local `cloud_ranges` mirror
    (planning#179) — no network call. It is NOT a shared-vs-dedicated
    distinction: it cannot tell an IONOS shared box from a single-tenant
    EC2 instance, and deliberately does not try.

    The coverage is deliberately narrower than a third-party "is this a
    datacenter" boolean, and that is a trade, not an oversight — say so
    here so nobody closes the gap by wiring one back in (planning#188).
    `cloud_ranges` covers ten cloud/CDN providers, so single-tenant hosting
    outside them — **OVH, Hetzner, IONOS** — reads as "not in a provider
    range" rather than as hosting. That is safe in this direction and only
    this one: Phase D's branch only ever NARROWS `unverified` ->
    `ownership_unverifiable`, so a miss falls back to `unverified` and we
    decline to escalate, never wrongly escalate. The fix for the gap is
    more feed coverage — geofeed discovery (planning#179) is the long-tail
    path — not another vendor boolean we cannot audit, version or pin.

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
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.models.asset_canonical import AssetCanonical
from app.services import cloud_ranges
from app.services.claim_emitter import get_current_claim, upsert_single_claim

log = logging.getLogger(__name__)

_MNEMONIC_URL = "https://api.mnemonic.no/pdns/v3/"

_REVERSE_IP_TTL = timedelta(days=14)

# This module is the "hosting_classifier" observer for both claim types it
# writes (planning#144 L3a) — hosting_class (classify_ip) and reverse_ip
# (reverse_ip_domains). reverse_ip is a TTL cache on the ip_address asset
# that used to live in asset_metadata, now a claim. hosting_class is NOT a
# TTL cache (planning#188) — classify_ip always computes fresh from the
# local cloud_ranges mirror and still writes the claim, because it's cheaper
# than the read that would amortise it and because a TTL would mask a daily
# dataset refresh. No separate observer exists for the reverse-IP lookup;
# it's the same producer module.
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
    provider: str | None = None
    service_class: str | None = None
    prefix: str | None = None
    # False only when the lookup could not be made at all — no ip_address
    # asset row, or no cloud_ranges dataset loaded. Distinct from a genuine
    # "checked, and this address is in no provider range" determination.
    #
    # planning#188 changed what this distinction is ABOUT, and the change
    # matters to callers. Under the retired third-party lookup it meant "the
    # HTTP call failed" — per-IP and transient. The source is now a local
    # indexed query, so it means "no dataset is loaded" — per-run and
    # systemic, the same distinction tenancy_enricher.tick() draws (an
    # unenriched asset has NO claim; an enriched one with no answer has a
    # claim saying so). Callers
    # that cache derived state on top of this (shared_infra_verifier.
    # classify_ip_ownership) must still not treat attempted=False as a real
    # is_datacenter=False — reporting our own outage as a determination
    # about the asset is the failure planning#177/#181 both landed on.
    attempted: bool = True


def _get_ip_asset(db: Session, ip: str) -> AssetCanonical | None:
    return (
        db.query(AssetCanonical)
        .filter(AssetCanonical.asset_type == "ip_address", AssetCanonical.value == ip)
        .first()
    )


def hosting_for_match(match: "cloud_ranges.CloudRangeMatch | None") -> HostingClass:
    """Pure mapping from a `cloud_ranges.lookup` result to a HostingClass.
    No DB access — test this directly.

    ⚠ The polarity here is NOT the same as tenancy_enricher's, and the two
    live one import apart, so read this before "simplifying" one into the
    other. `tenancy_for_match` maps service_class 'compute' to
    SINGLE_TENANT. `is_datacenter` asks a different question and wants the
    opposite answer: its only consumer (shared_infra_verifier's Phase D
    branch) reads True as "provider-run infrastructure — do not attribute a
    finding here to the org without corroboration". A 'compute' prefix is
    exactly that. Wiring is_datacenter = (service_class == 'compute') would
    invert the branch: it would demand corroboration for the addresses most
    likely to be genuinely the org's own, and skip it for the shared
    edge/managed space the check exists to catch.

    So ANY match is a datacenter, whatever the service_class — that is the
    question the retired third-party boolean was actually being asked
    (planning#188). On today's dataset 'compute' is 11,639 prefixes of
    which ~62% are
    Linode/DigitalOcean/Vultr VPS space: single-tenant instances on heavily
    recycled addresses, which is precisely the false-attribution population
    Phase D exists to catch. service_class rides along as evidence, recorded
    on the verdict and never branched on.
    """
    if match is None:
        return HostingClass(is_datacenter=False)
    return HostingClass(
        is_datacenter=True,
        provider=match.provider,
        service_class=match.service_class,
        prefix=match.prefix,
    )


def classify_ip(db: Session, ip: str) -> HostingClass:
    """Is `ip` inside a known cloud/CDN provider range? Local lookup against
    the `cloud_ranges` mirror (planning#188) — no outbound call.

    Recorded as a `hosting_class` claim on the ip_address asset (planning#144
    L3a). The claim is NOT a read-through cache: planning#179's source is an
    indexed inet containment query, cheaper than the claim read that would
    amortise it, and a 30-day TTL would mask a daily dataset refresh — and
    the coverage improvements geofeed discovery is meant to deliver — for a
    month. It is written because `projector.py` projects it into
    `AssetState.hosting`, and because it pins the dataset digest the verdict
    was made against.
    """
    asset = _get_ip_asset(db, ip)
    if asset is None:
        return HostingClass(is_datacenter=False, attempted=False)

    # Mirrors tenancy_enricher.tick()'s guard verbatim in intent: no dataset
    # is our outage, not a fact about the address. Reporting it as
    # is_datacenter=False would be the #177 mistake in a new place — a
    # broken dependency reading as a normal negative determination.
    state = cloud_ranges.dataset_state(db)
    if state is None:
        log.warning(
            "hosting_classifier: no cloud range dataset loaded — reporting %s "
            "as an unattempted lookup, not as 'not a datacenter' (planning#188)",
            ip,
        )
        return HostingClass(is_datacenter=False, attempted=False)
    if state.stale:
        log.warning(
            "hosting_classifier: cloud range dataset generated_at=%s is older "
            "than %s — classifying anyway, but the claim records that "
            "generated_at so the decision stays reconstructable",
            state.generated_at, cloud_ranges.STALE_AFTER,
        )

    try:
        match = cloud_ranges.lookup(db, ip)
        result = hosting_for_match(match)
        now = datetime.now(timezone.utc)
        upsert_single_claim(
            db, asset.id, _OBSERVER_NAME, _HOSTING_CLASS_CLAIM_TYPE,
            {
                "is_datacenter": result.is_datacenter,
                "provider": result.provider,
                "service_class": result.service_class,
                "prefix": result.prefix,
                # Pinned so a past attribution decision stays reconstructable,
                # the same provenance tenancy claims carry (SCHEMA.md).
                "dataset_sha256": state.dataset_sha256,
                "dataset_generated_at": state.generated_at.isoformat(),
            },
            now,
        )
        db.commit()
    except Exception:
        # The module's fail-soft contract: never raise into a scan path.
        db.rollback()
        log.warning("hosting_classifier: cloud_ranges lookup failed for %s", ip, exc_info=True)
        return HostingClass(is_datacenter=False, attempted=False)

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
