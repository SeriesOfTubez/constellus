"""
Certificate Transparency log enumeration.

Uses SSLMate's Certspotter API. Rate-limited heavily on the free tier
(100 req/hr unauthenticated, 1000 req/hr with a free API token), so we
treat CT as a **background-refreshed resource**, not an inline scan step:

  - ct_query_cache holds the most recent issuance payload per domain.
  - app.services.ct_refresher fires every minute, picks the oldest /
    missing entries, and refreshes them at the allowed rate.
  - `run(domain)` reads cache only. It never hits the network, so a
    monitoring run across many targets is bounded by IO on cached
    payloads — not by Certspotter's rate limit.
  - `run(domain, allow_network=True)` opts a single foreground call back
    in — used by initial-discovery for newly-added targets so the user
    sees CT data immediately rather than waiting for the next refresher
    tick.

Set CERTSPOTTER_API_TOKEN in the environment (free signup at
https://sslmate.com/signup?for=certspotter_api) to raise the rate limit.
"""

import logging
import re
import time
from datetime import datetime, timezone
from typing import Callable

import httpx

from app.connectors.base import DiscoveredAsset, PhaseResult
from app.core.database import SessionLocal
from app.core.secrets import get_secret
from app.models.asset import AssetType
from app.models.ct_query_cache import CTQueryCache

log = logging.getLogger(__name__)

_HOSTNAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

SUCCESS_TTL_SECONDS = 6 * 3600   # 6 h — a daily monitoring tick + buffer
FAILURE_TTL_SECONDS = 30 * 60    # 30 min — back off without permanently hiding the target


def run(domain: str, owned_domains: frozenset[str]) -> PhaseResult:
    """Return CT-derived assets for `domain` from the local cache.

    Cache-only — never blocks on the Certspotter API. The refresher fills
    the cache in the background, and the target-add hook calls
    prime_cache() once for newly added targets so they have CT data
    available on their first scan.
    """
    bare_assets: list[DiscoveredAsset] = []
    try:
        result = _query_certspotter(domain, allow_network=False)
        bare_assets = result.assets
    except Exception:
        log.exception("Certspotter failed for %s", domain)

    log.info("CT logs: %d unique subdomains for %s", len(bare_assets), domain)

    # Resolve each discovered name to its current DNS records — without this step
    # CT-only discovery produces dns_records with empty record_type/content, which
    # downstream IP enrichers (Shodan, WHOIS) can't act on. Bare CT assets are
    # kept so cert issuer / not_before / not_after metadata isn't lost.
    from app.services.discovery.dns_resolve import resolve_names
    resolved_assets = resolve_names(
        names=[a.value for a in bare_assets],
        source="cert_transparency",
        apex=domain,
        owned_domains=owned_domains,
    )

    return PhaseResult(assets=bare_assets + resolved_assets)


def prime_cache(domain: str) -> None:
    """Force-fetch the CT payload for one domain and store it in cache.

    Called from the target-add hook so a newly added target has CT data
    available on its first scan rather than after the refresher gets to
    it. Safe to call repeatedly — already-fresh cache entries are reused.
    """
    _fetch_issuances(domain, allow_network=True)


# ── certspotter ───────────────────────────────────────────────────────────────

def _query_certspotter(domain: str, *, allow_network: bool) -> PhaseResult:
    """Read CT issuances for `domain` from cache; optionally fall through
    to the API on miss."""
    issuances = _fetch_issuances(domain, allow_network=allow_network)
    if issuances is None:
        return PhaseResult()

    assets = []
    seen: set[str] = set()
    for issuance in issuances:
        for name in issuance.get("dns_names", []):
            name = name.strip().lstrip("*.").lower()
            if _valid_subdomain(name, domain) and name not in seen:
                seen.add(name)
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.DNS_RECORD,
                    value=name,
                    parent_value=domain if name != domain else None,
                    asset_metadata={
                        "sources": ["cert_transparency"],
                        "ct_source": "certspotter",
                        "not_before": issuance.get("not_before", ""),
                        "not_after": issuance.get("not_after", ""),
                        "issuer": issuance.get("issuer", {}).get("name", "") if isinstance(issuance.get("issuer"), dict) else "",
                    },
                ))

    log.info("certspotter: %d subdomains for %s", len(assets), domain)
    return PhaseResult(assets=assets)


def _fetch_issuances(domain: str, *, allow_network: bool) -> list[dict] | None:
    """Return cached issuances if fresh. On miss, call the API only if
    allow_network is True; otherwise return None and log."""
    db = SessionLocal()
    try:
        cached = db.get(CTQueryCache, domain)
        if cached is not None:
            ttl = SUCCESS_TTL_SECONDS if cached.success else FAILURE_TTL_SECONDS
            age = (datetime.now(timezone.utc) - cached.fetched_at).total_seconds()
            if age < ttl:
                log.info(
                    "certspotter: cache hit for %s (age=%ds, success=%s)",
                    domain, int(age), cached.success,
                )
                return cached.payload if cached.success else None

        if not allow_network:
            log.info(
                "certspotter: cache miss for %s — refresher will fill it (skipping live call)",
                domain,
            )
            return None

        return _live_fetch_and_cache(db, domain)
    finally:
        db.close()


def _live_fetch_and_cache(db, domain: str) -> list[dict] | None:
    """Hit the Certspotter API for `domain`, write result to cache, return it."""
    token = get_secret("CERTSPOTTER_API_TOKEN")
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def attempt() -> list[dict]:
        resp = httpx.get(
            "https://api.certspotter.com/v1/issuances",
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            timeout=30,
            headers=headers,
            follow_redirects=True,
        )
        resp.raise_for_status()
        return resp.json()

    issuances = _with_retry(attempt, retries=3, backoff=5, source="certspotter")
    _write_cache(db, domain, issuances, success=issuances is not None)
    return issuances


def _write_cache(db, domain: str, payload, success: bool) -> None:
    now = datetime.now(timezone.utc)
    safe_payload = payload if success and payload is not None else []
    existing = db.get(CTQueryCache, domain)
    if existing:
        existing.payload = safe_payload
        existing.success = success
        existing.fetched_at = now
    else:
        db.add(CTQueryCache(
            domain=domain,
            payload=safe_payload,
            success=success,
            fetched_at=now,
        ))
    db.commit()


# ── helpers ───────────────────────────────────────────────────────────────────

def _with_retry(fn: Callable, retries: int, backoff: int, source: str):
    """Call fn up to `retries` times with linear backoff. Returns None on total failure."""
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return fn()
        except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.NetworkError) as exc:
            last_exc = exc
            if attempt < retries:
                wait = backoff * attempt
                log.warning("%s attempt %d/%d failed (%s), retrying in %ds", source, attempt, retries, exc, wait)
                time.sleep(wait)
            else:
                log.error("%s failed after %d attempts: %s", source, retries, exc)
    return None


def _valid_subdomain(name: str, domain: str) -> bool:
    from app.connectors.base import is_dns_policy_name
    if not name:
        return False
    if name != domain and not name.endswith(f".{domain}"):
        return False
    if is_dns_policy_name(name):
        return False
    return bool(_HOSTNAME_RE.match(name))
