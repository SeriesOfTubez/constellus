"""
Certificate Transparency log enumeration.

Queries multiple CT log aggregators in parallel:
  - crt.sh  (sslmate mirror of all public CT logs)
  - certspotter  (SSLMate API, free tier, 100 req/hr)

Each source is attempted independently with retry/backoff. If one is down the
other still runs, so a single outage doesn't silently produce empty results.
"""

import logging
import re
import time
from typing import Callable

import httpx

from app.connectors.base import DiscoveredAsset, PhaseResult
from app.models.asset import AssetType

log = logging.getLogger(__name__)

_HOSTNAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def run(domain: str) -> PhaseResult:
    """Query all CT sources and merge results."""
    seen: set[str] = set()
    assets: list[DiscoveredAsset] = []

    for source_fn in (_query_crtsh, _query_certspotter):
        try:
            result = source_fn(domain)
            for a in result.assets:
                if a.value not in seen:
                    seen.add(a.value)
                    assets.append(a)
        except Exception:
            log.exception("CT source %s failed for %s", source_fn.__name__, domain)

    log.info("CT logs: %d unique subdomains for %s", len(assets), domain)
    return PhaseResult(assets=assets)


# ── crt.sh ────────────────────────────────────────────────────────────────────

def _query_crtsh(domain: str) -> PhaseResult:
    def attempt() -> list[dict]:
        resp = httpx.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=30,
            headers={"Accept": "application/json"},
            follow_redirects=True,
        )
        resp.raise_for_status()
        return resp.json()

    certs = _with_retry(attempt, retries=3, backoff=5, source="crt.sh")
    if certs is None:
        return PhaseResult()

    assets = []
    seen: set[str] = set()
    for cert in certs:
        for name in cert.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.").lower()
            if _valid_subdomain(name, domain) and name not in seen:
                seen.add(name)
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.DNS_RECORD,
                    value=name,
                    parent_value=domain if name != domain else None,
                    asset_metadata={
                        "sources": ["crt.sh"],
                        "issuer": cert.get("issuer_name", ""),
                        "not_before": cert.get("not_before", ""),
                        "not_after": cert.get("not_after", ""),
                    },
                ))

    log.info("crt.sh: %d subdomains for %s", len(assets), domain)
    return PhaseResult(assets=assets)


# ── certspotter ───────────────────────────────────────────────────────────────

def _query_certspotter(domain: str) -> PhaseResult:
    """
    SSLMate certspotter API — free tier, 100 req/hr, no auth required.
    https://certspotter.com/api/v1/issuances
    """
    def attempt() -> list[dict]:
        resp = httpx.get(
            "https://api.certspotter.com/v1/issuances",
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            timeout=30,
            headers={"Accept": "application/json"},
            follow_redirects=True,
        )
        resp.raise_for_status()
        return resp.json()

    issuances = _with_retry(attempt, retries=3, backoff=5, source="certspotter")
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
                        "sources": ["certspotter"],
                        "not_before": issuance.get("not_before", ""),
                        "not_after": issuance.get("not_after", ""),
                        "issuer": issuance.get("issuer", {}).get("name", "") if isinstance(issuance.get("issuer"), dict) else "",
                    },
                ))

    log.info("certspotter: %d subdomains for %s", len(assets), domain)
    return PhaseResult(assets=assets)


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
    if not name:
        return False
    if name != domain and not name.endswith(f".{domain}"):
        return False
    return bool(_HOSTNAME_RE.match(name))
