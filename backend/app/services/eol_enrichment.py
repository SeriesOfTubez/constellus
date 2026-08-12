"""EOL enrichment — post-scan identification of end-of-life software.

Reads service_version strings already extracted by the Layer 1 banner-grab
connector from each IP asset's open_ports[] metadata. Normalises them to
known product / version-cycle pairs, queries the endoflife.date public API for
each unique pair, and writes structured eol_services metadata back to the asset.

Assets with at least one confirmed EOL service are auto-tagged eol:{product}.
Responses are cached per-process with a 24 h TTL so repeated scans don't
hammer the API for the same common products.

Called synchronously in scan_executor after exposure_analyzer and before
the notification dispatcher — the scan is already in a background task.
"""

import logging
import re
import time
import uuid
from datetime import date
from typing import Any

from sqlalchemy.orm import Session

from app.connectors.http import connector_get
from app.models.asset import AssetType
from app.models.asset_canonical import AssetCanonical
from app.services.tag_service import merge_tags

log = logging.getLogger(__name__)

_EOL_API = "https://endoflife.date/api"

# Module-level response cache: (product, cycle) → (data | None, fetched_epoch)
_cache: dict[tuple[str, str], tuple[dict | None, float]] = {}
_CACHE_TTL = 86_400  # 24 hours

# (optional_service_filter, regex, endoflife_product_slug, version_group)
# Applied to service_version in order; first match wins.
# Slugs verified against https://endoflife.date/api/all.json — only include
# products that actually exist there. openssh, lighttpd, iis are absent.
_PRODUCT_PATTERNS: list[tuple[str | None, re.Pattern[str], str, int]] = [
    (None,    re.compile(r"nginx/(\d+\.\d+)", re.I),             "nginx",             1),
    (None,    re.compile(r"Apache/(\d+\.\d+)", re.I),            "apache-http-server",1),
    (None,    re.compile(r"OpenSSL/(\d+\.\d+)", re.I),           "openssl",           1),
    (None,    re.compile(r"HAProxy/(\d+\.\d+)", re.I),           "haproxy",           1),
    ("imap",  re.compile(r"Dovecot(?:\s+(?:IMAP|POP3)\s+release\s+)?(\d+\.\d+)", re.I), "dovecot", 1),
    ("pop3",  re.compile(r"Dovecot(?:\s+(?:IMAP|POP3)\s+release\s+)?(\d+\.\d+)", re.I), "dovecot", 1),
    # MySQL: service_version is the raw greeting version string (e.g. "8.0.31-ubuntu")
    ("mysql", re.compile(r"^(\d+\.\d+)"),                        "mysql",             1),
]


def _parse_product(service: str, service_version: str) -> tuple[str, str] | None:
    """Return (product_slug, version_cycle) or None."""
    for svc_filter, pattern, product, group in _PRODUCT_PATTERNS:
        if svc_filter and service != svc_filter:
            continue
        m = pattern.search(service_version)
        if m:
            return product, m.group(group)
    return None


def _fetch_eol(product: str, cycle: str) -> dict | None:
    """Query endoflife.date for product+cycle. None means product/cycle unknown."""
    key = (product, cycle)
    cached_data, fetched_at = _cache.get(key, (None, 0.0))
    if time.time() - fetched_at < _CACHE_TTL:
        return cached_data

    url = f"{_EOL_API}/{product}/{cycle}.json"
    try:
        resp = connector_get(url, timeout=10, max_retries=1)
        if resp.status_code == 200:
            data: dict | None = resp.json()
        elif resp.status_code == 404:
            data = None
        else:
            log.warning("endoflife.date returned %s for %s/%s", resp.status_code, product, cycle)
            return None  # don't cache transient failures
        _cache[key] = (data, time.time())
        return data
    except Exception:
        log.debug("endoflife.date lookup failed for %s/%s", product, cycle, exc_info=True)
        return None


def _parse_eol(eol_field: Any) -> tuple[str | None, bool, int | None]:
    """Return (eol_date_str | None, is_eol, days_past_eol | None)."""
    if eol_field is False or eol_field is None:
        return None, False, None
    if eol_field is True:
        return None, True, None
    if isinstance(eol_field, str):
        try:
            eol_date = date.fromisoformat(eol_field)
            delta = (date.today() - eol_date).days
            is_eol = delta > 0
            return eol_field, is_eol, delta if is_eol else None
        except ValueError:
            return None, False, None
    return None, False, None


def enrich_eol(db: Session, touched_asset_ids: set[uuid.UUID]) -> None:
    """Post-scan EOL enrichment entry point. Called from scan_executor."""
    if not touched_asset_ids:
        return

    assets = (
        db.query(AssetCanonical)
        .filter(
            AssetCanonical.id.in_(touched_asset_ids),
            AssetCanonical.asset_type == AssetType.IP_ADDRESS,
        )
        .all()
    )
    if not assets:
        return

    log.info("EOL enrichment: checking %d IP asset(s)", len(assets))
    enriched = 0

    for asset in assets:
        open_ports: list[dict] = (asset.asset_metadata or {}).get("open_ports") or []
        if not open_ports:
            continue

        eol_services: list[dict] = []
        eol_products: set[str] = set()

        for port_entry in open_ports:
            service_version = port_entry.get("service_version") or ""
            service = port_entry.get("service") or ""
            port = port_entry.get("port")
            if not service_version or not isinstance(port, int):
                continue

            parsed = _parse_product(service, service_version)
            if not parsed:
                continue

            product, cycle = parsed
            data = _fetch_eol(product, cycle)
            if data is None:
                continue

            eol_date_str, is_eol, days_past = _parse_eol(data.get("eol"))

            record: dict[str, Any] = {
                "port": port,
                "service": service or None,
                "product": product,
                "version": cycle,
                "eol_date": eol_date_str,
                "is_eol": is_eol,
                "days_past_eol": days_past,
                "latest": data.get("latest"),
            }
            eol_services.append(record)
            if is_eol:
                eol_products.add(product)

        if not eol_services:
            continue

        # Full dict replacement so SQLAlchemy detects the JSONB mutation
        asset.asset_metadata = {**(asset.asset_metadata or {}), "eol_services": eol_services}

        if eol_products:
            new_tags = [f"eol:{p}" for p in sorted(eol_products)]
            asset.tags = merge_tags(asset.tags or [], new_tags)

        enriched += 1

    if enriched:
        db.commit()
        log.info("EOL enrichment: updated %d asset(s) with EOL metadata", enriched)
