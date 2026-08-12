"""WHOIS / RDAP lookups with persistent DB cache.

Two flavours:
  - IP WHOIS (RDAP via ipwhois) — `lookup_cached` — answers "who owns this IP block"
  - Domain WHOIS (python-whois) — `lookup_domain_cached` — answers "who registered this domain"

Both are expensive (1-3s) and rate-limited at the registry level, so results
are cached in dedicated tables. IPs use a 30-day TTL; domains use a 7-day TTL
because expiry-date changes matter.
"""

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models.domain_whois_cache import DomainWhoisCache
from app.models.whois_cache import WhoisCache

log = logging.getLogger(__name__)

DEFAULT_TTL_DAYS = 30
DOMAIN_TTL_DAYS = 7


def _is_public(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved or ip.is_unspecified)


def _fresh_lookup(ip: str) -> dict:
    """Single-shot RDAP lookup. Returns {'org': str, 'asn': str}; never raises."""
    try:
        from ipwhois import IPWhois
        result = IPWhois(ip).lookup_rdap(depth=1)
        org = (
            result.get("network", {}).get("name")
            or result.get("asn_description")
            or ""
        )
        asn = f"AS{result['asn']}" if result.get("asn") else ""
        return {"org": org, "asn": asn}
    except Exception as exc:
        log.debug("WHOIS lookup failed for %s: %s", ip, exc)
        return {"org": "", "asn": ""}


def lookup_cached(db: Session, ip: str, ttl_days: int = DEFAULT_TTL_DAYS) -> dict | None:
    """
    Look up WHOIS info for an IP. Returns None if the IP is non-public.
    Returns {'org', 'asn', 'looked_up_at'} otherwise. Cached for ttl_days.
    """
    if not _is_public(ip):
        return None

    now = datetime.now(timezone.utc)
    row = db.get(WhoisCache, ip)
    if row and (now - row.looked_up_at) < timedelta(days=ttl_days):
        return {"org": row.org or "", "asn": row.asn or "", "looked_up_at": row.looked_up_at}

    result = _fresh_lookup(ip)
    if row:
        row.org = result["org"]
        row.asn = result["asn"]
        row.looked_up_at = now
    else:
        row = WhoisCache(ip=ip, org=result["org"], asn=result["asn"], looked_up_at=now)
        db.add(row)
    db.commit()
    return {"org": row.org or "", "asn": row.asn or "", "looked_up_at": row.looked_up_at}


# ── Domain WHOIS ──────────────────────────────────────────────────────────────

def _first_str(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, list):
        for item in v:
            if item:
                return str(item).strip()
        return None
    s = str(v).strip()
    return s or None


def _first_date(v) -> datetime | None:
    if v is None:
        return None
    if isinstance(v, list):
        v = next((d for d in v if d), None)
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    return None


def _to_str_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v.strip()] if v.strip() else []
    if isinstance(v, list):
        seen: list[str] = []
        for item in v:
            if item is None:
                continue
            s = str(item).strip().lower()
            if s and s not in seen:
                seen.append(s)
        return seen
    return []


def _fresh_domain_lookup(domain: str) -> dict:
    """python-whois lookup. Returns normalized fields; never raises."""
    empty = {
        "registrar": None, "registrant_org": None, "registrant_country": None,
        "creation_date": None, "expiration_date": None, "updated_date": None,
        "name_servers": [], "status": [], "dnssec": None,
    }
    try:
        import whois
        w = whois.whois(domain)
        if w is None:
            return empty
        return {
            "registrar": _first_str(w.get("registrar")),
            "registrant_org": _first_str(w.get("org") or w.get("registrant_org") or w.get("registrant_name")),
            "registrant_country": _first_str(w.get("country") or w.get("registrant_country")),
            "creation_date": _first_date(w.get("creation_date")),
            "expiration_date": _first_date(w.get("expiration_date")),
            "updated_date": _first_date(w.get("updated_date")),
            "name_servers": _to_str_list(w.get("name_servers")),
            "status": _to_str_list(w.get("status")),
            "dnssec": _first_str(w.get("dnssec")),
        }
    except Exception as exc:
        log.debug("Domain WHOIS lookup failed for %s: %s", domain, exc)
        return empty


def lookup_domain_cached(db: Session, domain: str, ttl_days: int = DOMAIN_TTL_DAYS) -> dict:
    """
    Look up registration info for a domain. Cached for ttl_days.
    Returns a dict with all normalized fields plus looked_up_at; empty fields
    are None / [] when the lookup failed or the data isn't available.
    """
    domain = domain.lower().strip().rstrip(".")
    now = datetime.now(timezone.utc)
    row = db.get(DomainWhoisCache, domain)
    if row and (now - row.looked_up_at) < timedelta(days=ttl_days):
        return _row_to_dict(row)

    result = _fresh_domain_lookup(domain)
    if row:
        for k, v in result.items():
            setattr(row, k, v)
        row.looked_up_at = now
    else:
        row = DomainWhoisCache(domain=domain, looked_up_at=now, **result)
        db.add(row)
    db.commit()
    return _row_to_dict(row)


def _row_to_dict(row: DomainWhoisCache) -> dict:
    return {
        "domain": row.domain,
        "registrar": row.registrar,
        "registrant_org": row.registrant_org,
        "registrant_country": row.registrant_country,
        "creation_date": row.creation_date,
        "expiration_date": row.expiration_date,
        "updated_date": row.updated_date,
        "name_servers": row.name_servers or [],
        "status": row.status or [],
        "dnssec": row.dnssec,
        "looked_up_at": row.looked_up_at,
    }
