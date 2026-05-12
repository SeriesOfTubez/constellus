"""
Target management — domains, IPs, and CIDRs with verification tracking.

Verification methods:
  connector    — domain pulled from a configured DNS connector (auto-verified)
  txt_record   — domain verified via _constellus-verify.<domain> TXT record
  acknowledged — IP/CIDR explicitly acknowledged by a user
  ptr_match    — IP reverse-DNS matches a verified domain (auto-verified)
"""

import ipaddress
import logging
import re
import secrets
import uuid
from datetime import datetime, timezone

import dns.resolver
from sqlalchemy.orm import Session

from app.models.target import Target, TargetType, VerificationMethod

log = logging.getLogger(__name__)

TXT_PREFIX = "_constellus-verify"
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


# ── Type detection ─────────────────────────────────────────────────────────────

def detect_type(value: str) -> TargetType:
    if "/" in value:
        return TargetType.CIDR
    try:
        ipaddress.ip_address(value)
        return TargetType.IP
    except ValueError:
        return TargetType.DOMAIN


# ── WHOIS lookup ───────────────────────────────────────────────────────────────

def whois_lookup(ip: str) -> dict:
    """Return {'org': str, 'asn': str} for an IP address. Best-effort — never raises."""
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


# ── Write helpers ──────────────────────────────────────────────────────────────

def ensure_connector_verified(db: Session, value: str, connector_id: str) -> Target:
    """Mark a domain as verified via connector. Idempotent."""
    existing = db.query(Target).filter(Target.value == value).first()
    if existing:
        if not existing.verified:
            existing.verified = True
            existing.verification_method = VerificationMethod.CONNECTOR
            existing.connector_id = connector_id
            existing.verified_at = datetime.now(timezone.utc)
            db.commit()
        return existing

    target = Target(
        id=uuid.uuid4(),
        type=TargetType.DOMAIN,
        value=value,
        verified=True,
        verification_method=VerificationMethod.CONNECTOR,
        connector_id=connector_id,
        verified_at=datetime.now(timezone.utc),
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    log.info("Target %s auto-verified via connector %s", value, connector_id)
    return target


def ensure_pending(db: Session, value: str) -> Target:
    """Return (or create) a pending target record."""
    value = value.lower().strip().rstrip(".")
    existing = db.query(Target).filter(Target.value == value).first()
    if existing:
        return existing

    target_type = detect_type(value)
    whois = {}
    if target_type in (TargetType.IP, TargetType.CIDR):
        ip = value.split("/")[0] if "/" in value else value
        whois = whois_lookup(ip)

    target = Target(
        id=uuid.uuid4(),
        type=target_type,
        value=value,
        verified=False,
        token=secrets.token_hex(32),
        whois_org=whois.get("org") or None,
        whois_asn=whois.get("asn") or None,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def acknowledge(db: Session, target_id: uuid.UUID, user_id: uuid.UUID) -> Target | None:
    """Acknowledge ownership of an IP/CIDR target."""
    target = db.get(Target, target_id)
    if not target:
        return None
    target.verified = True
    target.verification_method = VerificationMethod.ACKNOWLEDGED
    target.verified_by_id = user_id
    target.verified_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(target)
    log.info("Target %s acknowledged by user %s", target.value, user_id)
    return target


# ── Domain TXT verification ────────────────────────────────────────────────────

def attempt_txt_verification(db: Session, target_id: uuid.UUID) -> bool:
    """Check TXT record for a domain target. Returns True if verified."""
    target = db.get(Target, target_id)
    if not target or target.type != TargetType.DOMAIN:
        return False
    if target.verified:
        return True

    txt_name = f"{TXT_PREFIX}.{target.value}"
    try:
        answers = dns.resolver.resolve(txt_name, "TXT", lifetime=10)
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode().strip() == target.token:
                    target.verified = True
                    target.verification_method = VerificationMethod.TXT_RECORD
                    target.verified_at = datetime.now(timezone.utc)
                    db.commit()
                    log.info("Target %s verified via TXT record", target.value)
                    return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout,
            dns.exception.DNSException) as exc:
        log.debug("TXT lookup for %s failed: %s", txt_name, exc)

    return False


# ── Query helpers ──────────────────────────────────────────────────────────────

def is_verified(db: Session, value: str) -> bool:
    return db.query(Target).filter(
        Target.value == value,
        Target.verified == True,  # noqa: E712
    ).first() is not None


def apex_domain(fqdn: str) -> str:
    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn
