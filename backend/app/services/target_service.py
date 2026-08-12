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

from app.models.tag_rule import TagRule
from app.models.target import Target, TargetType, VerificationMethod
from app.services.tag_service import apply_rules_preloaded, merge_tags

log = logging.getLogger(__name__)

TXT_PREFIX = "_constellus-verify"

# RFC 1035-ish hostname: labels of [a-z0-9-] (not starting/ending with -),
# at least one dot, TLD of 2+ letters. The IGNORECASE flag handles uppercase
# input, but callers should lowercase first anyway.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


# ── Type detection ─────────────────────────────────────────────────────────────

def detect_type(value: str) -> TargetType:
    """Classify a target value. Raises ValueError if the value is not a
    valid domain, IP address, or CIDR network.

    Domain inputs are normalised through punycode first so unicode IDNs
    like `münchen.de` are accepted alongside their `xn--…` form. The
    ASCII regex check then runs against the canonical punycode value.
    """
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {value!r}") from exc
        return TargetType.CIDR
    try:
        ipaddress.ip_address(value)
        return TargetType.IP
    except ValueError:
        pass

    from app.core.apex import to_punycode
    import idna
    try:
        punycode = to_punycode(value)
    except idna.IDNAError as exc:
        raise ValueError(f"{value!r} is not a valid domain: {exc}") from exc
    if _DOMAIN_RE.match(punycode):
        return TargetType.DOMAIN
    raise ValueError(f"{value!r} is not a valid domain, IP address, or CIDR")


def canonicalize_value(value: str) -> str:
    """Return the canonical stored form of a target value.

    For domains: lowercase + dot-trimmed + punycode (so `MÜNCHEN.DE` and
    `xn--mnchen-3ya.de` both end up as `xn--mnchen-3ya.de`).
    For IPs / CIDRs: just lowercase + dot-trimmed (no IDN involvement).
    Invalid input is returned cleaned but unchanged — callers should pair
    this with `detect_type()` to reject malformed values.
    """
    cleaned = (value or "").strip().rstrip(".").lower()
    if not cleaned:
        return ""
    if "/" in cleaned:
        return cleaned
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass
    from app.core.apex import normalize_domain
    return normalize_domain(cleaned)


# ── WHOIS lookup ───────────────────────────────────────────────────────────────

def whois_lookup(db: Session, ip: str) -> dict:
    """Return {'org': str, 'asn': str} for an IP. Uses whois_cache for persistence."""
    from app.services import whois_service
    result = whois_service.lookup_cached(db, ip)
    if not result:
        return {"org": "", "asn": ""}
    return {"org": result["org"], "asn": result["asn"]}


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
    """Return (or create) a target record.

    The act of adding a target via the UI/API implies operator authorisation, so new
    targets are marked verified immediately with `verification_method = MANUAL`. The
    TXT-record and acknowledgement paths remain available (used by connector ingest
    + tests) but are no longer the default lifecycle for UI-added targets.

    Domains are stored as punycode — the canonical wire-level form. The
    UI calls a `displayName()` helper on read so users still see the
    unicode IDN if they entered one.
    """
    value = canonicalize_value(value)
    existing = db.query(Target).filter(Target.value == value).first()
    if existing:
        return existing

    target_type = detect_type(value)
    whois = {}
    if target_type in (TargetType.IP, TargetType.CIDR):
        ip = value.split("/")[0] if "/" in value else value
        whois = whois_lookup(db, ip)

    target = Target(
        id=uuid.uuid4(),
        type=target_type,
        value=value,
        verified=True,
        verification_method=VerificationMethod.MANUAL,
        verified_at=datetime.now(timezone.utc),
        token=secrets.token_hex(32),
        whois_org=whois.get("org") or None,
        whois_asn=whois.get("asn") or None,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    _apply_target_rules(db, target)
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


# ── Tag helpers ───────────────────────────────────────────────────────────────

def _apply_target_rules(db: Session, target: Target) -> None:
    rules = (
        db.query(TagRule)
        .filter(TagRule.entity_type == "target", TagRule.enabled == True)  # noqa: E712
        .all()
    )
    if not rules:
        return
    new_tags = apply_rules_preloaded(rules, target)
    if new_tags:
        target.tags = merge_tags(target.tags or [], new_tags)
        db.commit()


# ── Query helpers ──────────────────────────────────────────────────────────────

def is_verified(db: Session, value: str) -> bool:
    return db.query(Target).filter(
        Target.value == value,
        Target.verified == True,  # noqa: E712
    ).first() is not None


def is_scan_authorised(db: Session, value: str, mode: str) -> bool:
    """Return True if active scanning against `value` is permitted under the given auth mode.

    strict      — target must be fully verified (TXT record / acknowledgement)
    acknowledge — target must exist in the targets table (adding it is implicit confirmation)
    disabled    — no gate; always permitted
    """
    if mode == "disabled":
        return True
    if mode == "acknowledge":
        return db.query(Target).filter(Target.value == value).first() is not None
    # strict (default)
    return is_verified(db, value)


def apex_domain(fqdn: str) -> str:
    """PSL-backed apex extraction. See app.core.apex.apex_domain — this
    name is preserved as a re-export so existing call-sites keep working."""
    from app.core.apex import apex_domain as _apex
    return _apex(fqdn)
