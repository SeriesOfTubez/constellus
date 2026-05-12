"""
Domain verification helpers.

Connector-sourced domains are auto-verified on first appearance.
Manual domains require a DNS TXT record: _constellus-verify.<domain> = <token>
"""

import logging
import uuid
import dns.resolver

from sqlalchemy.orm import Session

from app.models.domain_verification import DomainVerification, VerificationMethod

log = logging.getLogger(__name__)

TXT_PREFIX = "_constellus-verify"


def ensure_connector_verified(db: Session, domain: str, connector_id: str) -> DomainVerification:
    """Mark a domain as verified via connector. Idempotent — safe to call on every sync."""
    existing = db.query(DomainVerification).filter(DomainVerification.domain == domain).first()
    if existing:
        if not existing.verified:
            existing.verified = True
            existing.method = VerificationMethod.CONNECTOR
            existing.connector_id = connector_id
            from datetime import datetime, timezone
            existing.verified_at = datetime.now(timezone.utc)
            db.commit()
        return existing

    record = DomainVerification(
        id=uuid.uuid4(),
        domain=domain,
        verified=True,
        method=VerificationMethod.CONNECTOR,
        connector_id=connector_id,
    )
    from datetime import datetime, timezone
    record.verified_at = datetime.now(timezone.utc)
    db.add(record)
    db.commit()
    db.refresh(record)
    log.info("Domain %s auto-verified via connector %s", domain, connector_id)
    return record


def ensure_pending(db: Session, domain: str) -> DomainVerification:
    """Return (or create) a pending verification record for a manually-added domain."""
    existing = db.query(DomainVerification).filter(DomainVerification.domain == domain).first()
    if existing:
        return existing
    record = DomainVerification(id=uuid.uuid4(), domain=domain, verified=False)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def attempt_txt_verification(db: Session, domain: str) -> bool:
    """
    Resolve TXT records for _constellus-verify.<domain> and check for the stored token.
    Returns True if verification succeeded.
    """
    record = db.query(DomainVerification).filter(DomainVerification.domain == domain).first()
    if not record:
        return False
    if record.verified:
        return True

    txt_name = f"{TXT_PREFIX}.{domain}"
    try:
        answers = dns.resolver.resolve(txt_name, "TXT", lifetime=10)
        for rdata in answers:
            for txt_string in rdata.strings:
                if txt_string.decode().strip() == record.token:
                    from datetime import datetime, timezone
                    record.verified = True
                    record.method = VerificationMethod.TXT_RECORD
                    record.verified_at = datetime.now(timezone.utc)
                    db.commit()
                    log.info("Domain %s verified via TXT record", domain)
                    return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException) as exc:
        log.debug("TXT lookup for %s failed: %s", txt_name, exc)

    return False


def is_verified(db: Session, domain: str) -> bool:
    record = db.query(DomainVerification).filter(
        DomainVerification.domain == domain,
        DomainVerification.verified == True,  # noqa: E712
    ).first()
    return record is not None


def apex_domain(fqdn: str) -> str:
    """Extract the apex (registrable) domain — last two labels."""
    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn
