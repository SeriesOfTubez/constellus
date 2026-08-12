"""Dispatch outbound notifications when new findings land.

Called from the scan executor as a BackgroundTask after the canonical
finding writer has committed. The dispatcher:

  1. Loads enabled notification rules.
  2. For each rule, filters the new findings to those meeting the
     severity threshold and (optional) category list.
  3. Renders a single summary email per rule and hands it to the
     enabled NotificationConnector.

Re-observations of a previously-resolved finding are NOT re-dispatched —
the writer reopens them in place; only the very first insert of a
canonical row counts as "new". The executor must therefore pass the
fresh ID list, not all touched IDs.
"""

import logging
import uuid

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.finding_canonical import EXCLUDED_VERIFICATIONS, FindingCanonical
from app.models.notification_rule import NotificationRule

log = logging.getLogger(__name__)

_SEVERITY_RANK = {
    "info":     0,
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}


def dispatch(new_finding_ids: list[uuid.UUID]) -> None:
    """Background entrypoint. Opens its own session — the caller's session
    is gone by the time the BackgroundTask fires."""
    if not new_finding_ids:
        return

    db = SessionLocal()
    try:
        _dispatch(db, new_finding_ids)
    except Exception:
        log.exception("notification_dispatcher: dispatch failed")
    finally:
        db.close()


def _dispatch(db: Session, new_finding_ids: list[uuid.UUID]) -> None:
    rules = (
        db.query(NotificationRule)
        .filter(NotificationRule.enabled == True)  # noqa: E712
        .all()
    )
    if not rules:
        return

    findings = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.id.in_(new_finding_ids),
            # Pre-existing gap closed (epic#81 Phase D, planning#109): this
            # query never checked `verification` at all, so a Shodan CVE
            # rejected/flagged by shared_infra_verifier in the very same
            # scan run could still page someone before anyone saw it
            # excluded from the main list. Same shared exclusion as the
            # dashboard/score aggregates (models/finding_canonical.py).
            or_(
                FindingCanonical.verification.is_(None),
                FindingCanonical.verification.notin_(EXCLUDED_VERIFICATIONS),
            ),
        )
        .all()
    )
    if not findings:
        return

    connectors = _enabled_notification_connectors(db)
    if not connectors:
        log.info(
            "notification_dispatcher: %d new finding(s) but no notification connector is enabled",
            len(findings),
        )
        return

    for rule in rules:
        matches = [f for f in findings if _rule_matches(rule, f)]
        if not matches:
            continue
        recipients = [r for r in (rule.recipients or []) if r]
        if not recipients:
            log.warning("notification_dispatcher: rule %s has no recipients — skipping", rule.id)
            continue

        subject, text_body, html_body = _render(rule, matches)
        for cid, connector, config in connectors:
            try:
                ok = connector.send(
                    subject=subject,
                    body_text=text_body,
                    recipients=recipients,
                    config=config,
                    body_html=html_body,
                )
                if ok:
                    log.info(
                        "notification_dispatcher: sent rule=%s via %s to %d recipient(s) (%d finding(s))",
                        rule.name, cid, len(recipients), len(matches),
                    )
            except Exception:
                log.exception("notification_dispatcher: connector %s send raised", cid)


# ── Internal ──────────────────────────────────────────────────────────────────

def _rule_matches(rule: NotificationRule, finding: FindingCanonical) -> bool:
    threshold = _SEVERITY_RANK.get(rule.severity_threshold or "high", 3)
    rank = _SEVERITY_RANK.get(finding.severity or "info", 0)
    if rank < threshold:
        return False
    cats = rule.categories or []
    if cats and finding.category not in cats:
        return False
    return True


def _enabled_notification_connectors(db: Session):
    """Yield (connector_id, instance, decrypted_config) for every enabled
    NotificationConnector. Imports are deferred to dodge the cycle between
    this module and the connectors API surface."""
    from app.api.connectors import REGISTRY
    from app.connectors.base import NotificationConnector
    from app.services import connector_config as svc

    enabled_ids = {r.connector_id for r in svc.get_all(db) if r.enabled}
    out = []
    for cid, connector in REGISTRY.items():
        if cid not in enabled_ids or not isinstance(connector, NotificationConnector):
            continue
        if not connector.is_configured():
            continue
        config = svc.get_decrypted_config(db, cid) or {}
        out.append((cid, connector, config))
    return out


def _render(rule: NotificationRule, findings: list[FindingCanonical]) -> tuple[str, str, str]:
    count = len(findings)
    subject = f"Constellus: {count} new {rule.severity_threshold}+ finding{'s' if count != 1 else ''}"

    lines_text: list[str] = [
        f"Rule: {rule.name}",
        f"Triggered by {count} new finding{'s' if count != 1 else ''}:",
        "",
    ]
    lines_html: list[str] = [
        f"<p><strong>Rule:</strong> {_esc(rule.name)}<br>",
        f"Triggered by <strong>{count}</strong> new finding{'s' if count != 1 else ''}:</p>",
        "<ul>",
    ]
    for f in findings[:25]:  # cap to keep emails short
        cve = f" — {f.cve_id}" if f.cve_id else ""
        line = f"  [{(f.severity or '').upper()}] {f.title}{cve}"
        lines_text.append(line)
        lines_html.append(
            f"<li><strong>{_esc((f.severity or '').upper())}</strong> "
            f"{_esc(f.title)}{_esc(cve)}</li>"
        )
    if count > 25:
        lines_text.append(f"… and {count - 25} more")
        lines_html.append(f"<li>… and {count - 25} more</li>")
    lines_html.append("</ul>")

    return subject, "\n".join(lines_text), "".join(lines_html)


def _esc(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
