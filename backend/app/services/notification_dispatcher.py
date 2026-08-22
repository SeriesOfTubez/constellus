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

`dispatch_promotions` (planning#131, temporal layer slice 1) is a second,
parallel entrypoint for band-escalation notifications — a finding whose
`risk_band` moved up a tier, or whose `building_velocity` just turned on,
as detected by `app.services.score_history.capture`. It is called from
both `scan_executor.py` (a scan-time promotion) and `nightly_rescore.py`
(the nightly full-scope re-score), and deliberately reuses
`_enabled_notification_connectors` and `_rule_matches` UNCHANGED so a
`NotificationRule` keeps exactly one meaning (severity threshold + category
filter against the finding) regardless of which event triggered dispatch —
this module does not grow a second rule vocabulary for promotions.

Ownership gating is IDENTICAL across both entrypoints, and must stay that
way. Each applies two independent filters in the same order: the
finding-level `EXCLUDED_VERIFICATIONS` exclusion, then the asset-level
`not_ours` gate (`_drop_not_ours`). They catch different routes to the same
"don't page anyone about this" verdict and neither subsumes the other — see
`_drop_not_ours`'s docstring for the two routes.

Two notification channels with different answers to "is this asset ours"
is a bug waiting to happen, which is why the gate went into both rather
than only the newer one. A future third entrypoint gets both filters too.
"""

import logging
import uuid

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.finding_canonical import EXCLUDED_VERIFICATIONS, FindingCanonical
from app.models.notification_rule import NotificationRule
from app.services import claims_query

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

    findings = _drop_not_ours(db, findings)
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


def dispatch_promotions(promotions: list) -> None:
    """Background/inline entrypoint for band-escalation notifications
    (planning#131). Opens its own session exactly like `dispatch()` — same
    reasoning: whichever caller invokes this (a scheduler job, or the scan
    executor near the end of a run) may have its own session gone or about
    to close by the time this runs.

    `promotions` is a `list[app.services.score_history.Promotion]`; typed
    loosely here (not imported) to avoid a module-load-order dependency —
    this module has no other reason to import `score_history`.
    """
    if not promotions:
        return

    db = SessionLocal()
    try:
        _dispatch_promotions(db, promotions)
    except Exception:
        log.exception("notification_dispatcher: dispatch_promotions failed")
    finally:
        db.close()


def _dispatch_promotions(db: Session, promotions: list) -> None:
    rules = (
        db.query(NotificationRule)
        .filter(NotificationRule.enabled == True)  # noqa: E712
        .all()
    )
    if not rules:
        return

    promotions_by_finding = {p.finding_canonical_id: p for p in promotions}
    findings = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.id.in_(list(promotions_by_finding.keys())),
            # Defence in depth, same reasoning as _dispatch above: re-apply
            # the exclusion here even though both callers (scan_executor,
            # nightly_rescore) already filtered it before handing us this
            # list — this function must be safe to call from anywhere, not
            # only from callers that remembered to filter first.
            or_(
                FindingCanonical.verification.is_(None),
                FindingCanonical.verification.notin_(EXCLUDED_VERIFICATIONS),
            ),
        )
        .all()
    )
    if not findings:
        return

    findings = _drop_not_ours(db, findings)
    if not findings:
        return

    connectors = _enabled_notification_connectors(db)
    if not connectors:
        log.info(
            "notification_dispatcher: %d promotion(s) but no notification connector is enabled",
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

        subject, text_body, html_body = _render_promotions(rule, matches, promotions_by_finding)
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
                        "notification_dispatcher: sent promotion rule=%s via %s to %d recipient(s) (%d finding(s))",
                        rule.name, cid, len(recipients), len(matches),
                    )
            except Exception:
                log.exception("notification_dispatcher: connector %s send raised", cid)


# ── Internal ──────────────────────────────────────────────────────────────────

def _drop_not_ours(db: Session, findings: list[FindingCanonical]) -> list[FindingCanonical]:
    """Drop findings whose ASSET is `not_ours` at the estate layer
    (planning#131). Second, independent ownership gate behind the
    finding-level `EXCLUDED_VERIFICATIONS` filter above — they cover
    different routes to the same "don't page anyone about this" verdict,
    and only together do they cover both.

    `projector.py` reaches `estate = "not_ours"` two ways:

      1. `verdict == "rejected_shared_infra"` — the affinity verifier
         disproved ownership of a shared host. This route ALSO stamps
         `verification = "rejected_shared_infra"` onto the findings, so
         the filter above already catches it. Nothing new here.
      2. A `third_party_dependency` claim — a captured CNAME boundary
         target (planning#147). This is a NAME asset, and
         `shared_infra_verifier.verify_findings` only ever classifies
         `asset_type == "ip_address"` assets, so a finding hanging off one
         of these keeps `verification = NULL` forever and sails straight
         through the filter above. That is the hole this function closes.

    Route 2 is narrow — a boundary node is never probed ("we never probed
    it and never will", per projector's own comment), so it can only
    accumulate findings from passive/connector sources like Shodan. Narrow
    is not zero, and a passively-sourced CVE misattributed to
    infrastructure we demonstrably do not own is precisely the
    false-attribution failure epic#81 exists to prevent.

    Applied by BOTH `_dispatch` (new findings) and `_dispatch_promotions`
    (band escalations). The new-finding path shipped before this gate
    existed and carried the same hole; closing it there is a deliberate
    behaviour change, and the blast radius is exactly route 2 above —
    route 1 was already filtered by `EXCLUDED_VERIFICATIONS`, so nothing
    that currently pages anyone through route 1 stops. What stops is
    paging on a captured CNAME boundary target, which is an asset
    `dns_resolve` observed falling outside every declared target domain.
    That is the settled epic#81 principle applied where it was missing —
    reject findings we cannot prove are ours, don't merely flag them —
    not a new policy.

    Takeover/dangling-DNS detection is NOT affected, and this was checked
    rather than assumed: `dangling_dns_analyzer._build_finding` attaches
    its findings to the `dns_record` asset (which is ours, and inside the
    authorized target scope), never to the boundary target the record
    points at. The `third_party_dependency` claim lands on the captured
    target node, a different asset entirely.

    `surface_by_asset` returns a value for every id asked about, so
    `"unknown"` (no ownership signal at all) passes through — only an
    affirmative `not_ours` suppresses. Silence is not a verdict here; that
    asymmetry is the opposite of hygiene scoring's, where unknown ranks
    WORST, and it is right in both places: an unowned-looking asset should
    still page you when nobody has actually established it isn't yours.
    """
    surface_by_id = claims_query.surface_by_asset(
        db, [f.asset_canonical_id for f in findings]
    )
    kept = [f for f in findings if surface_by_id.get(f.asset_canonical_id) != "not_ours"]
    dropped = len(findings) - len(kept)
    if dropped:
        log.info(
            "notification_dispatcher: suppressed %d promotion(s) on not_ours asset(s)",
            dropped,
        )
    return kept


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


def _render_promotions(rule: NotificationRule, findings: list[FindingCanonical], promotions_by_finding: dict) -> tuple[str, str, str]:
    """Separate from `_render` rather than over-generalising it — the two
    render genuinely different content (old_band -> new_band vs. severity +
    CVE) and forcing them through one function would mean threading a
    promotions-or-None param through every line. Reuses the same 25-row cap
    and `_esc` HTML escaping as `_render`."""
    count = len(findings)
    subject = f"Constellus: {count} finding{'s' if count != 1 else ''} escalated"

    lines_text: list[str] = [
        f"Rule: {rule.name}",
        f"{count} finding{'s' if count != 1 else ''} escalated:",
        "",
    ]
    lines_html: list[str] = [
        f"<p><strong>Rule:</strong> {_esc(rule.name)}<br>",
        f"{count} finding{'s' if count != 1 else ''} escalated:</p>",
        "<ul>",
    ]
    for f in findings[:25]:  # cap to keep emails short
        p = promotions_by_finding[f.id]
        prev_band = p.previous_band or "none"
        cve = f" — {f.cve_id}" if f.cve_id else ""
        velocity_note = " (velocity started)" if p.velocity_started else ""
        line = f"  [{prev_band} -> {p.new_band}] {f.title}{cve}{velocity_note}"
        lines_text.append(line)
        lines_html.append(
            f"<li><strong>{_esc(prev_band)} -&gt; {_esc(p.new_band)}</strong> "
            f"{_esc(f.title)}{_esc(cve)}{_esc(velocity_note)}</li>"
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
