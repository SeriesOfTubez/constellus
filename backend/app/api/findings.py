import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.connectors import REGISTRY
from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.finding import FindingState
from app.models.finding_canonical import EXCLUDED_VERIFICATIONS, FindingCanonical
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.models.user import UserRole
from app.services import bod_sla, projector, scan_executor
from app.services.asset_chain import chain_target_ids
from app.services.finding_confidence import confidence_for, strongest

router = APIRouter()


def _db_get_by_value(db: Session):
    """value → assets lookup backed by the DB, memoised per request. Used to
    walk CNAME chains when rolling up a single asset's findings."""
    cache: dict[str, list] = {}

    def get(value: str) -> list:
        key = value.lower().rstrip(".")
        if key not in cache:
            cache[key] = (
                db.query(AssetCanonical)
                .filter(AssetCanonical.value == value)
                .all()
            )
        return cache[key]

    return get


class StateUpdate(BaseModel):
    state: FindingState
    suppressed_until: datetime | None = None


class BulkStateUpdate(BaseModel):
    finding_ids: list[uuid.UUID]
    state: FindingState
    suppressed_until: datetime | None = None


@router.get("/")
def list_findings(
    severity: str | None = None,
    category: str | None = None,
    state: str | None = None,
    asset_value: str | None = None,
    asset_canonical_id: str | None = None,
    include_children: bool = False,
    verification: str | None = None,
    finding_type: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """List canonical findings. Returns durable identity rows — one per
    (asset, finding_type, source, fingerprint) — joined to their asset.

    `include_children` (with `asset_canonical_id`) rolls up findings on the
    asset PLUS findings on the specific asset it resolves to: for an A/AAAA/
    CNAME dns_record, that's the asset whose `value` matches this record's
    `content`; for everything else, assets whose `parent_value` == this
    asset's value. This surfaces an ip_address's exposure/CVE findings when
    viewing the dns_record that resolves to it — otherwise a hostname shows
    "High risk" but an empty findings list. Scoping to `content` (rather than
    every sibling record sharing the same name) keeps an A record's findings
    from also pulling in its AAAA sibling's separate IP.

    `verification` (epic#81 Phase D, planning#109) — when set, bypasses the
    default exclusion below entirely and filters to exactly this
    verification value instead. This is the "Ownership Unverifiable" saved
    view's data source: those findings are excluded from the default view by
    design, so the view needs its own explicit query, not a client-side
    filter over the already-loaded (already-excluding) default result set.

    `finding_type` (planning#110) — narrow filter used by the frontend's
    dangling_dns sibling cross-link (a small, targeted fetch rather than
    loading every finding to search client-side).
    """
    q = (
        db.query(FindingCanonical, AssetCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
    )
    if severity:
        q = q.filter(FindingCanonical.severity == severity)
    if category:
        q = q.filter(FindingCanonical.category == category)
    if finding_type:
        q = q.filter(FindingCanonical.finding_type == finding_type)
    if state:
        q = q.filter(FindingCanonical.state == state)
    if verification:
        q = q.filter(FindingCanonical.verification == verification)
    elif state in (None, "open", "acknowledged"):
        # A finding the shared-infra verifier excluded (rejected outright or
        # flagged ownership_unverifiable) drops out of the default/active
        # view — still individually reachable (e.g. via asset_canonical_id,
        # a direct id lookup, or ?verification=), never deleted. Only
        # applies to active-ish state queries; an explicit
        # state=resolved/suppressed query is unaffected (an excluded
        # finding's `state` itself is never touched, so it wouldn't match
        # those anyway).
        q = q.filter(_NOT_EXCLUDED_FROM_MAIN)
    if asset_value:
        q = q.filter(AssetCanonical.value.ilike(f"%{asset_value}%"))
    if asset_canonical_id:
        try:
            aid = uuid.UUID(asset_canonical_id)
        except ValueError:
            aid = None
        if aid is not None:
            if include_children:
                ids = [aid]
                parent = db.get(AssetCanonical, aid)
                if parent is not None:
                    record_type = parent.record_type
                    content = parent.content
                    if record_type in ("A", "AAAA", "CNAME") and content:
                        # This dns_record resolves to a host — roll up the
                        # findings of every asset along the chain it points to
                        # (each hop's record + the terminal IP), so a CNAME
                        # mirrors the host it resolves to across multi-hop
                        # chains (host1 → host2 → IP). Sibling records sharing
                        # the same name but resolving elsewhere aren't pulled in.
                        ids.extend(chain_target_ids(parent, _db_get_by_value(db)))
                    else:
                        ids.extend(
                            cid for (cid,) in
                            db.query(AssetCanonical.id)
                            .filter(AssetCanonical.parent_value == parent.value)
                            .all()
                        )
                q = q.filter(FindingCanonical.asset_canonical_id.in_(ids))
            else:
                q = q.filter(FindingCanonical.asset_canonical_id == aid)

    # Risk Score is the primary prioritisation key (nulls last so un-scored
    # findings don't dominate), then most-recently-seen. Limit is on canonical
    # (per-source) rows; the CVE rollup below collapses them to fewer logical
    # findings, so the cap is generous to leave the rollup enough rows.
    rows = (
        q.order_by(
            FindingCanonical.risk_score.desc().nullslast(),
            FindingCanonical.last_seen_at.desc(),
        )
        .limit(2000)
        .all()
    )
    # planning#144 L3c-3: bod_sla's `exposed` axis reads the projected
    # asset_state, so batch-load it for the whole page in one query — this
    # path serializes up to 2000 rows, where a per-finding lookup would be a
    # textbook N+1.
    states = projector.load_states(db, {f.asset_canonical_id for f, _a in rows})
    return _rollup_cve_findings([
        _serialize_finding(f, a, states.get(f.asset_canonical_id)) for f, a in rows
    ])


@router.post("/bulk/state")
def bulk_update_finding_state(
    data: BulkStateUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    if not data.finding_ids:
        return {"updated": 0}
    if data.state == FindingState.SUPPRESSED and not data.suppressed_until:
        raise HTTPException(status_code=422, detail="suppressed_until is required when suppressing")

    now = datetime.now(timezone.utc)
    updated = 0
    for fid in data.finding_ids:
        finding = db.get(FindingCanonical, fid)
        if not finding:
            continue
        _apply_state_fanout(db, finding, data.state, data.suppressed_until, current_user.id, now)
        updated += 1

    db.commit()
    return {"updated": updated}


_OPEN_STATES = ["open", "acknowledged"]

# A finding the shared-infra verifier excluded — either rejected outright
# (planning#77/#103, direct disproof) or flagged ownership_unverifiable
# (epic#81 Phase D, planning#108, inferential counter-evidence) — drops out
# of dashboard/score aggregates by default. Auditable and reversible (still
# in the DB with its evidence), never deleted. NULL (never checked) and
# every other verification value pass through unaffected.
# EXCLUDED_VERIFICATIONS itself lives on the model (models/finding_canonical.py)
# so api/assets.py and services/notification_dispatcher.py can share it too
# without a service importing from an API-layer module.
_NOT_EXCLUDED_FROM_MAIN = or_(
    FindingCanonical.verification.is_(None),
    FindingCanonical.verification.notin_(EXCLUDED_VERIFICATIONS),
)


@router.get("/security-score")
def security_score(
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Org-level Constellus Risk Score for the dashboard gauge.

    Worst-driven (locked 2026-06-10): the score is the single highest open
    finding risk_score and the band is that finding's verdict. Breadth is
    expressed by `worst_band_count` (open findings in the current worst band)
    + a day-over-day trend, not by inflating the number. See the "Org security
    score = worst-driven" design note.

    Contract: { score, band, worst_band_count, worst_band_count_prev,
                worst_band_new, worst_band_resolved, breakdown[] }
    """
    day_ago = datetime.now(timezone.utc) - timedelta(days=1)

    top = (
        db.query(FindingCanonical, AssetCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(FindingCanonical.state.in_(_OPEN_STATES), _NOT_EXCLUDED_FROM_MAIN)
        .order_by(
            FindingCanonical.risk_score.desc().nullslast(),
            FindingCanonical.last_seen_at.desc(),
        )
        .first()
    )

    # No open findings (or none scored yet) → Secure Posture.
    if top is None or not top[0].risk_score:
        return {
            "score": 0,
            "band": "secure",
            "worst_band_count": 0,
            "worst_band_count_prev": 0,
            "worst_band_new": 0,
            "worst_band_resolved": 0,
            "breakdown": [],
        }

    worst, _asset = top
    band = worst.risk_band

    # Open findings currently in the worst band.
    worst_band_count = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.state.in_(_OPEN_STATES),
            FindingCanonical.risk_band == band,
            _NOT_EXCLUDED_FROM_MAIN,
        )
        .count()
    )

    # Prior-day count: findings in this band that were present ~24h ago — seen
    # before the cutoff and not resolved before it. v1 uses each finding's
    # *current* band as a proxy for its band yesterday (band promotions are rare
    # day-over-day); a score-snapshot history will refine this later.
    worst_band_count_prev = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.risk_band == band,
            FindingCanonical.first_seen_at <= day_ago,
            or_(
                FindingCanonical.resolved_at.is_(None),
                FindingCanonical.resolved_at > day_ago,
            ),
            _NOT_EXCLUDED_FROM_MAIN,
        )
        .count()
    )

    # New / resolved in the worst band over the last day — drives the
    # `↑ n new · ↓ n resolved` tooltip split.
    worst_band_new = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.state.in_(_OPEN_STATES),
            FindingCanonical.risk_band == band,
            FindingCanonical.first_seen_at > day_ago,
            _NOT_EXCLUDED_FROM_MAIN,
        )
        .count()
    )
    worst_band_resolved = (
        db.query(FindingCanonical)
        .filter(
            FindingCanonical.risk_band == band,
            FindingCanonical.resolved_at > day_ago,
            _NOT_EXCLUDED_FROM_MAIN,
        )
        .count()
    )

    # Top contributing findings in the worst band.
    breakdown_rows = (
        db.query(FindingCanonical, AssetCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(
            FindingCanonical.state.in_(_OPEN_STATES),
            FindingCanonical.risk_band == band,
            _NOT_EXCLUDED_FROM_MAIN,
        )
        .order_by(
            FindingCanonical.risk_score.desc().nullslast(),
            FindingCanonical.last_seen_at.desc(),
        )
        .limit(5)
        .all()
    )
    breakdown = [
        {
            "id": str(f.id),
            "title": f.title,
            "asset_value": a.value if a else None,
            "risk_score": f.risk_score,
            "severity": f.severity,
            "building_velocity": f.building_velocity,
        }
        for f, a in breakdown_rows
    ]

    return {
        "score": worst.risk_score,
        "band": band,
        "worst_band_count": worst_band_count,
        "worst_band_count_prev": worst_band_count_prev,
        "worst_band_new": worst_band_new,
        "worst_band_resolved": worst_band_resolved,
        "breakdown": breakdown,
    }


@router.get("/{finding_id}")
def get_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Fetch a single canonical finding by ID — drives the full-detail page."""
    finding = db.get(FindingCanonical, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    asset = db.get(AssetCanonical, finding.asset_canonical_id)
    return _serialize_finding(finding, asset, _finding_asset_state(db, finding))


@router.get("/{finding_id}/epss-history")
def get_epss_history(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return 12-week EPSS trend data for the CVE associated with this finding.

    Response: {cve_id, current_score, current_percentile, delta, history[]}
    history is weekly-bucketed, most-recent first, up to 12 points.
    delta is (current - previous daily sample), None if < 2 daily samples exist.
    Returns 404 if the finding has no CVE, 200 with empty history if no data yet.
    """
    from app.services import epss_history_service

    finding = db.get(FindingCanonical, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not finding.cve_id:
        raise HTTPException(status_code=404, detail="Finding has no CVE")

    return epss_history_service.get_history(db, finding.cve_id)


@router.patch("/{finding_id}/state")
def update_finding_state(
    finding_id: uuid.UUID,
    data: StateUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    finding = db.get(FindingCanonical, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if data.state == FindingState.SUPPRESSED and not data.suppressed_until:
        raise HTTPException(status_code=422, detail="suppressed_until is required when suppressing")

    _apply_state_fanout(db, finding, data.state, data.suppressed_until, current_user.id, datetime.now(timezone.utc))
    db.commit()

    asset = db.get(AssetCanonical, finding.asset_canonical_id)
    return _serialize_finding(finding, asset, _finding_asset_state(db, finding))


@router.post("/{finding_id}/verify", status_code=202)
def verify_finding(
    finding_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    finding = db.get(FindingCanonical, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    asset = db.get(AssetCanonical, finding.asset_canonical_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset for finding not found")

    asset_value = asset.value
    asset_type = asset.asset_type
    run = ScanRun(
        id=uuid.uuid4(),
        name=f"Verify: {finding.title[:80]}",
        status=ScanStatus.PENDING,
        kind=ScanKind.RECHECK,
        scope={
            "domains": [asset_value] if asset_type == "dns_record" else [],
            "ip_ranges": [asset_value] if asset_type == "ip_address" else [],
        },
        # force_reverify (planning#115): the shared-infra verifier normally
        # only re-stamps a finding that already holds a decisive verdict
        # once a contrary result persists past a grace window — an explicit
        # "Re-verify" click should bypass both that guard and
        # classify_ip_ownership's TTL cache instead of silently no-op'ing.
        options={"skip_discovery": True, "force_reverify": True},
        created_by_id=current_user.id,
    )
    db.add(run)
    db.commit()

    started_at = datetime.now(timezone.utc)
    background_tasks.add_task(
        _verify_and_resolve, run.id, finding_id, started_at, REGISTRY
    )
    return {"scan_id": run.id, "status": "queued"}


# ── helpers ───────────────────────────────────────────────────────────────────

def _rollup_cve_findings(items: list[dict]) -> list[dict]:
    """Collapse per-source canonical rows sharing an (asset, cve_id) into one
    logical finding (#66 D3): keep per-source rows in the DB, dedup at read time.

    Same CVE on one asset from shodan + version_match + nuclei → a single row
    whose `confidence` is the strongest of the group (confirmed > potential),
    `sources` lists every contributing source, and `fixed_version` is taken from
    the version_match row (the only source that carries one — #34's input).
    `rolled_up_ids` carries every constituent id so a state change can fan out.

    The representative is the first (highest-risk_score) row of the group; group
    members share their mirrored CVE-level signals, so its score/CVSS/etc. stand
    in for the group. Findings without a cve_id pass through untouched.
    """
    result: list[dict] = []
    index: dict[tuple[str, str], int] = {}
    for d in items:
        cve = d.get("cve_id")
        if not cve:
            # Non-CVE findings are never rolled up, but carry the same shape so
            # the frontend doesn't special-case them.
            d["sources"] = [d["source"]]
            d["rolled_up_ids"] = [d["id"]]
            result.append(d)
            continue
        key = (d["asset_canonical_id"], cve)
        pos = index.get(key)
        if pos is None:
            d["sources"] = [d["source"]]
            d["rolled_up_ids"] = [d["id"]]
            if d["source"] == "version_match":
                d["fixed_version"] = (d.get("detail") or {}).get("fixed_version")
            index[key] = len(result)
            result.append(d)
        else:
            rep = result[pos]
            if d["source"] not in rep["sources"]:
                rep["sources"].append(d["source"])
            rep["rolled_up_ids"].append(d["id"])
            rep["confidence"] = strongest(rep["confidence"], d["confidence"])
            if d["source"] == "version_match" and not rep.get("fixed_version"):
                rep["fixed_version"] = (d.get("detail") or {}).get("fixed_version")
    for d in result:
        if "sources" in d:
            d["sources"] = sorted(set(d["sources"]))
    return result


def _apply_state_fanout(
    db: Session,
    finding: FindingCanonical,
    state: FindingState,
    suppressed_until: datetime | None,
    user_id: uuid.UUID,
    now: datetime,
) -> None:
    """Apply a state change to a finding AND every per-source canonical row that
    shares its (asset, cve_id). The findings list rolls those rows up into one
    logical finding (#66 D3), so acking/suppressing must fan out — otherwise a
    still-open sibling re-surfaces the finding under a state filter."""
    _apply_state(finding, state, suppressed_until, user_id, now)
    if finding.cve_id:
        siblings = (
            db.query(FindingCanonical)
            .filter(
                FindingCanonical.asset_canonical_id == finding.asset_canonical_id,
                FindingCanonical.cve_id == finding.cve_id,
                FindingCanonical.id != finding.id,
            )
            .all()
        )
        for s in siblings:
            _apply_state(s, state, suppressed_until, user_id, now)


def _apply_state(
    finding: FindingCanonical,
    state: FindingState,
    suppressed_until: datetime | None,
    user_id: uuid.UUID,
    now: datetime,
) -> None:
    finding.state = state.value if isinstance(state, FindingState) else state
    if state == FindingState.ACKNOWLEDGED:
        finding.acknowledged_by_id = user_id
        finding.acknowledged_at = now
        finding.suppressed_until = None
        finding.resolved_at = None
    elif state == FindingState.SUPPRESSED:
        finding.acknowledged_by_id = user_id
        finding.acknowledged_at = now
        finding.suppressed_until = suppressed_until
        finding.resolved_at = None
    elif state == FindingState.RESOLVED:
        finding.resolved_at = now
        finding.suppressed_until = None
    elif state == FindingState.OPEN:
        finding.resolved_at = None
        finding.suppressed_until = None


def _verify_and_resolve(
    scan_run_id: uuid.UUID,
    original_finding_id: uuid.UUID,
    started_at: datetime,
    registry: dict,
) -> None:
    """Run the verification scan and resolve the canonical finding if it
    wasn't re-observed (i.e. its last_seen_at didn't advance past started_at)."""
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        run = db.get(ScanRun, scan_run_id)
        if not run:
            return
        scan_executor.launch(scan_run_id, run.scope, registry)
        db.expire_all()
        original = db.get(FindingCanonical, original_finding_id)
        if original and original.last_seen_at < started_at:
            original.state = FindingState.RESOLVED.value
            original.resolved_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def _finding_asset_state(db: Session, f: FindingCanonical):
    """The one projected `asset_state` row behind a single finding, for the
    single-finding endpoints (planning#144 L3c-3). The list endpoint must
    NOT use this — it batch-loads instead."""
    return projector.load_states(db, [f.asset_canonical_id]).get(f.asset_canonical_id)


def _serialize_finding(f: FindingCanonical, a: AssetCanonical | None, state=None) -> dict:
    return {
        "id": str(f.id),
        "asset_value": a.value if a else None,
        "asset_parent_value": a.parent_value if a else None,
        "asset_canonical_id": str(f.asset_canonical_id),
        "finding_type": f.finding_type,
        "source": f.source,
        # Per-source confidence (#66 D4). The list rollup may strengthen this to
        # the max across sources sharing the CVE; a lone/detail view shows the
        # source's own confidence.
        "confidence": confidence_for(f.source),
        "fingerprint": f.fingerprint,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "detail": f.detail or {},
        "state": f.state,
        "acknowledged_at": f.acknowledged_at.isoformat() if f.acknowledged_at else None,
        "suppressed_until": f.suppressed_until.isoformat() if f.suppressed_until else None,
        # Shared-infra verification (migrations 0036/0037, epic#81 Phases A/D).
        # Was never serialized before Phase D — added so the frontend can show
        # WHY a finding is excluded from the main list (rejected_shared_infra /
        # ownership_unverifiable), not just silently drop it.
        "verification": f.verification,
        "verification_evidence": f.verification_evidence,
        "verified_at": f.verified_at.isoformat() if f.verified_at else None,
        "category": f.category,
        "cve_id": f.cve_id,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "cvss_version": f.cvss_version,
        "epss_score": f.epss_score,
        "epss_percentile": f.epss_percentile,
        "kev": f.kev,
        "kev_date_added": f.kev_date_added.isoformat() if f.kev_date_added else None,
        "cwe": f.cwe,
        # Constellus Risk Score
        "risk_score": f.risk_score,
        "risk_band": f.risk_band,
        "building_velocity": f.building_velocity,
        "impact_class": f.impact_class,
        "exploit_types": f.exploit_types or [],
        # SSVC (CISA Vulnrichment or derived fallback)
        "ssvc_exploitation": f.ssvc_exploitation,
        "ssvc_automatable": f.ssvc_automatable,
        "ssvc_technical_impact": f.ssvc_technical_impact,
        "ssvc_source": f.ssvc_source,
        "ssvc_scored_at": f.ssvc_scored_at.isoformat() if f.ssvc_scored_at else None,
        "vulncheck_kev": f.vulncheck_kev,
        "has_exploit": f.has_exploit,
        "exploit_count": f.exploit_count,
        "ransomware_use": f.ransomware_use,
        "canary_detected": f.canary_detected,
        "is_template": f.is_template,
        "is_poc": f.is_poc,
        "tags": f.tags or [],
        "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
        "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        # BOD-26-04 remediation SLA lens (compliance deadline, separate from Risk Score)
        "bod_sla": bod_sla.compute_sla(f, a, state),
    }
