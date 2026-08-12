import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.models.scan_template import ScanTemplate
from app.models.target import Target, TargetType
from app.models.user import UserRole
from app.services import scheduler, target_service as svc

log = logging.getLogger(__name__)

router = APIRouter()


class TargetResponse(BaseModel):
    id: uuid.UUID
    type: str
    value: str
    verified: bool
    verification_method: str | None
    connector_id: str | None
    token: str
    whois_org: str | None
    whois_asn: str | None
    verified_at: str | None
    created_at: str
    notes: str | None
    aggressiveness: str | None
    effective_aggressiveness: str
    last_scanned_at: str | None
    next_scan_at: str | None

    model_config = {"from_attributes": True}


class AddTargetRequest(BaseModel):
    value: str
    notes: str | None = None


class TargetPatch(BaseModel):
    # All fields optional — only the keys present are updated.
    aggressiveness: str | None = None
    notes: str | None = None
    # Sentinel: pass `clear_aggressiveness=True` to reset to inherit
    # (since `aggressiveness=None` in a JSON body is ambiguous with "absent").
    clear_aggressiveness: bool = False


class AcknowledgeRequest(BaseModel):
    confirmed: bool


class BulkTargetRequest(BaseModel):
    target_ids: list[uuid.UUID]


class BulkAggressivenessRequest(BaseModel):
    target_ids: list[uuid.UUID]
    aggressiveness: str | None = None
    # Sentinel: pass `clear=True` to reset to inherit (mirrors TargetPatch).
    clear: bool = False


@router.get("/", response_model=list[TargetResponse])
def list_targets(
    verified: bool | None = None,
    type: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    from app.services import aggressiveness as aggr
    from app.services import app_settings as app_settings_svc

    q = db.query(Target)
    if verified is not None:
        q = q.filter(Target.verified == verified)
    if type:
        q = q.filter(Target.type == type)
    targets = q.order_by(Target.created_at.desc()).all()
    timestamps = _compute_scan_timestamps(db, targets)
    global_tier = aggr.normalize(app_settings_svc.get(db, "aggressiveness"))
    return [
        _to_response(t, *timestamps.get(t.id, (None, None)), global_tier=global_tier)
        for t in targets
    ]


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Fetch a single target by ID — drives the full-detail page."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    last_at, next_at = _compute_scan_timestamps(db, [target]).get(target.id, (None, None))
    return _to_response(target, last_at, next_at)


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def add_target(
    data: AddTargetRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    value = svc.canonicalize_value(data.value)
    if not value:
        raise HTTPException(status_code=422, detail="Value is required")

    try:
        svc.detect_type(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Detect whether this is a brand-new target before ensure_pending runs.
    # New UI-added targets get an immediate first-time discovery scan; existing
    # ones are idempotent no-ops. Lookup uses the canonical (punycode) form so
    # `münchen.de` and `xn--mnchen-3ya.de` collide on the same row.
    existing = db.query(Target).filter(Target.value == value).first()
    is_new = existing is None

    target = svc.ensure_pending(db, value)
    if data.notes and not target.notes:
        target.notes = data.notes
        db.commit()

    if is_new:
        _launch_initial_discovery(db, target, current_user.id, background_tasks)

    return _to_response(target)


def _launch_initial_discovery(
    db: Session,
    target: Target,
    user_id: uuid.UUID,
    background_tasks: BackgroundTasks,
) -> None:
    """Fire a one-off ScanRun against a freshly-added target so the user sees
    discovery results immediately, rather than waiting for the next scheduled
    cron tick. Uses full Phase 1 discovery (passive defaults on, active off)
    since we don't know anything about this target yet.
    """
    from app.api.connectors import REGISTRY
    from app.services import scan_executor

    scope = {
        "domains": [target.value] if target.type == TargetType.DOMAIN else [],
        "ip_ranges": [target.value] if target.type in (TargetType.IP, TargetType.CIDR) else [],
    }
    run = ScanRun(
        id=uuid.uuid4(),
        name=f"Initial discovery: {target.value}",
        status=ScanStatus.PENDING,
        kind=ScanKind.INITIAL_DISCOVERY,
        scope=scope,
        options={
            "cert_transparency": True,
            "subfinder": True,
            "dnsrecon": False,
            "bruteforce": False,
        },
        created_by_id=user_id,
    )
    db.add(run)
    db.commit()
    log.info("Queued initial discovery scan %s for new target %s", run.id, target.value)
    background_tasks.add_task(_prime_ct_and_launch, target.value, run.id, run.scope)


def _prime_ct_and_launch(target_value: str, run_id, scope: dict) -> None:
    """Background entry point for initial-discovery runs. Warms the CT cache
    for the new target with one synchronous Certspotter call so its first
    scan has CT data available, then launches the scan executor."""
    from app.api.connectors import REGISTRY
    from app.services import scan_executor
    from app.services.discovery import cert_transparency

    if scope.get("domains"):
        try:
            cert_transparency.prime_cache(target_value)
        except Exception:
            log.exception("CT prime_cache failed for %s — continuing without it", target_value)

    scan_executor.launch(run_id, scope, REGISTRY)


@router.post("/{target_id}/verify", response_model=TargetResponse)
def verify_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Check TXT record for domain targets."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if target.type != TargetType.DOMAIN:
        raise HTTPException(status_code=400, detail="TXT verification only applies to domain targets")
    if target.verified:
        return _to_response(target)
    success = svc.attempt_txt_verification(db, target_id)
    db.refresh(target)
    if not success:
        raise HTTPException(
            status_code=422,
            detail=f"TXT record not found. Add: {svc.TXT_PREFIX}.{target.value} = {target.token}",
        )
    return _to_response(target)


@router.post("/{target_id}/acknowledge", response_model=TargetResponse)
def acknowledge_target(
    target_id: uuid.UUID,
    data: AcknowledgeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Acknowledge ownership of an IP or CIDR target."""
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if target.type == TargetType.DOMAIN:
        raise HTTPException(status_code=400, detail="Use /verify for domain targets")
    if not data.confirmed:
        raise HTTPException(status_code=422, detail="Must confirm ownership")
    result = svc.acknowledge(db, target_id, current_user.id)
    return _to_response(result)


# Bulk routes are declared before /{target_id} so the path matcher picks
# them up first — otherwise "bulk" gets parsed as a UUID and the request
# 422s on path validation.

@router.post("/bulk/recheck", status_code=202)
def bulk_recheck_targets(
    data: BulkTargetRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Queue a full discovery + enrichment + scan run against the selected
    targets. Unlike asset recheck (which uses skip_discovery), a target
    recheck runs the full Phase 1 to pick up new subdomains / IPs."""
    if not data.target_ids:
        raise HTTPException(status_code=422, detail="No targets selected")

    targets = db.query(Target).filter(Target.id.in_(data.target_ids)).all()
    if not targets:
        raise HTTPException(status_code=404, detail="No matching targets found")

    domains = sorted({t.value for t in targets if t.type == TargetType.DOMAIN})
    ip_ranges = sorted({
        t.value for t in targets
        if t.type in (TargetType.IP, TargetType.CIDR)
    })

    run = ScanRun(
        id=uuid.uuid4(),
        name=f"Manual recheck: {len(targets)} target{'s' if len(targets) != 1 else ''}",
        status=ScanStatus.PENDING,
        kind=ScanKind.MANUAL,
        scope={"domains": domains, "ip_ranges": ip_ranges},
        options={
            "cert_transparency": True,
            "subfinder": True,
            "dnsrecon": False,
            "bruteforce": False,
        },
        created_by_id=current_user.id,
    )
    db.add(run)
    db.commit()

    from app.api.connectors import REGISTRY
    from app.services import scan_executor
    background_tasks.add_task(scan_executor.launch, run.id, run.scope, REGISTRY)
    return {"scan_id": run.id, "target_count": len(targets), "status": "queued"}


@router.post("/bulk/aggressiveness", status_code=200)
def bulk_set_aggressiveness(
    data: BulkAggressivenessRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Set or clear the aggressiveness override on a batch of targets.
    Mirrors PATCH /{id} semantics — pass `clear=True` to reset to inherit,
    or `aggressiveness=<tier>` to set."""
    from app.services import aggressiveness as aggr

    if not data.target_ids:
        raise HTTPException(status_code=422, detail="No targets selected")

    if data.clear:
        new_value: str | None = None
    else:
        if data.aggressiveness not in aggr.TIERS:
            raise HTTPException(
                status_code=422,
                detail=f"aggressiveness must be one of {list(aggr.TIERS)} (or pass clear=true)",
            )
        new_value = data.aggressiveness

    updated = (
        db.query(Target)
        .filter(Target.id.in_(data.target_ids))
        .update({Target.aggressiveness: new_value}, synchronize_session=False)
    )
    db.commit()
    return {"updated": updated, "aggressiveness": new_value}


def _sweep_cname_descendants(db: Session, seed_values: set[str]) -> int:
    """Recursively delete AssetCanonical rows whose parent_value chains down
    from the given seed values. Used by both apex- and target-scoped deletes
    so CNAME chains terminating at external SaaS hostnames don't leave
    orphan IP groups after the parent dns_record is removed."""
    from app.models.asset_canonical import AssetCanonical

    swept = 0
    parent_values = set(seed_values)
    for _i in range(8):
        if not parent_values:
            break
        downstream = (
            db.query(AssetCanonical.id, AssetCanonical.value)
            .filter(AssetCanonical.parent_value.in_(parent_values))
            .all()
        )
        if not downstream:
            break
        ids = [r[0] for r in downstream]
        parent_values = {r[1] for r in downstream if r[1]}
        db.query(AssetCanonical).filter(
            AssetCanonical.id.in_(ids)
        ).delete(synchronize_session=False)
        swept += len(ids)
    return swept


def _soft_cascade_target_assets(db: Session, target_ids: list[uuid.UUID]) -> int:
    """Delete assets that were referenced ONLY by the given targets, and sweep
    their CNAME descendants. Call before the targets themselves are deleted —
    target_asset_links cascades through FK once the target rows go, so we need
    to gather the link set first.
    """
    from app.models.asset_canonical import AssetCanonical
    from app.models.target_asset_link import TargetAssetLink

    linked_asset_ids = {
        r[0] for r in db.query(TargetAssetLink.asset_canonical_id)
        .filter(TargetAssetLink.target_id.in_(target_ids))
        .all()
    }
    if not linked_asset_ids:
        return 0

    # Assets that also link to a target NOT in our delete set survive.
    survivors = {
        r[0] for r in db.query(TargetAssetLink.asset_canonical_id)
        .filter(TargetAssetLink.asset_canonical_id.in_(linked_asset_ids))
        .filter(~TargetAssetLink.target_id.in_(target_ids))
        .all()
    }
    to_delete = linked_asset_ids - survivors
    if not to_delete:
        return 0

    seed_values = {
        r[0] for r in db.query(AssetCanonical.value)
        .filter(AssetCanonical.id.in_(to_delete))
        .all()
        if r[0]
    }
    db.query(AssetCanonical).filter(
        AssetCanonical.id.in_(to_delete)
    ).delete(synchronize_session=False)
    return len(to_delete) + _sweep_cname_descendants(db, seed_values)


@router.delete("/bulk", status_code=200)
def bulk_delete_targets(
    data: BulkTargetRequest,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Delete a set of targets and soft-cascade their orphan assets. See
    `delete_target` for the cascade semantics.
    """
    if not data.target_ids:
        raise HTTPException(status_code=422, detail="No targets selected")

    assets_deleted = _soft_cascade_target_assets(db, data.target_ids)
    deleted = (
        db.query(Target)
        .filter(Target.id.in_(data.target_ids))
        .delete(synchronize_session=False)
    )
    db.commit()
    return {"deleted": deleted, "assets_deleted": assets_deleted}


@router.delete("/{target_id}", status_code=200)
def delete_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Delete a target and soft-cascade the assets that only this target
    referenced. Assets shared with other targets are kept (their link rows
    drop via FK CASCADE). CNAME-chain descendants of deleted assets are also
    swept so dangling SaaS-hostname groups don't appear after delete.
    """
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    assets_deleted = _soft_cascade_target_assets(db, [target_id])
    db.delete(target)
    db.commit()
    return {"target_deleted": True, "assets_deleted": assets_deleted}


@router.patch("/{target_id}", response_model=TargetResponse)
def patch_target(
    target_id: uuid.UUID,
    data: TargetPatch,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Partial update. Only fields present in the body are modified."""
    from app.services import aggressiveness as aggr

    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if data.clear_aggressiveness:
        target.aggressiveness = None
    elif data.aggressiveness is not None:
        if data.aggressiveness not in aggr.TIERS:
            raise HTTPException(
                status_code=422,
                detail=f"aggressiveness must be one of {list(aggr.TIERS)} or null",
            )
        target.aggressiveness = data.aggressiveness

    if data.notes is not None:
        target.notes = data.notes

    db.commit()
    db.refresh(target)
    last_at, next_at = _compute_scan_timestamps(db, [target]).get(target.id, (None, None))
    return _to_response(target, last_at, next_at)


def _to_response(
    t: Target,
    last_scanned_at: str | None = None,
    next_scan_at: str | None = None,
    global_tier: str | None = None,
) -> TargetResponse:
    from app.services import aggressiveness as aggr

    # effective_aggressiveness is the resolved value the executor would
    # use right now. Callers that already know the global tier pass it in
    # so list endpoints don't re-query app_settings per row. Fallback for
    # legacy callers: read it inline (single row case, fine).
    if global_tier is None:
        from app.core.database import SessionLocal
        from app.services import app_settings as app_settings_svc
        db = SessionLocal()
        try:
            global_tier = aggr.normalize(app_settings_svc.get(db, "aggressiveness"))
        finally:
            db.close()
    effective = aggr.effective_for_target(t.aggressiveness, None, global_tier)

    return TargetResponse(
        id=t.id,
        type=t.type,
        value=t.value,
        verified=t.verified,
        verification_method=t.verification_method,
        connector_id=t.connector_id,
        token=t.token,
        whois_org=t.whois_org,
        whois_asn=t.whois_asn,
        verified_at=t.verified_at.isoformat() if t.verified_at else None,
        created_at=t.created_at.isoformat(),
        notes=t.notes,
        aggressiveness=t.aggressiveness,
        effective_aggressiveness=effective,
        last_scanned_at=last_scanned_at,
        next_scan_at=next_scan_at,
    )


def _compute_scan_timestamps(
    db: Session,
    targets: list[Target],
) -> dict[uuid.UUID, tuple[str | None, str | None]]:
    """Derive (last_scanned_at, next_scan_at) per target as ISO strings.

    last_scanned_at — max completed_at across all `scan_runs` whose scope
    contains the target's value. Read once, indexed in-memory.

    next_scan_at — looked up via the tag-priority resolver (mirrors
    `scan_executor._resolve_dynamic_scope`): walk a target's tags through the
    enabled tier templates in priority order; the first match owns the
    target. No match falls back to the default monitoring template. The
    owning template's next fire time comes from APScheduler.
    """
    if not targets:
        return {}

    # ── last_scanned_at: build value → most-recent completed_at map ──────
    runs: list[tuple[dict, datetime]] = (
        db.query(ScanRun.scope, ScanRun.completed_at)
        .filter(ScanRun.status == ScanStatus.COMPLETED.value)
        .filter(ScanRun.completed_at.isnot(None))
        .order_by(ScanRun.completed_at.desc())
        .all()
    )
    last_by_value: dict[str, datetime] = {}
    for scope, completed_at in runs:
        if not scope:
            continue
        for key in ("domains", "ip_ranges"):
            for v in scope.get(key) or []:
                # Iterating completed_at DESC; only set on first sighting.
                if v not in last_by_value:
                    last_by_value[v] = completed_at

    # ── next_scan_at: tag-priority resolver + scheduler lookup ───────────
    tier_templates = (
        db.query(ScanTemplate)
        .filter(ScanTemplate.tag_priority.isnot(None))
        .filter(ScanTemplate.enabled == True)  # noqa: E712
        .filter(ScanTemplate.dynamic_scope == True)  # noqa: E712
        .order_by(ScanTemplate.tag_priority)
        .all()
    )
    next_by_template: dict[str, str | None] = {
        j["id"]: j["next_run_time"] for j in scheduler.list_jobs()
    }
    default_next = next_by_template.get(str(scheduler.DEFAULT_MONITORING_TEMPLATE_ID))

    def winning_next(target_tags: list[str]) -> str | None:
        tag_set = set(target_tags or [])
        for tier in tier_templates:
            tier_tag = (tier.target_tag_filter or [None])[0]
            if tier_tag and tier_tag in tag_set:
                return next_by_template.get(str(tier.id))
        return default_next

    out: dict[uuid.UUID, tuple[str | None, str | None]] = {}
    for t in targets:
        last_dt = last_by_value.get(t.value)
        out[t.id] = (
            last_dt.isoformat() if last_dt else None,
            winning_next(t.tags or []),
        )
    return out
