import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.dialects.postgresql import aggregate_order_by
from sqlalchemy.orm import Session

from app.api.connectors import REGISTRY
from app.api.deps import require_permission
from app.core.permissions import Permission
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.finding import FindingState
from app.models.finding_canonical import EXCLUDED_VERIFICATIONS, FindingCanonical
from app.models.scan import ScanKind, ScanRun, ScanStatus
from app.models.user import User
from app.services import audit, bod_sla, cluster_writeup, finding_writeup, projector, read_scope, scan_executor
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
    user: User = Depends(require_permission(Permission.FINDINGS_READ)),
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
        .filter(read_scope.finding_clause(user, FindingCanonical, AssetCanonical))
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
    current_user=Depends(require_permission(Permission.FINDINGS_TRIAGE)),
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
    user: User = Depends(require_permission(Permission.FINDINGS_READ)),
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
    # Every aggregate below counts only findings the caller may read
    # (planning#261): the score of a deal under restriction is not leaked by
    # the org-level number.
    readable = read_scope.finding_clause(user, FindingCanonical, AssetCanonical)

    top = (
        db.query(FindingCanonical, AssetCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(FindingCanonical.state.in_(_OPEN_STATES), _NOT_EXCLUDED_FROM_MAIN, readable)
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
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(
            FindingCanonical.state.in_(_OPEN_STATES),
            FindingCanonical.risk_band == band,
            _NOT_EXCLUDED_FROM_MAIN,
            readable,
        )
        .count()
    )

    # Prior-day count: findings in this band that were present ~24h ago — seen
    # before the cutoff and not resolved before it. v1 uses each finding's
    # *current* band as a proxy for its band yesterday (band promotions are rare
    # day-over-day); a score-snapshot history will refine this later.
    worst_band_count_prev = (
        db.query(FindingCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(
            FindingCanonical.risk_band == band,
            FindingCanonical.first_seen_at <= day_ago,
            or_(
                FindingCanonical.resolved_at.is_(None),
                FindingCanonical.resolved_at > day_ago,
            ),
            _NOT_EXCLUDED_FROM_MAIN,
            readable,
        )
        .count()
    )

    # New / resolved in the worst band over the last day — drives the
    # `↑ n new · ↓ n resolved` tooltip split.
    worst_band_new = (
        db.query(FindingCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(
            FindingCanonical.state.in_(_OPEN_STATES),
            FindingCanonical.risk_band == band,
            FindingCanonical.first_seen_at > day_ago,
            _NOT_EXCLUDED_FROM_MAIN,
            readable,
        )
        .count()
    )
    worst_band_resolved = (
        db.query(FindingCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(
            FindingCanonical.risk_band == band,
            FindingCanonical.resolved_at > day_ago,
            _NOT_EXCLUDED_FROM_MAIN,
            readable,
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
            readable,
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


_CLUSTER_GROUP_CAP = 500
_CLUSTER_MEMBER_CAP = 2000
_SEVERITY_BY_RANK = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _severity_rank_expr():
    """SQL severity rank (same ordering as the dispatcher's `_SEVERITY_RANK`),
    built with `case()` so no SQL text is assembled at runtime."""
    return case(
        (FindingCanonical.severity == "critical", 4),
        (FindingCanonical.severity == "high", 3),
        (FindingCanonical.severity == "medium", 2),
        (FindingCanonical.severity == "low", 1),
        else_=0,
    )


def _cluster_base_filters(user, state: str | None):
    """WHERE terms shared by both cluster routes. `read_scope.finding_clause`
    is part of the WHERE so it applies BEFORE any grouping: counts never
    include rows the caller cannot read. `state="all"` is the Findings page's
    "all" filter: no state term, default exclusion kept (as `list_findings`
    does with no state)."""
    if state == "all":
        state = None
    filters = [read_scope.finding_clause(user, FindingCanonical, AssetCanonical)]
    if state:
        filters.append(FindingCanonical.state == state)
    if state in (None, "open", "acknowledged"):
        filters.append(_NOT_EXCLUDED_FROM_MAIN)
    return filters


@router.get("/clusters")
def list_finding_clusters(
    state: str | None = "open",
    db: Session = Depends(get_db),
    user=Depends(require_permission(Permission.FINDINGS_READ)),
):
    """Findings that share one identity key `(finding_type, source,
    fingerprint)` across more than one asset (planning#233 slice 1). The
    frontend groups its already-loaded rows by matching `rolled_up_ids`
    against `member_ids`."""
    rank = _severity_rank_expr()
    cve = FindingCanonical.cve_id
    max_rank = func.max(rank)
    asset_count = func.count(func.distinct(FindingCanonical.asset_canonical_id))
    rows = (
        db.query(
            FindingCanonical.finding_type,
            FindingCanonical.source,
            FindingCanonical.fingerprint,
            max_rank.label("max_rank"),
            func.count(FindingCanonical.id).label("finding_count"),
            asset_count.label("asset_count"),
            func.array_agg(
                aggregate_order_by(FindingCanonical.title, rank.desc(), FindingCanonical.last_seen_at.desc())
            )[1].label("title"),
            func.array_agg(FindingCanonical.id).label("member_ids"),
            case(
                (
                    and_(func.count(func.distinct(cve)) == 1, func.count(cve) == func.count(FindingCanonical.id)),
                    func.min(cve),
                ),
                else_=None,
            ).label("cve_id"),
            func.min(FindingCanonical.first_seen_at).label("first_seen_at"),
            func.max(FindingCanonical.last_seen_at).label("last_seen_at"),
        )
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(*_cluster_base_filters(user, state))
        .group_by(FindingCanonical.finding_type, FindingCanonical.source, FindingCanonical.fingerprint)
        .having(asset_count > 1)
        .order_by(max_rank.desc(), asset_count.desc(), FindingCanonical.finding_type)
        .limit(_CLUSTER_GROUP_CAP)
        .all()
    )
    return [
        {
            "finding_type": r.finding_type,
            "source": r.source,
            "fingerprint": r.fingerprint,
            "title": r.title,
            "max_severity": _SEVERITY_BY_RANK.get(r.max_rank, "info"),
            "finding_count": r.finding_count,
            "asset_count": r.asset_count,
            "cve_id": r.cve_id,
            "first_seen_at": r.first_seen_at,
            "last_seen_at": r.last_seen_at,
            "member_ids": [str(i) for i in r.member_ids],
        }
        for r in rows
    ]


@router.get("/clusters/members")
def list_cluster_members(
    finding_type: str,
    source: str,
    fingerprint: str,
    state: str | None = "open",
    db: Session = Depends(get_db),
    user=Depends(require_permission(Permission.FINDINGS_READ)),
):
    """The findings of ONE cluster key, same state/exclusion/read-scope rules
    as `/clusters`. Deliberately NOT passed through `_rollup_cve_findings`: a
    cluster is one key, and the rollup would merge across sources."""
    rows = (
        db.query(FindingCanonical, AssetCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(
            FindingCanonical.finding_type == finding_type,
            FindingCanonical.source == source,
            FindingCanonical.fingerprint == fingerprint,
            *_cluster_base_filters(user, state),
        )
        .order_by(
            FindingCanonical.risk_score.desc().nullslast(),
            FindingCanonical.last_seen_at.desc(),
        )
        .limit(_CLUSTER_MEMBER_CAP)
        .all()
    )
    states = projector.load_states(db, {f.asset_canonical_id for f, _a in rows})
    return [_serialize_finding(f, a, states.get(f.asset_canonical_id)) for f, a in rows]


# ── AI write-up of a cluster (planning#233 slice 2b) ─────────────────────────

def _reads_every_member(db: Session, user, key: cluster_writeup.Key) -> bool:
    system = {f.id for f, _a in cluster_writeup.members(db, key)}
    return system == {f.id for f, _a in cluster_writeup.members(db, key, user=user)}


def _cluster_writeup_state(db: Session, user, key: cluster_writeup.Key) -> dict:
    """Never generates. A write-up whose frozen members the viewer cannot all
    read is withheld (`hidden`), not shown with the rest redacted."""
    rows = cluster_writeup.members(db, key, user=user)
    eligible = len({f.asset_canonical_id for f, _a in rows}) >= 2
    done = cluster_writeup.latest_succeeded(db, key)
    newest = cluster_writeup.latest_any(db, key)
    pending = newest if newest is not None and newest.status in ("queued", "running") else None
    failure = newest if newest is not None and newest.status == "failed" else None
    writeup, hidden, inputs_changed = None, False, None
    if done is not None:
        if not cluster_writeup.viewer_can_read(db, user, done):
            hidden = True
        else:
            writeup = {
                **_writeup_out(db, done),
                "summary_dropped": done.summary_dropped,
                "finding_count": done.finding_count,
                "asset_count": done.asset_count,
                "max_severity": done.max_severity,
                "auto": done.requested_by_id is None,
            }
            # The hash covers every system member; compare it only for a viewer
            # who can read them all, or "changed" would say something about
            # findings they cannot see.
            if _reads_every_member(db, user, key):
                inputs_changed = done.input_hash != (cluster_writeup.current_hash(db, key) if eligible else None)
    return {
        "eligible": eligible,
        "ineligible_reason": None if eligible else (
            "not a cross-asset cluster: needs open findings on more than one asset"),
        "mode": cluster_writeup.mode(db),
        "writeup": writeup,
        "hidden": hidden,
        "inputs_changed": inputs_changed,
        "pending": {"id": str(pending.id), "status": pending.status, "created_at": pending.created_at} if pending else None,
        "last_failure": {"error": failure.error, "finished_at": failure.finished_at} if failure else None,
    }


@router.get("/clusters/ai-writeup")
def get_cluster_ai_writeup(
    finding_type: str,
    source: str,
    fingerprint: str,
    db: Session = Depends(get_db),
    user=Depends(require_permission(Permission.FINDINGS_READ)),
):
    """The newest succeeded write-up of ONE cluster (if the viewer may read
    every member it described), any queued/running one, the newest failure if
    it is the latest attempt, and whether the cluster changed since."""
    return _cluster_writeup_state(db, user, cluster_writeup.Key(finding_type, source, fingerprint))


@router.post("/clusters/ai-writeup")
def request_cluster_ai_writeup(
    finding_type: str,
    source: str,
    fingerprint: str,
    request: Request,
    background_tasks: BackgroundTasks,
    force: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.FINDINGS_GENERATE_WRITEUP)),
):
    """Generate a cluster write-up, or return the cached one when the cluster
    is unchanged (no call). Any severity is eligible. 409 when it is not a
    cross-asset cluster, the AI is not configured, or one is already running."""
    key = cluster_writeup.Key(finding_type, source, fingerprint)
    if not _reads_every_member(db, current_user, key):
        # The write-up describes every member; one the requester cannot read
        # must not shape or reveal it. Deliberately says nothing of why.
        raise HTTPException(status_code=409, detail="cluster write-up unavailable")
    try:
        row, cached = cluster_writeup.request_writeup(db, key=key, user_id=current_user.id, force=force)
    except (cluster_writeup.NotEligible, cluster_writeup.NotConfigured, cluster_writeup.AlreadyRunning) as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if not cached:
        audit.record_detail(
            request, cluster={"finding_type": finding_type, "source": source, "fingerprint": fingerprint},
            writeup_id=str(row.id), force=force,
        )
        background_tasks.add_task(cluster_writeup.run_in_background, row.id)
    return {"cached": cached, **_cluster_writeup_state(db, current_user, key)}


def _readable_finding(db: Session, user: User, finding_id: uuid.UUID) -> FindingCanonical:
    """The finding if `user` may read it, else 404 exactly as for an unknown id.
    The single-id write routes use it too (planning#261): a caller cannot
    triage, verify or request a write-up on a finding it cannot read."""
    finding = db.execute(
        select(FindingCanonical)
        .join(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .where(FindingCanonical.id == finding_id, read_scope.finding_clause(user, FindingCanonical, AssetCanonical))
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/{finding_id}")
def get_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.FINDINGS_READ)),
):
    """Fetch a single canonical finding by ID — drives the full-detail page."""
    finding = _readable_finding(db, user, finding_id)
    asset = db.get(AssetCanonical, finding.asset_canonical_id)
    return _serialize_finding(finding, asset, _finding_asset_state(db, finding))


# ── AI write-up (planning#226) ───────────────────────────────────────────────

def _writeup_out(db: Session, row) -> dict:
    payload = row.payload or {}
    return {
        "id": str(row.id),
        "created_at": row.created_at,
        "finished_at": row.finished_at,
        "model": row.model,
        "summary": payload.get("summary"),
        "context": payload.get("context", []),
        "fix_steps": payload.get("fix_steps", []),
        "priority_note": payload.get("priority_note"),
        "statements_returned": row.statements_returned,
        "statements_dropped": row.statements_dropped,
        "priority_note_dropped": row.priority_note_dropped,
        "forced_strict": row.forced_strict,
        "cost_usd": finding_writeup.cost_usd(db, row.ledger_ids or []),
    }


def _writeup_state(db: Session, finding: FindingCanonical) -> dict:
    eligible = finding.severity in finding_writeup.WRITEUP_SEVERITIES
    done = finding_writeup.latest_succeeded(db, finding.id)
    newest = finding_writeup.latest_any(db, finding.id)
    pending = newest if newest is not None and newest.status in ("queued", "running") else None
    failure = newest if newest is not None and newest.status == "failed" else None
    inputs_changed = None
    if done is not None and eligible:
        inputs_changed = done.input_hash != finding_writeup.current_hash(db, finding)
    return {
        "eligible": eligible,
        "writeup": _writeup_out(db, done) if done is not None else None,
        "inputs_changed": inputs_changed,
        "pending": {"id": str(pending.id), "status": pending.status, "created_at": pending.created_at} if pending else None,
        "last_failure": {"error": failure.error, "finished_at": failure.finished_at} if failure else None,
    }


@router.get("/{finding_id}/ai-writeup")
def get_ai_writeup(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.FINDINGS_READ)),
):
    """The newest succeeded write-up, any queued/running one, the newest
    failure if it is the latest attempt, and whether the inputs changed
    since the write-up was made. Never generates anything."""
    finding = _readable_finding(db, user, finding_id)
    return _writeup_state(db, finding)


@router.post("/{finding_id}/ai-writeup")
def request_ai_writeup(
    finding_id: uuid.UUID,
    request: Request,
    background_tasks: BackgroundTasks,
    force: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.FINDINGS_GENERATE_WRITEUP)),
):
    """Generate a write-up, or return the cached one when the inputs are
    unchanged (no call is made). `force` (Regenerate) skips the cache.
    Every refusal happens here, before a row exists or any request is sent:
    unknown finding (404), not Critical/High, connector or AI models not
    configured, or a write-up already queued/running (409)."""
    finding = _readable_finding(db, current_user, finding_id)
    try:
        row, cached = finding_writeup.request_writeup(db, finding=finding, user_id=current_user.id, force=force)
    except (finding_writeup.NotEligible, finding_writeup.NotConfigured, finding_writeup.AlreadyRunning) as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if not cached:
        audit.record_detail(request, finding_id=str(finding_id), writeup_id=str(row.id), force=force)
        # planning#134: another on-demand background task the job queue retires.
        background_tasks.add_task(finding_writeup.run_in_background, row.id)
    return {"cached": cached, **_writeup_state(db, finding)}


@router.get("/{finding_id}/epss-history")
def get_epss_history(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(Permission.FINDINGS_READ)),
):
    """Return 12-week EPSS trend data for the CVE associated with this finding.

    Response: {cve_id, current_score, current_percentile, delta, history[]}
    history is weekly-bucketed, most-recent first, up to 12 points.
    delta is (current - previous daily sample), None if < 2 daily samples exist.
    Returns 404 if the finding has no CVE, 200 with empty history if no data yet.
    """
    from app.services import epss_history_service

    finding = _readable_finding(db, user, finding_id)
    if not finding.cve_id:
        raise HTTPException(status_code=404, detail="Finding has no CVE")

    return epss_history_service.get_history(db, finding.cve_id)


@router.patch("/{finding_id}/state")
def update_finding_state(
    finding_id: uuid.UUID,
    data: StateUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(Permission.FINDINGS_TRIAGE)),
):
    finding = _readable_finding(db, current_user, finding_id)

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
    current_user=Depends(require_permission(Permission.FINDINGS_VERIFY)),
):
    finding = _readable_finding(db, current_user, finding_id)

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
    wasn't re-observed (i.e. its last_seen_at didn't advance past started_at).

    The run MUST have reached COMPLETED first (planning#162 item 4). Without
    that check, a verification scan that died turned "we did not look" into
    "it is fixed" — absence of evidence promoted to evidence of absence, the
    same shape as planning#160.

    Note what does NOT work here: wrapping the launch in try/except.
    `scan_executor.launch` catches everything itself and calls `_fail()`
    internally (scan_executor.py:56-64), so it returns `None` on success and
    `None` on catastrophe — the caller cannot tell the two apart from the
    return value. The run's own `status` is the only honest signal, so we
    re-read it. `db.expire_all()` below makes that re-read see the row the
    executor's separate session committed.
    """
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        run = db.get(ScanRun, scan_run_id)
        if not run:
            return
        scan_executor.launch(scan_run_id, run.scope, registry)
        db.expire_all()

        run = db.get(ScanRun, scan_run_id)
        status = getattr(run.status, "value", run.status) if run else None
        original = db.get(FindingCanonical, original_finding_id)
        if original is None:
            return

        if status != ScanStatus.COMPLETED.value:
            # FAILED, CANCELLED, or still RUNNING (a hard abort that never
            # reached _fail). Leave the finding's state exactly as it was and
            # record why, so the operator who clicked Re-verify learns that
            # nothing happened rather than clicking forever against a
            # systematically failing scanner.
            _record_verification_attempt(db, original, run, "failed")
            db.commit()
            return

        if original.last_seen_at < started_at:
            original.state = FindingState.RESOLVED.value
            original.resolved_at = datetime.now(timezone.utc)
            _record_verification_attempt(db, original, run, "resolved")
        else:
            _record_verification_attempt(db, original, run, "still_observed")
        db.commit()
    finally:
        db.close()


def _record_verification_attempt(
    db: Session,
    finding: FindingCanonical,
    run: ScanRun | None,
    outcome: str,
) -> None:
    """Stamp the outcome of a manual Re-verify onto the finding
    (planning#162 item 4).

    Lives in `detail` rather than on the `verification` / `verified_at`
    columns on purpose: those belong to the shared-infra verifier and answer
    a different question (is this finding attributable to an asset we own).
    Conflating "the ownership verdict" with "the last recheck scan's outcome"
    would corrupt an axis the claims layer reads. `detail` is already
    serialized out wholesale by `_serialize_finding`, and `last_verification`
    is lifted to a top-level key there, so the UI can render
    "Last verification failed — view run" with no schema change.

    `outcome` is one of: `failed` (the run did not reach COMPLETED — the
    finding's state was left untouched), `resolved`, `still_observed`.
    """
    attempt: dict = {
        "outcome": outcome,
        "at": datetime.now(timezone.utc).isoformat(),
        "scan_run_id": str(run.id) if run else None,
        "scan_run_status": (getattr(run.status, "value", run.status) if run else None),
    }
    if run is not None and outcome == "failed":
        # `error` is set by the executor's `_fail`; `partial_failures` carries
        # per-chunk errors on a run that otherwise completed. Both are useful
        # to a human here and neither is guaranteed to be populated.
        if run.error:
            attempt["error"] = run.error
        if run.partial_failures:
            attempt["partial_failures"] = run.partial_failures
    # Reassign rather than mutate: SQLAlchemy does not track in-place changes
    # to a plain JSONB dict, so an in-place update would never be flushed.
    finding.detail = {**(finding.detail or {}), "last_verification": attempt}


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
        # Outcome of the last manual Re-verify (planning#162 item 4). Lifted
        # out of `detail` so the UI does not have to know it lives in a
        # free-form blob; None means this finding has never been re-verified.
        "last_verification": (f.detail or {}).get("last_verification"),
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
