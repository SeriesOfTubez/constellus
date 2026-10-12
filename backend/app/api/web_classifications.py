"""AI web-app classification API (planning#231).

The AI's classification of a web endpoint is applied and shown as inferred;
an ADMIN corrects it (Jason, 2026-10-11, #231 6112788736). Correction is
ADMIN-only until custom roles land (planning#243).

- `GET  /api/assets/{asset_id}/web-classifications` - per web endpoint: the
  effective kind/environment and its source (ai | user | none), the AI row,
  the correction, any active run, the latest failure and the change flags.
  Never generates anything.
- `POST /api/assets/{asset_id}/web-classifications` (ADMIN) - classify the
  asset's web endpoints, or return the cached ones when the input is
  unchanged (no call). `force` skips the cache.
- `PUT|DELETE /api/assets/{asset_id}/web-endpoints/{port}/classification`
  (ADMIN) - set / remove a person's correction. Audited.
- `GET  /api/web-endpoints` - every web endpoint the caller may read, with
  the same state, filterable by effective kind and source.

Every endpoint state carries its `redirect_chain` (planning#271): the hops
`app.services.redirect_follow` recorded for it, read-only, loaded in one
query per response. A hop's title belongs to the hop's URL, never to the
endpoint; `http_title` stays the endpoint's own.

Nothing here writes a score, attribution, estate or tag (see
`app.services.web_classifier`). Reads are limited to the assets
`read_scope.asset_clause` lets the caller see.
"""

import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, select, tuple_
from sqlalchemy.orm import Session, aliased

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.http_redirect_hop import HttpRedirectHop
from app.models.user import User, UserRole
from app.models.web_classification import REASON_CAP, WebClassification, WebEndpointOverride
from app.services import audit, read_scope, web_classifier

router = APIRouter()


Kind = Literal[
    "login_portal", "admin_panel", "default_install", "parked", "marketing_site", "api", "application", "unknown",
]
Environment = Literal["production", "non_production", "unknown"]


class OverrideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Kind
    environment: Environment
    reason: str | None = Field(default=None, max_length=REASON_CAP)


def _row_out(db: Session, row: WebClassification) -> dict:
    return {
        "id": str(row.id),
        "port": row.port,
        "status": row.status,
        "kind": row.kind,
        "environment": row.environment,
        "product": row.product,
        "product_source_field": row.product_source_field,
        "evidence": row.evidence or [],
        "citations_dropped": row.citations_dropped,
        "product_dropped": row.product_dropped,
        "downgraded": row.downgraded,
        "model": row.model,
        "forced_strict": row.forced_strict,
        "error": row.error,
        "requested_by_id": str(row.requested_by_id) if row.requested_by_id else None,
        "created_at": row.created_at,
        "finished_at": row.finished_at,
        "cost_usd": web_classifier.cost_usd(db, row.ledger_ids or []),
    }


def _override_out(db: Session, ov: WebEndpointOverride) -> dict:
    by = db.get(User, ov.set_by_id) if ov.set_by_id else None
    return {
        "kind": ov.kind,
        "environment": ov.environment,
        "reason": ov.reason,
        "set_by": by.full_name if by is not None else None,
        "set_at": ov.set_at,
        "updated_at": ov.updated_at,
        "ai_classification_id": str(ov.ai_classification_id) if ov.ai_classification_id else None,
    }


def _redirect_chains(db: Session, user: User, states: list[dict]) -> dict[tuple[uuid.UUID, int], list[dict]]:
    """(asset id, port) -> its redirect hops in hop order, for every state in
    one query. `hop_asset_id` is given only when the caller may read the
    hop's asset (`read_scope`); the URL itself is the endpoint's own data."""
    keys = {(st["asset"].id, st["port"]) for st in states}
    if not keys:
        return {}
    hop_asset = aliased(AssetCanonical)
    rows = db.execute(
        select(HttpRedirectHop, hop_asset.id)
        .outerjoin(hop_asset, and_(hop_asset.id == HttpRedirectHop.hop_asset_id,
                                   read_scope.asset_clause(user, hop_asset)))
        .where(tuple_(HttpRedirectHop.origin_asset_id, HttpRedirectHop.origin_port).in_(list(keys)))
        .order_by(HttpRedirectHop.origin_asset_id, HttpRedirectHop.origin_port, HttpRedirectHop.hop_index)
    ).all()
    chains: dict[tuple[uuid.UUID, int], list[dict]] = {}
    for hop, visible_hop_asset_id in rows:
        chains.setdefault((hop.origin_asset_id, hop.origin_port), []).append({
            "hop_index": hop.hop_index,
            "url": hop.url,
            "followed": hop.followed,
            "reason": hop.reason,
            "http_status": hop.http_status,
            "http_title": hop.http_title,
            "hop_asset_id": str(visible_hop_asset_id) if visible_hop_asset_id is not None else None,
        })
    return chains


def _states_out(db: Session, user: User, states: list[dict], *, with_asset: bool = False) -> list[dict]:
    chains = _redirect_chains(db, user, states)
    return [_state_out(db, st, chains, with_asset=with_asset) for st in states]


def _state_out(db: Session, st: dict, chains: dict[tuple[uuid.UUID, int], list[dict]], *,
               with_asset: bool = False) -> dict:
    entry = st["entry"]
    out = {
        "port": st["port"],
        "kind": st["kind"],
        "environment": st["environment"],
        "product": st["product"],
        "source": st["source"],
        "http_title": entry.get("http_title"),
        "http_status": entry.get("http_status"),
        "service": entry.get("service"),
        "ai": _row_out(db, st["ai"]) if st["ai"] is not None else None,
        "override": _override_out(db, st["override"]) if st["override"] is not None else None,
        "active": _row_out(db, st["active"]) if st["active"] is not None else None,
        "last_failure": _row_out(db, st["last_failure"]) if st["last_failure"] is not None else None,
        "ai_inputs_changed": st["ai_inputs_changed"],
        "override_stale": st["override_stale"],
        "ai_suggests": st["ai_suggests"],
        "redirect_chain": chains.get((st["asset"].id, st["port"]), []),
    }
    if with_asset:
        out["asset_id"] = str(st["asset"].id)
        out["asset_value"] = st["asset"].value
        out["asset_type"] = st["asset"].asset_type
    return out


def _endpoints_state(db: Session, user: User, asset: AssetCanonical) -> list[dict]:
    return _states_out(db, user, web_classifier.asset_endpoint_states(db, asset))


def _visible_asset(db: Session, user: User, asset_id: uuid.UUID) -> AssetCanonical:
    asset = db.execute(
        select(AssetCanonical).where(AssetCanonical.id == asset_id, read_scope.asset_clause(user, AssetCanonical))
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/assets/{asset_id}/web-classifications")
def get_web_classifications(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    asset = _visible_asset(db, current_user, asset_id)
    return {"endpoints": _endpoints_state(db, current_user, asset)}


@router.post("/assets/{asset_id}/web-classifications")
def request_web_classifications(
    asset_id: uuid.UUID,
    request: Request,
    background_tasks: BackgroundTasks,
    force: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Classify the asset's web endpoints, or return the cached ones when the
    input is unchanged. Every refusal happens before a row exists or any
    request is sent: unknown asset (404); no web endpoint, connector or AI
    models not configured, or every endpoint already running (409)."""
    asset = _visible_asset(db, current_user, asset_id)
    try:
        results = web_classifier.request_classifications(db, asset=asset, user_id=current_user.id, force=force)
    except (web_classifier.NotEligible, web_classifier.NotConfigured, web_classifier.AlreadyRunning) as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    queued = [row.id for row, cached in results if not cached]
    cached_count = len(results) - len(queued)
    if queued:
        audit.record_detail(
            request, asset_id=str(asset_id), queued=[str(i) for i in queued], cached=cached_count, force=force,
        )
        # planning#134: another on-demand background task the job queue retires.
        background_tasks.add_task(web_classifier.run_in_background, queued)
    asset = _visible_asset(db, current_user, asset_id)
    return {"queued": len(queued), "cached": cached_count, "endpoints": _endpoints_state(db, current_user, asset)}


@router.put("/assets/{asset_id}/web-endpoints/{port}/classification")
def set_web_classification_override(
    asset_id: uuid.UUID,
    data: OverrideIn,
    request: Request,
    port: int = Path(ge=1, le=65535),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Correct the endpoint's classification. The correction wins over the
    AI value until it is removed; 409 when the port is not a recorded web
    endpoint."""
    asset = _visible_asset(db, current_user, asset_id)
    try:
        ov, before = web_classifier.set_override(
            db, asset=asset, port=port, kind=data.kind, environment=data.environment,
            reason=data.reason, user=current_user,
        )
    except web_classifier.NotEligible as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    audit.record_detail(
        request, asset_id=str(asset_id), port=port, web_classification_override={
            "from": before, "to": {"kind": ov.kind, "environment": ov.environment},
        }, reason_given=ov.reason is not None,
    )
    state = next(st for st in web_classifier.asset_endpoint_states(db, asset) if st["port"] == port)
    return _states_out(db, current_user, [state])[0]


@router.delete("/assets/{asset_id}/web-endpoints/{port}/classification")
def clear_web_classification_override(
    asset_id: uuid.UUID,
    request: Request,
    port: int = Path(ge=1, le=65535),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """Remove the correction so the AI value applies again; 404 when there
    is none."""
    asset = _visible_asset(db, current_user, asset_id)
    removed = web_classifier.clear_override(db, asset=asset, port=port)
    if removed is None:
        raise HTTPException(status_code=404, detail="No correction on this endpoint")
    audit.record_detail(
        request, asset_id=str(asset_id), port=port, web_classification_override={"from": removed, "to": None},
    )
    state = next((st for st in web_classifier.asset_endpoint_states(db, asset) if st["port"] == port), None)
    return _states_out(db, current_user, [state])[0] if state is not None else {"port": port, "removed": True}


@router.get("/web-endpoints")
def list_web_endpoints(
    kind: Kind | None = None,
    source: Literal["ai", "user", "none"] | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Every web endpoint on the assets the caller may read (not ignored,
    not `not_ours`), with its effective classification."""
    page, total = web_classifier.list_endpoints(
        db, current_user, kind=kind, source=source, limit=limit, offset=offset,
    )
    return {
        "items": _states_out(db, current_user, page, with_asset=True),
        "total": total,
        "limit": limit,
        "offset": offset,
    }
