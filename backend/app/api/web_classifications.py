"""AI web-app classification API (planning#231 slice 1).

- `GET  /api/assets/{asset_id}/web-classifications` - per web endpoint: the
  current proposal/decision, any active run, the latest failure, and whether
  the inputs changed since. Never generates anything.
- `POST /api/assets/{asset_id}/web-classifications` (ADMIN) - classify the
  asset's web endpoints, or return the cached ones when the input is
  unchanged (no call). `force` skips the cache.
- `GET  /api/web-classifications` - the review queue (proposals by default).
- `POST /api/web-classifications/{id}/decision` (ADMIN) - accept or reject a
  proposal. Accepting adds asset tags; nothing else changes.

A classification is a proposal and writes no score, attribution or
estate (see `app.services.web_classifier`). Reads are limited to the assets
`read_scope.asset_clause` lets the caller see.
"""

import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.user import User, UserRole
from app.models.web_classification import WebClassification
from app.services import audit, read_scope, web_classifier

router = APIRouter()


class DecisionIn(BaseModel):
    decision: Literal["accepted", "rejected"]


def _row_out(db: Session, row: WebClassification) -> dict:
    return {
        "id": str(row.id),
        "port": row.port,
        "status": row.status,
        "decision": row.decision,
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
        "decided_by_id": str(row.decided_by_id) if row.decided_by_id else None,
        "decided_at": row.decided_at,
        "created_at": row.created_at,
        "finished_at": row.finished_at,
        "cost_usd": web_classifier.cost_usd(db, row.ledger_ids or []),
    }


def _endpoints_state(db: Session, asset: AssetCanonical) -> list[dict]:
    out = []
    for entry in web_classifier.web_endpoints(db, asset):
        port = entry["port"]
        current = web_classifier.latest_succeeded(db, asset.id, port)
        active = web_classifier.active_row(db, asset.id, port)
        newest = web_classifier.latest_any(db, asset.id, port)
        failure = newest if newest is not None and newest.status == "failed" else None
        inputs_changed = None
        if current is not None:
            inputs_changed = current.input_hash != web_classifier.input_hash(web_classifier.build_input(asset, entry))
        out.append({
            "port": port,
            "current": _row_out(db, current) if current is not None else None,
            "active": _row_out(db, active) if active is not None else None,
            "last_failure": _row_out(db, failure) if failure is not None else None,
            "inputs_changed": inputs_changed,
        })
    return out


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
    return {"endpoints": _endpoints_state(db, asset)}


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
    return {"queued": len(queued), "cached": cached_count, "endpoints": _endpoints_state(db, asset)}


@router.get("/web-classifications")
def list_web_classifications(
    decision: Literal["proposed", "accepted", "rejected", "superseded"] = "proposed",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """The review queue: classifications with this decision, newest first,
    on the assets the caller may read."""
    rows = db.execute(
        select(WebClassification, AssetCanonical.value)
        .join(AssetCanonical, AssetCanonical.id == WebClassification.asset_canonical_id)
        .where(WebClassification.decision == decision, read_scope.asset_clause(current_user, AssetCanonical))
        .order_by(WebClassification.created_at.desc(), WebClassification.id.desc())
        .limit(limit).offset(offset)
    ).all()
    return {
        "items": [
            {**_row_out(db, row), "asset_id": str(row.asset_canonical_id), "asset_value": value}
            for row, value in rows
        ],
        "limit": limit,
        "offset": offset,
    }


@router.post("/web-classifications/{classification_id}/decision")
def decide_web_classification(
    classification_id: uuid.UUID,
    data: DecisionIn,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    row = db.get(WebClassification, classification_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Classification not found")
    _visible_asset(db, current_user, row.asset_canonical_id)
    try:
        row, tags_added = web_classifier.decide(
            db, row_id=classification_id, decision=data.decision, user=current_user,
        )
    except web_classifier.DecisionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    audit.record_detail(
        request, web_classification=str(classification_id), asset_id=str(row.asset_canonical_id),
        decision={"from": "proposed", "to": data.decision}, tags_added=tags_added,
    )
    return {**_row_out(db, row), "asset_id": str(row.asset_canonical_id), "tags_added": tags_added}
