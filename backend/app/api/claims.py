"""Claims-layer query API (planning#145, L4).

Two read-only endpoints over `app.services.claims_query` — the epic's
final slice puts the estate tri-state and the absence primitive behind an
HTTP surface so the frontend (and any future automation) can read them
without importing a service module directly. Follows `app/api/edges.py`'s
conventions: a plain `APIRouter`, `_=Depends(get_current_user)` for
read-only access (same as `list_assets`), and `HTTPException` for error
shapes rather than a custom response envelope.

Both endpoints are thin: all the actual query logic — the NULL-mapping
rule for "unknown", the NOT-IN absence primitive, the composable filters —
lives in `claims_query` and is unit-tested there (`test_claims_query.py`).
This module's own job is boundary validation: turning a `ValueError` raised
by `claims_query` (unknown claim_type / observer_name / surface value) into
a 422 with a clear detail, rather than letting it 500. `claims_query` stays
free to keep raising `ValueError` — a service module shouldn't import
FastAPI to describe its own preconditions — so this translation happens
once, here, at the one place callers actually cross the HTTP boundary.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.claim import CLAIM_TYPES
from app.services import claims_query

router = APIRouter()


@router.get("/surface/{asset_id}")
def get_surface(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """The estate tri-state (plus `"unknown"`) for one asset.

    404s if `asset_id` doesn't resolve to an `assets_canonical` row at
    all — distinct from `"unknown"`, which means the row exists but has no
    ownership signal yet (see `claims_query`'s module docstring).
    """
    exists = db.query(AssetCanonical.id).filter(AssetCanonical.id == asset_id).first()
    if exists is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"asset_id": str(asset_id), "surface": claims_query.surface(db, asset_id)}


@router.get("/absence")
def get_absence(
    claim_type: str,
    observer: str | None = None,
    asset_type: str | None = None,
    surface: str | None = None,
    include_ignored: bool = False,
    limit: int = Query(1000, ge=1, le=1000),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Assets carrying no `claim_type` claim (optionally scoped to one
    `observer`), the absence primitive's row-returning form.

    `claim_type` is required; an unrecognised value, an unrecognised
    `observer` name, or an unrecognised `surface` value each 422 rather
    than silently matching "every asset" or 500ing — `claims_query` raises
    `ValueError` for exactly these cases and this endpoint is the boundary
    that turns them into a client-correctable error. `surface` on every
    returned row comes from one batched `surface_by_asset` call, never a
    per-row lookup.
    """
    if claim_type not in CLAIM_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown claim_type: {claim_type!r} (expected one of {sorted(CLAIM_TYPES)})",
        )
    if surface is not None and surface not in claims_query.SURFACE_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown surface: {surface!r} (expected one of {sorted(claims_query.SURFACE_VALUES)})",
        )

    try:
        assets = claims_query.assets_missing_claim(
            db,
            claim_type,
            observer_name=observer,
            asset_type=asset_type,
            surface_value=surface,
            include_ignored=include_ignored,
            limit=limit,
        )
    except ValueError as exc:
        # The only ValueError assets_missing_claim can still raise past the
        # claim_type/surface checks above is an unrecognised observer_name
        # (missing_claim_asset_ids' own guard) — surfaced as 422, same as
        # the checks above rather than a 500.
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    surface_by_id = claims_query.surface_by_asset(db, [a.id for a in assets])
    return [
        {
            "asset_id": str(a.id),
            "asset_type": a.asset_type,
            "value": a.value,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
            "surface": surface_by_id.get(a.id, claims_query.SURFACE_UNKNOWN),
        }
        for a in assets
    ]
