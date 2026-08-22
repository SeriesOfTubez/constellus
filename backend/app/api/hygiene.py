"""Asset hygiene score API (planning#130, L1).

Read-only endpoints over the `asset_hygiene_score` table
`app.services.hygiene_scorer.run()` populates nightly, plus one admin-only
trigger to run it synchronously on demand. Follows `app/api/claims.py`'s
conventions exactly: a plain `APIRouter`, `_=Depends(get_current_user)` for
reads, `HTTPException` rather than a custom response envelope, and
`ValueError`-to-422 translation happening once, here, at the HTTP boundary
— `hygiene_scorer` and `claims_query` stay free to raise `ValueError` for
their own preconditions without importing FastAPI to describe them.

All the actual scoring logic (the five dimensions, the settled "unknown
ranks below bad" rule, the batching) lives in `hygiene_scorer` and is
unit-tested there (`test_hygiene_scorer.py`). This module's job is boundary
concerns only: 404 vs. "no score yet" vs. "excluded" disambiguation for the
single-asset read, band-filter validation for the list read, and the RBAC
gate on the recompute trigger.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.asset_hygiene_score import BAND_VALUES, AssetHygieneScore
from app.models.user import UserRole
from app.services import claims_query, hygiene_scorer

router = APIRouter()


@router.get("/{asset_id}")
def get_hygiene_score(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """One asset's hygiene score, or an explanation of why it has none.

    404s if `asset_id` doesn't resolve to an `assets_canonical` row at all
    — distinct from a row that exists but was never scored (or was scored
    once and then excluded), which is a 200 with `"scored": false` and a
    `reason`:

      * `"excluded_not_ours"` — `claims_query.surface(asset) == "not_ours"`;
        `hygiene_scorer.run()` deliberately never scores (and deletes any
        stale score for) an asset in this state.
      * `"not_yet_computed"` — everything else: the nightly job hasn't run
        since this asset started existing/qualifying, or is between runs.

    The two are told apart by calling `surface()` rather than guessing from
    context, same disambiguation `app/api/claims.py`'s `get_surface`
    endpoint already does for the estate tri-state itself.
    """
    exists = db.query(AssetCanonical.id).filter(AssetCanonical.id == asset_id).first()
    if exists is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    row = db.get(AssetHygieneScore, asset_id)
    if row is None:
        surface_value = claims_query.surface(db, asset_id)
        reason = "excluded_not_ours" if surface_value == "not_ours" else "not_yet_computed"
        return {"asset_id": str(asset_id), "scored": False, "reason": reason}

    return {
        "asset_id": str(asset_id),
        "scored": True,
        "score": row.score,
        "band": row.band,
        "dimensions": row.dimensions,
        "computed_at": row.computed_at.isoformat(),
    }


@router.get("/")
def list_hygiene_scores(
    band: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Worst-first list of scored assets (`score ASC` — the whole point of
    pre-computing this table is that this is a plain indexed sort, not a
    per-row aggregation).

    `band`, if given, must be one of `BAND_VALUES` or this 422s — same
    shape as `app/api/claims.py`'s `get_absence` claim_type guard.
    `asset_type`/`value` come from a single join against `assets_canonical`
    (one query), never a per-row lookup.
    """
    if band is not None and band not in BAND_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown band: {band!r} (expected one of {sorted(BAND_VALUES)})",
        )

    q = db.query(AssetHygieneScore, AssetCanonical.asset_type, AssetCanonical.value).join(
        AssetCanonical, AssetHygieneScore.asset_canonical_id == AssetCanonical.id
    )
    if band is not None:
        q = q.filter(AssetHygieneScore.band == band)
    q = q.order_by(AssetHygieneScore.score.asc()).limit(limit)

    return [
        {
            "asset_id": str(row.asset_canonical_id),
            "asset_type": asset_type,
            "value": value,
            "score": row.score,
            "band": row.band,
            "dimensions": row.dimensions,
            "computed_at": row.computed_at.isoformat(),
        }
        for row, asset_type, value in q.all()
    ]


@router.post("/recompute")
def recompute_hygiene_scores(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Run `hygiene_scorer.run()` synchronously and return its stats dict.

    Admin-only (not INTEGRATION_ADMIN too, unlike most write endpoints in
    this codebase) — this is a full sweep over every in-scope asset, not a
    scoped write, and there's no legitimate integration use case for
    triggering it out of band from the nightly schedule.
    """
    return hygiene_scorer.run(db)
