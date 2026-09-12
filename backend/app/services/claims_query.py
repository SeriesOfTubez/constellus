"""Claims-layer query surface (planning#145, L4 — the epic's final slice).

L0-L3 (planning#141-#144) built the grounding ontology, the current-claims
store, and the projector that folds claims down into `asset_state`. This
module is what every consumer reads that projection *through* — the crisp
mechanical predicate planning#130 (asset hygiene / Coverage-unmanaged) and
planning#79 (staleness retirement) key off is **`surface(asset) ==
"not_ours"`** (or, for the absence primitive, "no claim of type T"), never
the IONIX operational-layer view. IONIX's third-party ring is ontological
and reporting-only; nothing mechanical in this codebase reads it. Anything
that wants to *act* on ownership or coverage reads this module, and only
this module — a second inline copy of any of these queries anywhere else in
the codebase is a bug, not a convenience.

Two primitives live here:

  - `surface` / `surface_by_asset` / `asset_ids_with_surface` — the estate
    tri-state (`proven_ours` / `claimed_ours` / `not_ours`) plus a fourth,
    query-layer-only value, `"unknown"`. Per the planning#145 settled
    decision, `asset_state.estate` stays nullable and the projector keeps
    writing NULL when there is no ownership signal (see
    `app.services.projector`'s own comment on this — it deliberately
    refuses to invent a stored default). Mapping NULL, and the absence of
    an `asset_state` row altogether, to `"unknown"` happens ONLY here, at
    read time. Why unknown must be a first-class, legible value rather than
    quietly falling in with `not_ours`: planning#130 requires unknown to
    rank *below* not_ours for hygiene scoring — "a machine nothing reports
    on is a machine nobody is managing" is a worse finding than a machine
    we've positively excluded, and collapsing the two would hide exactly
    the assets that matter most.

  - `missing_claim_asset_ids` / `assets_missing_claim` — the absence
    primitive. "No asset_claims row of claim_type T (optionally from a
    specific observer)" cannot be expressed as equality or an inner join —
    it is a NOT-IN/NOT-EXISTS over `asset_claims`, and it must return an
    asset with *zero* claims of any kind just as readily as one with many
    claims of other types. The worked example the epic is built around:
    an internet-visible asset with no EDR claim and no device-management
    claim is an unmanaged asset (planning#130's Coverage dimension).

No TTL is applied by anything in this module. `claim_types.authorisation_ttl`
is the *authorisation* freshness window the cross-epic probe-authorisation
gate (planning#128/#132) reads at authorisation time, to decide whether a
claim is fresh enough to license a probe. `surface()` and the absence
primitive are *reporting* consumers, not authorisation consumers, and
`claim_types.reporting_ttl` is seeded NULL for every claim type today (no
reporting-side staleness policy exists yet). Applying the 24h
`cloud_inventory` authorisation TTL here would make `estate` flap between
`proven_ours` and whatever the next-best signal is on a daily cycle, purely
because a credentialed connector's refresh cadence is longer than a day —
that is an authorisation-time concern, not a reporting-time one. State this
explicitly so a future edit doesn't "fix" what looks like a missing TTL
check by importing one from `claim_types` into this module.
"""

import uuid

from sqlalchemy.orm import Session

from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import ESTATE_VALUES, AssetState
from app.models.claim import CLAIM_TYPES, AssetClaim
from app.models.observer import Observer

# The query-layer-only fourth surface value — never stored, see module
# docstring. Derived from ESTATE_VALUES rather than re-listed by hand so a
# future stored estate value (there is no plan for one today) can't drift
# out of sync with what this module considers a valid surface.
SURFACE_UNKNOWN = "unknown"
SURFACE_VALUES: frozenset[str] = ESTATE_VALUES | {SURFACE_UNKNOWN}


# ── estate tri-state (+ unknown) ────────────────────────────────────────────

def surface_by_asset(db: Session, asset_ids) -> dict[uuid.UUID, str]:
    """Batch form of `surface` — one query for the whole id list.

    Every id in `asset_ids` appears in the returned dict, whether or not it
    has an `asset_state` row: ids with no row, and ids whose row has a NULL
    `estate`, both map to `SURFACE_UNKNOWN`. Callers therefore never need
    `.get(id, default)` — a plain `[id]` lookup is always safe. Follows the
    batching discipline in `projector.load_states()`: no N+1, one
    `IN (...)` query regardless of how many ids are requested. Empty input
    returns `{}` without querying.
    """
    ids = list(asset_ids)
    if not ids:
        return {}
    estate_by_id = {
        asset_id: estate
        for asset_id, estate in (
            db.query(AssetState.asset_canonical_id, AssetState.estate)
            .filter(AssetState.asset_canonical_id.in_(ids))
            .all()
        )
    }
    return {asset_id: estate_by_id.get(asset_id) or SURFACE_UNKNOWN for asset_id in ids}


def surface(db: Session, asset_id: uuid.UUID) -> str:
    """The estate tri-state for one asset, plus `"unknown"`.

    Always returns a value from `SURFACE_VALUES`, never `None` — a missing
    `asset_state` row and an `estate IS NULL` row both surface as
    `"unknown"` (see module docstring). Implemented in terms of
    `surface_by_asset` rather than the other way round, so there is exactly
    one place the NULL-mapping rule lives.
    """
    return surface_by_asset(db, [asset_id])[asset_id]


def asset_ids_with_surface(db: Session, surface_value: str):
    """Scalar subquery of asset ids whose surface is `surface_value`.

    For callers that want to filter a larger `assets_canonical` query by
    estate — the shape `app.api.assets._third_party_asset_ids` already
    needs (now implemented by calling this with `"not_ours"`). Raises
    `ValueError` if `surface_value` is not one of `SURFACE_VALUES`.

    `"unknown"` cannot be a simple equality filter over `asset_state`: it
    means `estate IS NULL` **or no `asset_state` row exists at all**, and a
    naive `AssetState.estate == None` filter only ever matches rows that
    exist. So the unknown branch is expressed as a NOT-IN over the ids that
    DO have a non-NULL estate, over the full `assets_canonical` id space —
    that correctly includes assets with no projection yet. The three stored
    values stay a direct equality filter over `asset_state`, same shape as
    the pre-existing inline query this replaces.
    """
    if surface_value not in SURFACE_VALUES:
        raise ValueError(
            f"Unknown surface value: {surface_value!r} (expected one of {sorted(SURFACE_VALUES)})"
        )
    if surface_value == SURFACE_UNKNOWN:
        non_unknown_ids = (
            db.query(AssetState.asset_canonical_id)
            .filter(AssetState.estate.isnot(None))
            .scalar_subquery()
        )
        return (
            db.query(AssetCanonical.id)
            .filter(~AssetCanonical.id.in_(non_unknown_ids))
            .scalar_subquery()
        )
    return (
        db.query(AssetState.asset_canonical_id)
        .filter(AssetState.estate == surface_value)
        .scalar_subquery()
    )


# ── the absence primitive ───────────────────────────────────────────────────

def missing_claim_asset_ids(db: Session, claim_type: str, observer_name: str | None = None):
    """Scalar subquery of `assets_canonical` ids carrying NO `asset_claims`
    row of `claim_type` — from `observer_name` specifically if given, from
    ANY observer if not.

    This is the absence primitive planning#130's "unmanaged" query and
    planning#79's staleness retirement both key off. Raises `ValueError` if
    `claim_type` is not in `CLAIM_TYPES`, and `ValueError` if `observer_name`
    is given but isn't a seeded `Observer.name` — an unknown observer would
    otherwise silently mean "every asset lacks a claim from them", which is
    trivially true and exactly the kind of confidently-wrong answer that
    gets acted on. Fail loud instead of returning "everything".

    Expressed as a NOT-IN over the ids that DO carry a matching claim, over
    the full `assets_canonical` id space — never as an anti-join gated on
    an `asset_claims` or `asset_state` row existing, which would silently
    exclude an asset with zero claims of any kind instead of returning it
    (the exact case this primitive exists to catch).
    """
    if claim_type not in CLAIM_TYPES:
        raise ValueError(f"Unknown claim_type: {claim_type!r} (expected one of {sorted(CLAIM_TYPES)})")

    filters = [AssetClaim.claim_type == claim_type]
    if observer_name is not None:
        observer_id = db.query(Observer.id).filter(Observer.name == observer_name).scalar()
        if observer_id is None:
            raise ValueError(f"Unknown observer_name: {observer_name!r}")
        filters.append(AssetClaim.observer_id == observer_id)

    having_claim_ids = db.query(AssetClaim.asset_canonical_id).filter(*filters).scalar_subquery()
    return (
        db.query(AssetCanonical.id)
        .filter(~AssetCanonical.id.in_(having_claim_ids))
        .scalar_subquery()
    )


def assets_missing_claim(
    db: Session,
    claim_type: str,
    observer_name: str | None = None,
    asset_type: str | None = None,
    surface_value: str | None = None,
    include_ignored: bool = False,
    limit: int = 1000,
) -> list[AssetCanonical]:
    """Row-returning form of `missing_claim_asset_ids`, with the filters a
    real caller layers on top (all AND-composed).

    `surface_value` lets a caller narrow the universe without this module
    baking a policy into it — planning#130's "unmanaged" query is exactly
    `surface_value` excluded-`not_ours` AND missing an EDR claim, composed
    by the caller from these two primitives rather than encoded here.
    Excludes *currently suppressed* assets unless `include_ignored=True`
    — an asset whose `ignore_expires_at` has passed is NOT excluded. Ordered by
    `last_seen_at DESC`, matching `list_assets`, and capped at `limit`.
    `ValueError`s from `missing_claim_asset_ids` / `asset_ids_with_surface`
    (bad claim_type / observer_name / surface_value) propagate unchanged —
    this function validates nothing itself, it only composes.
    """
    q = db.query(AssetCanonical).filter(
        AssetCanonical.id.in_(missing_claim_asset_ids(db, claim_type, observer_name))
    )
    if asset_type is not None:
        q = q.filter(AssetCanonical.asset_type == asset_type)
    if not include_ignored:
        # `suppressed`, not `ignored`: an ignore whose expiry has passed
        # must reappear in the absence query — that is the point of
        # having an expiry (migration 0047).
        q = q.filter(~AssetCanonical.suppressed)
    if surface_value is not None:
        q = q.filter(AssetCanonical.id.in_(asset_ids_with_surface(db, surface_value)))
    return q.order_by(AssetCanonical.last_seen_at.desc()).limit(limit).all()
