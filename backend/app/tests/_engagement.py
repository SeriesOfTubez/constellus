"""Shared fixture helper for engagement-posture tests (planning#211).

`make_engagement` replaces the ~100 call sites across the suite that used
to set a bare posture boolean on `Target` directly. A test that needs a
restricting (or any-posture) target now creates an `Engagement` row with
this helper and points a `Target.engagement_id` at its `.id`, instead of
repeating the insert inline.

## Cleanup order

`targets.engagement_id` is `ON DELETE RESTRICT` (migration 0059) —
deleting an `Engagement` row while a `Target` still points at it raises.
Callers must delete (or detach) every linked target BEFORE calling
`cleanup_engagement`, the same "delete decision rows before assets"
discipline this suite already follows for `authorisation_decisions` /
`assets_canonical`.
"""

import uuid

from app.models.engagement import Engagement, EngagementPosture


def make_engagement(db, posture: str = EngagementPosture.PRE_CLOSE.value, **overrides) -> Engagement:
    """Insert and commit a throwaway `Engagement` row, unique name by
    default (`uuid.uuid4().hex` — never a real company name, per
    feedback_real_customer_data). `overrides` may set `name`,
    `authorised_at`, `authorised_by_id`, `authorisation_reference`, etc. —
    whatever a specific test's CHECK-constraint or authorisation-record
    coverage needs; the caller is responsible for satisfying
    `ck_engagements_authorisation_matches_posture` when it sets those by
    hand (e.g. `day_0` requires both `authorised_at` and
    `authorisation_reference` non-null).
    """
    overrides.setdefault("name", f"pa211-engagement-{uuid.uuid4().hex[:10]}")
    e = Engagement(id=uuid.uuid4(), posture=posture, **overrides)
    db.add(e)
    db.commit()
    return e


def cleanup_engagement(db, engagement_id: uuid.UUID | None) -> None:
    """Delete one engagement by id. No-op on `None` so callers can pass an
    optional/never-created id unconditionally in a `finally` block. Must be
    called AFTER every target that links to it is deleted or detached —
    see module docstring."""
    if engagement_id is None:
        return
    db.query(Engagement).filter(Engagement.id == engagement_id).delete(synchronize_session=False)
    db.commit()
