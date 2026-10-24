"""An active zone in a connector account claims its own domain (planning#277 S1b).

A connector instance is created by a person and bound to an organization, and
its credentials prove control of every zone the provider lists as active. So an
active zone is a Strong `connector_zone` signal that this organization owns the
domain, and `process_zone` acts on it: it verifies the target AND claims the
candidate under the instance's bound organization (a "system claim": the person
who created the connector passively decided). Inferred signals (reverse IP,
verifiers) still need a person.

A zone that cannot be acted on is never skipped silently: it becomes a
`connector_zone_clashes` row for a person to look at. A person's rejection
outranks the connector: the signal is recorded (it can unlock a candidate only
the way any new Strong signal does) but nothing is verified or claimed.

Transaction ownership: `process_zone` is a SESSION OWNER's call, one zone per
unit of work, because `entity_graph.store_evidence` commits. The evidence is
therefore stored BEFORE the target is touched, so that commit never carries a
half-written target. `resolve_unlisted` and the clash upsert only flush.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.connector_instance import ConnectorInstance
from app.models.connector_zone_clash import ConnectorZoneClash
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent
from app.models.target import Target
from app.services import entity_graph, target_service
from app.services.connector_instances import SCOPE_ESTATE, instance_scope_key
from app.services.org_discovery import candidates

CLAIMED = "claimed"
ALREADY_CLAIMED = "already_claimed"
SIGNAL_ONLY_REJECTED = "signal_only_rejected"
CLASH = "clash"

log = logging.getLogger(__name__)


@dataclass
class ZoneOutcome:
    action: str
    target: Target | None = None
    candidate_id: uuid.UUID | None = None
    created_candidate: bool = False
    claimed: bool = False
    left_open: bool = False  # a candidate now `open` that this zone created or unlocked


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _open_clash(db: Session, instance_id: uuid.UUID, zone: str) -> ConnectorZoneClash | None:
    return db.execute(
        select(ConnectorZoneClash).where(
            ConnectorZoneClash.instance_id == instance_id,
            ConnectorZoneClash.zone == zone,
            ConnectorZoneClash.resolved_at.is_(None),
        )
    ).scalar_one_or_none()


def _upsert_clash(
    db: Session, *, instance_id: uuid.UUID, zone: str, reason: str,
    candidate_id: uuid.UUID | None = None, target_id: uuid.UUID | None = None,
) -> None:
    """One unresolved row per (instance, zone). Flushes."""
    row = _open_clash(db, instance_id, zone)
    now = _now()
    if row is None:
        db.add(ConnectorZoneClash(
            id=uuid.uuid4(), instance_id=instance_id, zone=zone, reason=reason,
            conflicting_candidate_id=candidate_id, conflicting_target_id=target_id,
            first_seen_at=now, last_seen_at=now,
        ))
    else:
        row.reason = reason
        row.conflicting_candidate_id = candidate_id
        row.conflicting_target_id = target_id
        row.last_seen_at = now
    db.flush()


def _resolve_clash(db: Session, instance_id: uuid.UUID, zone: str) -> None:
    row = _open_clash(db, instance_id, zone)
    if row is not None:
        row.resolved_at = _now()
        db.flush()


def resolve_unlisted(db: Session, *, instance: ConnectorInstance, listed: set[str]) -> int:
    """Resolve the instance's open clashes for zones no longer listed. Flushes."""
    keep = {target_service.canonicalize_value(z) for z in listed}
    now = _now()
    n = 0
    for row in db.execute(
        select(ConnectorZoneClash).where(
            ConnectorZoneClash.instance_id == instance.id, ConnectorZoneClash.resolved_at.is_(None)
        )
    ).scalars():
        if row.zone not in keep:
            row.resolved_at = now
            n += 1
    db.flush()
    return n


def _store_zone_evidence(db: Session, *, instance: ConnectorInstance, value: str):
    body = json.dumps(
        {
            "rule": "connector_zone", "instance_id": str(instance.id), "connector_type": instance.type,
            "zone": value, "zone_status": "active",
        },
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    # No timestamp in the body and a stable source_url: a re-sync reuses the
    # same evidence row and the same signal row (only last_seen_at moves).
    evidence = entity_graph.store_evidence(
        db,
        content=body,
        content_type="application/json",
        source_url=f"https://org-discovery.invalid/generate/connector_zone/{instance.id}/{value}",
        fetched_at=_now(),
        origin="fetched",
    )
    return evidence


def _conflict(
    db: Session, *, instance: ConnectorInstance, root_id: uuid.UUID, value: str, lock: bool,
) -> tuple[str, uuid.UUID | None, uuid.UUID | None] | None:
    """Steps 2 and 4: (reason, candidate_id, target_id) of the first clash, or
    None. With `lock` the existing target is selected FOR UPDATE, so a person's
    claim cannot attribute it to another entity between this check and the
    writes that follow (the lock lasts until the caller's commit)."""
    # 2. Claimed by another organization: nothing else is touched. Two `ours`
    # roots share the estate scope, so the target check alone would not see it.
    other = db.execute(
        select(ScopeCandidate).where(
            ScopeCandidate.kind == "domain", ScopeCandidate.value == value,
            ScopeCandidate.status == "claimed", ScopeCandidate.root_entity_id != root_id,
        ).order_by(ScopeCandidate.id).limit(1)
    ).scalar_one_or_none()
    if other is not None:
        return "claimed_by_other_org", other.id, None

    # 4. A target for the value is attributed to an entity outside this
    # organization's tree. (A person's claim attributes the target to the
    # AFFILIATED entity, which may be a subsidiary in the tree: not a clash.)
    q = select(Target).where(Target.value == value)
    if lock:
        # populate_existing: a Target already in the identity map must be
        # refreshed from the locked read, not served stale.
        q = q.with_for_update().execution_options(populate_existing=True)
    existing = db.execute(q).scalar_one_or_none()
    if existing is None:
        return None
    if (
        existing.entity_id is not None and existing.entity_id != root_id
        and not candidates._in_tree(db, root_id, existing.entity_id)
    ):
        return "target_other_entity", None, existing.id
    own_scope = instance_scope_key(db, instance)
    existing_scope = SCOPE_ESTATE if existing.engagement_id is None else str(existing.engagement_id)
    if own_scope != existing_scope:
        return "target_in_other_scope", None, existing.id
    return None


def process_zone(db: Session, *, instance: ConnectorInstance, zone: str) -> ZoneOutcome:
    """One zone of one connector instance. Session owner only; the caller
    commits (or rolls back) the unit of work."""
    root_id = instance.bound_entity_id
    if root_id is None:
        raise ValueError(f"connector instance {instance.id} is not bound to an organization")
    instance_id = instance.id

    # 1. Only a zone that is already in claimable form is acted on. The signal
    # stores `normalise_domain(zone)`, which strips `www.`; controlling a `www.`
    # zone does not prove control of the apex, so any difference is a clash
    # and nothing is queried or written for either form.
    canonical = target_service.canonicalize_value(zone or "")
    try:
        value = candidates.normalise_domain(zone)
    except candidates.CandidateInvalid:
        value = None
    if value is None or value != canonical:
        clash_zone = canonical or (zone or "").strip()
        if not clash_zone:
            raise ValueError("connector zone is blank")
        log.warning("Connector %s listed a zone that is not claimable: %r", instance_id, zone)
        _upsert_clash(db, instance_id=instance_id, zone=clash_zone, reason="not_a_claimable_domain")
        return ZoneOutcome(action=CLASH)

    clash = _conflict(db, instance=instance, root_id=root_id, value=value, lock=False)
    if clash is not None:
        reason, cand_id, target_id = clash
        _upsert_clash(db, instance_id=instance_id, zone=value, reason=reason, candidate_id=cand_id, target_id=target_id)
        return ZoneOutcome(action=CLASH, candidate_id=cand_id)

    # 3. A person rejected it under this root: the rejection outranks the
    # connector. Record the signal; verify and claim nothing.
    own = db.execute(
        select(ScopeCandidate).where(
            ScopeCandidate.root_entity_id == root_id, ScopeCandidate.kind == "domain",
            ScopeCandidate.value == value,
        )
    ).scalar_one_or_none()
    if own is not None:
        was_rejected = own.status == "rejected" or db.execute(
            select(ScopeCandidateEvent.id).where(
                ScopeCandidateEvent.candidate_id == own.id, ScopeCandidateEvent.event == "rejected"
            ).limit(1)
        ).first() is not None
        if was_rejected:
            evidence = _store_zone_evidence(db, instance=instance, value=value)
            outcome = candidates.record_signal(
                db, root_entity_id=root_id, value=value, signal_type="connector_zone",
                anchor_kind="connector_instance", anchor_connector_instance_id=instance_id,
                via_entity_id=root_id, evidence_id=evidence.id,
                quote=f"{value} is an active zone in connector instance {instance_id}",
            )
            cand = outcome.candidate
            return ZoneOutcome(
                action=SIGNAL_ONLY_REJECTED, candidate_id=cand.id if cand is not None else own.id,
                left_open=cand is not None and cand.status == "open",
            )

    existing_id = db.execute(select(Target.id).where(Target.value == value)).scalar_one_or_none()

    # 6a. Evidence first: store_evidence commits, and nothing is half-written yet.
    evidence = _store_zone_evidence(db, instance=instance, value=value)

    # store_evidence committed, so no lock from above survives it: check again,
    # this time locking the target, before anything is written to it. (A
    # clash here leaves the evidence; the next sync reuses it.)
    clash = _conflict(db, instance=instance, root_id=root_id, value=value, lock=True)
    if clash is not None:
        reason, cand_id, target_id = clash
        _upsert_clash(db, instance_id=instance_id, zone=value, reason=reason, candidate_id=cand_id, target_id=target_id)
        return ZoneOutcome(action=CLASH, candidate_id=cand_id)

    # 5. The target. (None only if a target appeared since the read above.)
    target = target_service.ensure_connector_verified(db, value, instance)
    if target is None:
        _upsert_clash(
            db, instance_id=instance_id, zone=value, reason="target_in_other_scope", target_id=existing_id,
        )
        return ZoneOutcome(action=CLASH)
    if target.entity_id is None:
        target.entity_id = root_id
        db.flush()

    # 6b. The signal.
    sig = candidates.record_signal(
        db, root_entity_id=root_id, value=value, signal_type="connector_zone",
        anchor_kind="connector_instance", anchor_connector_instance_id=instance_id,
        via_entity_id=root_id, evidence_id=evidence.id,
        quote=f"{value} is an active zone in connector instance {instance_id}",
    )
    cand = sig.candidate
    if cand is None:
        raise RuntimeError("connector_zone signal produced no candidate")

    # 7. The claim.
    if cand.status == "open":
        candidates.claim_by_connector(db, candidate=cand, instance=instance, target=target)
        _resolve_clash(db, instance_id, value)
        return ZoneOutcome(
            action=CLAIMED, target=target, candidate_id=cand.id, created_candidate=sig.created_candidate,
            claimed=True,
        )
    if cand.status == "claimed":
        _resolve_clash(db, instance_id, value)
        return ZoneOutcome(
            action=ALREADY_CLAIMED, target=target, candidate_id=cand.id, created_candidate=sig.created_candidate,
        )
    # Rejected between the check above and now: the person's decision stands,
    # and the target verified above must not be committed. Raise so the
    # caller rolls this zone back; the next sync takes the step-3 path.
    raise candidates.CandidateConflict(
        f"candidate {cand.id} became {cand.status} during the zone sync; zone rolled back"
    )
