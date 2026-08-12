"""Tag-based monitoring cadence policies.

Operators tag targets and these policies decide how often each tag's
targets get scanned. Under the hood every policy is just a scan_template
with `dynamic_scope=True`, `target_tag_filter=[tag]`, and `tag_priority`
populated — the executor's resolver uses tag_priority to partition the
inventory so each target is owned by exactly one template (the lowest
matching tier, or the default monitoring template when no tier matches).

The default monitoring template (fixed UUID, seeded on first run) is
returned via this API with `is_default=True`. Its cron can be edited
but it can't be deleted, and it has no tag — it covers everything not
claimed by a tier.
"""

import logging
import uuid

from apscheduler.triggers.cron import CronTrigger
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.database import get_db
from app.models.scan_template import ScanTemplate
from app.models.user import UserRole
from app.services import scheduler

log = logging.getLogger(__name__)

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class MonitoringPolicy(BaseModel):
    id: uuid.UUID
    name: str
    tag: str | None
    schedule_cron: str
    tag_priority: int | None
    enabled: bool
    is_default: bool

    model_config = {"from_attributes": True}


class PolicyCreate(BaseModel):
    tag: str
    schedule_cron: str
    tag_priority: int = 100

    @field_validator("tag")
    @classmethod
    def _strip_tag(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("tag is required")
        return v

    @field_validator("schedule_cron")
    @classmethod
    def _validate_cron(cls, v: str) -> str:
        try:
            CronTrigger.from_crontab(v.strip(), timezone="UTC")
        except ValueError as exc:
            raise ValueError(f"Invalid cron expression: {exc}")
        return v.strip()


class PolicyUpdate(BaseModel):
    schedule_cron: str | None = None
    tag_priority: int | None = None
    enabled: bool | None = None

    @field_validator("schedule_cron")
    @classmethod
    def _validate_cron(cls, v: str | None) -> str | None:
        if v is None:
            return None
        try:
            CronTrigger.from_crontab(v.strip(), timezone="UTC")
        except ValueError as exc:
            raise ValueError(f"Invalid cron expression: {exc}")
        return v.strip()


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/policies", response_model=list[MonitoringPolicy])
def list_policies(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    """Return the default monitoring template + every cadence tier,
    sorted with the default first then tiers by priority."""
    rows = (
        db.query(ScanTemplate)
        .filter(ScanTemplate.dynamic_scope == True)  # noqa: E712
        .all()
    )
    # Default first (id == seeded UUID), then tiers by priority ascending
    rows.sort(key=lambda t: (
        0 if t.id == scheduler.DEFAULT_MONITORING_TEMPLATE_ID else 1,
        t.tag_priority if t.tag_priority is not None else 0,
        t.name,
    ))
    return [_to_response(t) for t in rows]


@router.post("/policies", response_model=MonitoringPolicy, status_code=status.HTTP_201_CREATED)
def create_policy(
    data: PolicyCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    existing = (
        db.query(ScanTemplate)
        .filter(ScanTemplate.dynamic_scope == True)  # noqa: E712
        .filter(ScanTemplate.target_tag_filter.contains([data.tag]))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A policy for tag '{data.tag}' already exists",
        )

    tmpl = ScanTemplate(
        id=uuid.uuid4(),
        name=f"Tag policy: {data.tag}",
        scope={},
        options={
            "cert_transparency": True,
            "subfinder": True,
            "dnsrecon": False,
            "bruteforce": False,
        },
        schedule_cron=data.schedule_cron,
        enabled=True,
        dynamic_scope=True,
        target_tag_filter=[data.tag],
        tag_priority=data.tag_priority,
        batch_size=50,
        batch_delay_seconds=0,
        created_by_id=current_user.id,
    )
    db.add(tmpl)
    db.commit()
    db.refresh(tmpl)

    scheduler.upsert_template_job(tmpl)
    log.info("Created monitoring policy %s for tag %r (priority=%d, cron=%r)",
             tmpl.id, data.tag, data.tag_priority, data.schedule_cron)
    return _to_response(tmpl)


@router.patch("/policies/{policy_id}", response_model=MonitoringPolicy)
def update_policy(
    policy_id: uuid.UUID,
    data: PolicyUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    tmpl = db.get(ScanTemplate, policy_id)
    if not tmpl or not tmpl.dynamic_scope:
        raise HTTPException(status_code=404, detail="Policy not found")

    if data.schedule_cron is not None:
        tmpl.schedule_cron = data.schedule_cron
    if data.tag_priority is not None:
        if tmpl.id == scheduler.DEFAULT_MONITORING_TEMPLATE_ID:
            raise HTTPException(
                status_code=400,
                detail="The default monitoring template can't have a tag_priority",
            )
        tmpl.tag_priority = data.tag_priority
    if data.enabled is not None:
        if tmpl.id == scheduler.DEFAULT_MONITORING_TEMPLATE_ID and not data.enabled:
            raise HTTPException(
                status_code=400,
                detail="The default monitoring template can't be disabled",
            )
        tmpl.enabled = data.enabled

    db.commit()
    db.refresh(tmpl)
    scheduler.upsert_template_job(tmpl)
    return _to_response(tmpl)


@router.delete("/policies/{policy_id}", status_code=204)
def delete_policy(
    policy_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    if policy_id == scheduler.DEFAULT_MONITORING_TEMPLATE_ID:
        raise HTTPException(
            status_code=400,
            detail="The default monitoring template can't be deleted",
        )
    tmpl = db.get(ScanTemplate, policy_id)
    if not tmpl or not tmpl.dynamic_scope:
        raise HTTPException(status_code=404, detail="Policy not found")
    scheduler.remove_template_job(tmpl.id)
    db.delete(tmpl)
    db.commit()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_response(t: ScanTemplate) -> MonitoringPolicy:
    is_default = t.id == scheduler.DEFAULT_MONITORING_TEMPLATE_ID
    tag = (t.target_tag_filter or [None])[0]
    return MonitoringPolicy(
        id=t.id,
        name=t.name,
        tag=None if is_default else tag,
        schedule_cron=t.schedule_cron or "",
        tag_priority=t.tag_priority,
        enabled=t.enabled,
        is_default=is_default,
    )
