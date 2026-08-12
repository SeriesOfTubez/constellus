import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.models.tag_rule import TagRule
from app.models.target import Target
from app.models.user import UserRole
from app.services import tag_service

router = APIRouter()

ENTITY_TYPES = ("target", "asset", "finding")


# ── Pydantic models ───────────────────────────────────────────────────────────

class TagsUpdate(BaseModel):
    tags: list[str]


class TagRuleCreate(BaseModel):
    name: str
    entity_type: str
    condition: dict
    tag: str
    enabled: bool = True


class TagRuleUpdate(BaseModel):
    name: str | None = None
    condition: dict | None = None
    tag: str | None = None
    enabled: bool | None = None


# ── Tag listing (autocomplete) ────────────────────────────────────────────────

@router.get("/")
def list_tags(
    entity_type: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return all distinct tags in use, optionally filtered by entity type."""
    tags: set[str] = set()

    if entity_type in (None, "target"):
        for (t,) in db.query(Target.tags).filter(Target.tags != []).all():
            tags.update(t or [])
    if entity_type in (None, "asset"):
        for (t,) in db.query(AssetCanonical.tags).filter(AssetCanonical.tags != []).all():
            tags.update(t or [])
    if entity_type in (None, "finding"):
        for (t,) in db.query(FindingCanonical.tags).filter(FindingCanonical.tags != []).all():
            tags.update(t or [])

    return sorted(tags)


# ── Per-entity tag updates ────────────────────────────────────────────────────

@router.patch("/targets/{target_id}")
def update_target_tags(
    target_id: uuid.UUID,
    data: TagsUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    tag_service.set_entity_tags(target, data.tags)
    db.commit()
    return {"id": str(target_id), "tags": target.tags}


@router.patch("/assets/{asset_id}")
def update_asset_tags(
    asset_id: uuid.UUID,
    data: TagsUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    asset = db.get(AssetCanonical, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    tag_service.set_entity_tags(asset, data.tags)
    db.commit()
    return {"id": str(asset_id), "tags": asset.tags}


@router.patch("/findings/{finding_id}")
def update_finding_tags(
    finding_id: uuid.UUID,
    data: TagsUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    finding = db.get(FindingCanonical, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    tag_service.set_entity_tags(finding, data.tags)
    db.commit()
    return {"id": str(finding_id), "tags": finding.tags}


# ── Tag rules CRUD ────────────────────────────────────────────────────────────

@router.get("/rules")
def list_rules(
    entity_type: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    q = db.query(TagRule)
    if entity_type:
        q = q.filter(TagRule.entity_type == entity_type)
    return q.order_by(TagRule.created_at.desc()).all()


@router.post("/rules", status_code=201)
def create_rule(
    data: TagRuleCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    if data.entity_type not in ENTITY_TYPES:
        raise HTTPException(status_code=422, detail=f"entity_type must be one of {ENTITY_TYPES}")
    rule = TagRule(
        id=uuid.uuid4(),
        name=data.name,
        entity_type=data.entity_type,
        condition=data.condition,
        tag=data.tag.strip().lower(),
        enabled=data.enabled,
        created_by_id=current_user.id,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.patch("/rules/{rule_id}")
def update_rule(
    rule_id: uuid.UUID,
    data: TagRuleUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    rule = db.get(TagRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if data.name is not None:
        rule.name = data.name
    if data.condition is not None:
        rule.condition = data.condition
    if data.tag is not None:
        rule.tag = data.tag.strip().lower()
    if data.enabled is not None:
        rule.enabled = data.enabled
    db.commit()
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    rule = db.get(TagRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()


# ── Bulk re-evaluate ──────────────────────────────────────────────────────────

@router.post("/rules/evaluate", status_code=202)
def evaluate_rules(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN)),
):
    """Re-run all enabled rules against every entity. Adds tags; never removes manual tags."""
    background_tasks.add_task(_run_reevaluate)
    return {"status": "evaluation queued"}


def _run_reevaluate() -> None:
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        counts = tag_service.reevaluate_all(db)
        import logging
        logging.getLogger(__name__).info("Tag re-evaluation complete: %s", counts)
    finally:
        db.close()
