"""Notification rules CRUD.

Rules drive the notification_dispatcher: when a new finding lands, every
enabled rule whose severity threshold + category filter matches gets a
summary email via the enabled NotificationConnector.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_role
from app.core.database import get_db
from app.models.notification_rule import NotificationRule
from app.models.user import UserRole

log = logging.getLogger(__name__)

router = APIRouter()

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class RuleResponse(BaseModel):
    id: uuid.UUID
    name: str
    enabled: bool
    severity_threshold: str
    categories: list[str]
    recipients: list[str]

    model_config = {"from_attributes": True}


class RuleCreate(BaseModel):
    name: str
    severity_threshold: str = "high"
    categories: list[str] = []
    recipients: list[str]
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        return v

    @field_validator("severity_threshold")
    @classmethod
    def _sev(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in _VALID_SEVERITIES:
            raise ValueError(f"severity_threshold must be one of {sorted(_VALID_SEVERITIES)}")
        return v

    @field_validator("recipients")
    @classmethod
    def _recipients(cls, v: list[str]) -> list[str]:
        cleaned = [r.strip() for r in v if r and r.strip()]
        if not cleaned:
            raise ValueError("at least one recipient is required")
        return cleaned


class RuleUpdate(BaseModel):
    name: str | None = None
    severity_threshold: str | None = None
    categories: list[str] | None = None
    recipients: list[str] | None = None
    enabled: bool | None = None

    @field_validator("severity_threshold")
    @classmethod
    def _sev(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        if v not in _VALID_SEVERITIES:
            raise ValueError(f"severity_threshold must be one of {sorted(_VALID_SEVERITIES)}")
        return v


@router.get("/rules", response_model=list[RuleResponse])
def list_rules(
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    return db.query(NotificationRule).order_by(NotificationRule.created_at.desc()).all()


@router.post("/rules", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
def create_rule(
    data: RuleCreate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    rule = NotificationRule(
        id=uuid.uuid4(),
        name=data.name,
        enabled=data.enabled,
        severity_threshold=data.severity_threshold,
        categories=data.categories,
        recipients=data.recipients,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    log.info("Created notification rule %s (%r)", rule.id, rule.name)
    return rule


@router.patch("/rules/{rule_id}", response_model=RuleResponse)
def update_rule(
    rule_id: uuid.UUID,
    data: RuleUpdate,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    rule = db.get(NotificationRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if data.name is not None:
        rule.name = data.name.strip() or rule.name
    if data.severity_threshold is not None:
        rule.severity_threshold = data.severity_threshold
    if data.categories is not None:
        rule.categories = data.categories
    if data.recipients is not None:
        cleaned = [r.strip() for r in data.recipients if r and r.strip()]
        if not cleaned:
            raise HTTPException(status_code=422, detail="recipients can't be empty")
        rule.recipients = cleaned
    if data.enabled is not None:
        rule.enabled = data.enabled
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_role(UserRole.ADMIN, UserRole.INTEGRATION_ADMIN)),
):
    rule = db.get(NotificationRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
