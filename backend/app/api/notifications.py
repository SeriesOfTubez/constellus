"""Notification rules CRUD.

Rules drive the notification_dispatcher: when a new finding lands, every
enabled rule whose severity threshold + category filter matches gets a
summary email via the enabled NotificationConnector.
"""

import logging
import re
import uuid

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.permissions import Permission
from app.core.database import get_db
from app.models.alert_event import AlertDelivery, AlertDispatch, AlertEvent
from app.models.asset_canonical import AssetCanonical
from app.models.digest import Digest
from app.models.finding_canonical import FindingCanonical
from app.models.notification_rule import RULE_MODES, NotificationRule

from app.services import app_settings, audit, digest as digest_svc
from app.services.notification_dispatcher import _SEVERITY_RANK

log = logging.getLogger(__name__)

router = APIRouter()

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _check_mode(v: str) -> str:
    v = v.strip().lower()
    if v not in RULE_MODES:
        raise ValueError(f"mode must be one of {sorted(RULE_MODES)}")
    return v


class RuleResponse(BaseModel):
    id: uuid.UUID
    name: str
    enabled: bool
    severity_threshold: str
    categories: list[str]
    recipients: list[str]
    mode: str

    model_config = {"from_attributes": True}


class RuleCreate(BaseModel):
    name: str
    severity_threshold: str = "high"
    categories: list[str] = []
    recipients: list[str]
    enabled: bool = True
    mode: str = "immediate"

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        return _check_mode(v)

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
    mode: str | None = None

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str | None) -> str | None:
        return None if v is None else _check_mode(v)

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
    _=Depends(require_permission(Permission.NOTIFICATIONS_READ)),
):
    return db.query(NotificationRule).order_by(NotificationRule.created_at.desc()).all()


@router.post("/rules", response_model=RuleResponse, status_code=status.HTTP_201_CREATED)
def create_rule(
    data: RuleCreate,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.NOTIFICATIONS_CREATE)),
):
    rule = NotificationRule(
        id=uuid.uuid4(),
        name=data.name,
        enabled=data.enabled,
        severity_threshold=data.severity_threshold,
        categories=data.categories,
        recipients=data.recipients,
        mode=data.mode,
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
    _=Depends(require_permission(Permission.NOTIFICATIONS_UPDATE)),
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
    if data.mode is not None:
        rule.mode = data.mode
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(
    rule_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.NOTIFICATIONS_DELETE)),
):
    rule = db.get(NotificationRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()


# ── Alert history (planning#233) ─────────────────────────────────────────────

_EVENTS_PER_DISPATCH = 5


class AlertEventOut(BaseModel):
    finding_id: uuid.UUID
    title: str | None
    severity: str | None
    asset_value: str | None
    detail: dict


class AlertDeliveryOut(BaseModel):
    connector_id: str | None
    outcome: str
    recipient_count: int


class AlertDispatchOut(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID | None
    rule_name: str
    kind: str
    created_at: datetime
    event_count: int
    events: list[AlertEventOut]
    deliveries: list[AlertDeliveryOut]


@router.get("/alerts", response_model=list[AlertDispatchOut])
def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.NOTIFICATIONS_READ)),
):
    """Newest-first alert history: what each rule selected and what became of
    it. Three queries total (dispatches, events, deliveries), no N+1."""
    dispatches = (
        db.query(AlertDispatch)
        .order_by(AlertDispatch.created_at.desc(), AlertDispatch.id.desc())
        .limit(limit)
        .all()
    )
    if not dispatches:
        return []
    ids = [d.id for d in dispatches]

    event_rows = (
        db.query(AlertEvent, FindingCanonical.title, AssetCanonical.value)
        .join(FindingCanonical, FindingCanonical.id == AlertEvent.finding_id)
        .outerjoin(AssetCanonical, AssetCanonical.id == FindingCanonical.asset_canonical_id)
        .filter(AlertEvent.dispatch_id.in_(ids))
        .all()
    )
    events_by: dict[uuid.UUID, list] = {}
    for ev, title, asset_value in event_rows:
        events_by.setdefault(ev.dispatch_id, []).append((ev, title, asset_value))

    deliveries_by: dict[uuid.UUID, list] = {}
    for dl in (
        db.query(AlertDelivery)
        .filter(AlertDelivery.dispatch_id.in_(ids))
        .order_by(AlertDelivery.created_at, AlertDelivery.id)
        .all()
    ):
        deliveries_by.setdefault(dl.dispatch_id, []).append(dl)

    out = []
    for d in dispatches:
        evs = events_by.get(d.id, [])
        evs.sort(key=lambda t: (-_SEVERITY_RANK.get(t[0].severity or "info", 0), t[1] or ""))
        out.append(AlertDispatchOut(
            id=d.id, rule_id=d.rule_id, rule_name=d.rule_name, kind=d.kind,
            created_at=d.created_at, event_count=len(evs),
            events=[
                AlertEventOut(
                    finding_id=ev.finding_id, title=title, severity=ev.severity,
                    asset_value=asset_value, detail=ev.detail or {},
                )
                for ev, title, asset_value in evs[:_EVENTS_PER_DISPATCH]
            ],
            deliveries=[
                AlertDeliveryOut(
                    connector_id=dl.connector_id, outcome=dl.outcome,
                    recipient_count=dl.recipient_count,
                )
                for dl in deliveries_by.get(d.id, [])
            ],
        ))
    return out


# ── Digests (planning#233 slice 2a) ──────────────────────────────────────────


class DigestOut(BaseModel):
    id: uuid.UUID
    rule_id: uuid.UUID | None
    rule_name: str
    period_start: datetime
    period_end: datetime
    event_count: int
    finding_count: int
    outcome: str
    narrative_status: str | None
    narrative_reason: str | None
    deliveries: list[dict]
    created_at: datetime
    sent_at: datetime | None

    model_config = {"from_attributes": True}


class DigestDetailOut(DigestOut):
    body: dict
    narrative: dict | None


@router.get("/digests", response_model=list[DigestOut])
def list_digests(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.NOTIFICATIONS_READ)),
):
    return db.query(Digest).order_by(Digest.created_at.desc(), Digest.id.desc()).limit(limit).all()


@router.get("/digests/{digest_id}", response_model=DigestDetailOut)
def get_digest(
    digest_id: uuid.UUID,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.NOTIFICATIONS_READ)),
):
    row = db.get(Digest, digest_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Digest not found")
    return row


_BASE_URL_RE = re.compile(r"https?://[^\s/?#@]+(/[^\s?#]*)?")


class DigestSettings(BaseModel):
    digest_hour_utc: int
    app_base_url: str


class DigestSettingsUpdate(BaseModel):
    digest_hour_utc: int | None = Field(default=None, ge=0, le=23)
    app_base_url: str | None = Field(default=None, max_length=200)

    @field_validator("app_base_url")
    @classmethod
    def _base_url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        if v and not _BASE_URL_RE.fullmatch(v):
            raise ValueError("app_base_url must be empty or an http(s) URL without a query or fragment")
        return v.rstrip("/")


def _digest_settings(db: Session) -> DigestSettings:
    return DigestSettings(digest_hour_utc=digest_svc.digest_hour(db), app_base_url=digest_svc.app_base_url(db))


@router.get("/digest-settings", response_model=DigestSettings)
def get_digest_settings(
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.NOTIFICATIONS_READ)),
):
    return _digest_settings(db)


@router.put("/digest-settings", response_model=DigestSettings)
def put_digest_settings(
    data: DigestSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_permission(Permission.NOTIFICATIONS_CONFIGURE)),
):
    old = _digest_settings(db)
    if data.digest_hour_utc is not None:
        app_settings.set_value(db, digest_svc.DIGEST_HOUR_KEY, str(data.digest_hour_utc))
        audit.record_detail(request, digest_hour_utc={"from": old.digest_hour_utc, "to": data.digest_hour_utc})
    if data.app_base_url is not None:
        app_settings.set_value(db, digest_svc.BASE_URL_KEY, data.app_base_url)
        audit.record_detail(request, app_base_url={"from": old.app_base_url, "to": data.app_base_url})
    return _digest_settings(db)
