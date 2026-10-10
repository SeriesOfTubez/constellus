"""Reports API (planning#230 slice 1): AI-narrated, grounded executive
summaries per engagement. See `app.services.reports` for what a report is
and what is checked."""

import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_role
from app.core.database import get_db
from app.models.engagement import Engagement
from app.models.report import Report
from app.models.user import User, UserRole
from app.services import audit, llm_connector, read_scope, reports

router = APIRouter()

_WRITERS = (UserRole.ADMIN, UserRole.REPORT_ADMIN)


class ReportRequest(BaseModel):
    engagement_id: uuid.UUID
    kind: Literal["exec_summary"] = "exec_summary"


def _email(db: Session, user_id: uuid.UUID | None) -> str | None:
    user = db.get(User, user_id) if user_id else None
    return user.email if user is not None else None


def _summary(db: Session, r: Report) -> dict:
    return {
        "id": str(r.id),
        "engagement_id": str(r.engagement_id),
        "kind": r.kind,
        "status": r.status,
        "as_of": r.as_of,
        "created_at": r.created_at,
        "finished_at": r.finished_at,
        "statements_returned": r.statements_returned,
        "statements_dropped": r.statements_dropped,
        "requested_by": _email(db, r.requested_by_id),
        "cost_usd": reports.cost_usd(db, r.ledger_ids or []),
    }


def _detail(db: Session, r: Report) -> dict:
    return {
        **_summary(db, r),
        "prompt_version": r.prompt_version,
        "facts": r.facts,
        "payload": r.payload,
        "drop_reasons": r.drop_reasons or {},
        "model": r.model,
        "forced_strict": r.forced_strict,
        "error": r.error,
    }


def _visible_engagement(db: Session, user: User, engagement_id: uuid.UUID) -> Engagement:
    """404 for an unknown engagement AND for one the read scope hides, so the
    second is not confirmed to exist."""
    engagement = db.get(Engagement, engagement_id)
    if engagement is None or not read_scope.engagement_visible(user, engagement_id):
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


def _visible_report(db: Session, user: User, report_id: uuid.UUID) -> Report:
    r = db.get(Report, report_id)
    if r is None or not read_scope.engagement_visible(user, r.engagement_id):
        raise HTTPException(status_code=404, detail="Report not found")
    return r


@router.get("")
def list_reports(
    engagement_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Reports for one engagement, newest first (at most 50)."""
    _visible_engagement(db, current_user, engagement_id)
    rows = (
        db.query(Report).filter(Report.engagement_id == engagement_id)
        .order_by(Report.created_at.desc(), Report.id.desc()).limit(50).all()
    )
    return [_summary(db, r) for r in rows]


@router.post("", status_code=202)
def create_report(
    body: ReportRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_WRITERS)),
):
    """Queue a report. Every refusal happens before a row exists or a request
    is sent: unknown engagement (404), AI not configured (503), one already
    queued or running (409), today's cap reached (429)."""
    engagement = _visible_engagement(db, current_user, body.engagement_id)
    if not llm_connector.is_configured(db):
        raise HTTPException(status_code=503, detail="the OpenRouter connector is not configured or not enabled")
    if not llm_connector.models_configured(db):
        raise HTTPException(status_code=503, detail="AI models not configured (Admin -> AI models)")
    try:
        row = reports.request_report(db, engagement, body.kind, current_user)
    except reports.AlreadyRunning as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except reports.DailyCapReached as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    audit.record_detail(request, report_id=str(row.id), engagement_id=str(engagement.id), kind=body.kind)
    background_tasks.add_task(reports.run_in_background, row.id, current_user.id)
    return _summary(db, row)


@router.get("/{report_id}")
def get_report(
    report_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return _detail(db, _visible_report(db, current_user, report_id))


@router.get("/{report_id}/markdown")
def get_report_markdown(
    report_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    r = _visible_report(db, current_user, report_id)
    if r.status != "done":
        raise HTTPException(status_code=409, detail="the report is not finished")
    engagement = db.get(Engagement, r.engagement_id)
    body = reports.render_markdown(r, engagement.name if engagement else "")
    # The filename carries the id only: an engagement name is client data.
    return Response(
        content=body, media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{r.id}.md"'},
    )


@router.delete("/{report_id}", status_code=204)
def delete_report(
    report_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(*_WRITERS)),
):
    r = _visible_report(db, current_user, report_id)
    audit.record_detail(request, report_id=str(r.id), engagement_id=str(r.engagement_id))
    db.delete(r)
    db.commit()
    return Response(status_code=204)
