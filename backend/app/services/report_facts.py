"""app.services.report_facts — the deterministic numbers behind a report
(planning#230).

Every number is the result of a query-language query counted through
`query_compiler.count_query`, as the REQUESTING USER (so the read scope the
user has is the read scope the report has). Each metric stores the query that
produced it, so a reader can re-run it. Time-relative metrics use `as_of` as
an ISO literal, never `now()`: the stored query reproduces the stored number.

No model is involved and none of this text is model output: the labels are
written here. The engagement NAME is deliberately absent; the model does not
need it and the UI takes it from the engagement API.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.models.engagement import Engagement
from app.models.user import User
from app.services import query_compiler
from app.services.query_schema import validate

TOP_FINDINGS = 10          # rows in the "highest-risk open findings" list
WINDOW_DAYS = 30           # the "new" / "resolved" window
WINDOWED = ("assets_new_30d", "findings_new_30d", "findings_resolved_30d")
OPEN_STATES = ["open", "acknowledged"]


def _field(name: str, op: str, value: Any) -> dict:
    return {"field": name, "op": op, "value": value}


def _plain(q) -> dict:
    """The validated query as plain JSON (what is stored and re-runnable)."""
    return q.model_dump(mode="json", exclude_none=True, by_alias=True)


def _metrics(since_iso: str, engagement_id: str) -> list[tuple[str, str, str, list[dict]]]:
    """(key, label, entity, extra predicates). The engagement predicate is added by the caller."""
    open_ = _field("finding.state", "in", OPEN_STATES)

    def sev(s: str) -> list[dict]:
        return [open_, _field("finding.severity", "eq", s)]

    return [
        ("assets_total", "Assets (excluding third-party context)", "asset", []),
        ("assets_proven_ours", "Assets proven ours", "asset", [_field("asset.surface", "eq", "proven_ours")]),
        ("assets_claimed_ours", "Assets claimed ours", "asset", [_field("asset.surface", "eq", "claimed_ours")]),
        ("assets_not_ours", "Assets not ours (third party)", "asset", [_field("asset.surface", "eq", "not_ours")]),
        ("assets_unknown", "Assets of unknown ownership", "asset", [_field("asset.surface", "eq", "unknown")]),
        ("assets_new_30d", f"Assets first seen in the last {WINDOW_DAYS} days", "asset",
         [_field("asset.first_seen_at", "gte", since_iso)]),
        ("findings_open", "Open findings", "finding", [open_]),
        ("findings_open_critical", "Open critical findings", "finding", sev("critical")),
        ("findings_open_high", "Open high findings", "finding", sev("high")),
        ("findings_open_medium", "Open medium findings", "finding", sev("medium")),
        ("findings_open_low", "Open low findings", "finding", sev("low")),
        ("findings_open_kev", "Open findings on the CISA KEV list", "finding",
         [open_, _field("finding.kev", "eq", True)]),
        ("findings_open_exploit", "Open findings with a known public exploit", "finding",
         [open_, _field("finding.has_exploit", "eq", True)]),
        ("findings_new_30d", f"Findings first seen in the last {WINDOW_DAYS} days", "finding",
         [_field("finding.first_seen_at", "gte", since_iso)]),
        ("findings_resolved_30d", f"Findings resolved in the last {WINDOW_DAYS} days", "finding",
         [_field("finding.resolved_at", "gte", since_iso)]),
    ]


def top_findings_query(engagement_id: str) -> dict:
    return {
        "entity": "finding",
        "where": {"all": [
            _field("asset.engagement_id", "eq", engagement_id),
            _field("finding.state", "in", OPEN_STATES),
        ]},
        "sort": [{"field": "finding.risk_score", "dir": "desc"}],
        "limit": TOP_FINDINGS,
    }


def build_facts(db: Session, engagement: Engagement, user: User, as_of: datetime) -> dict:
    eid = str(engagement.id)
    since_iso = (as_of - timedelta(days=WINDOW_DAYS)).isoformat()
    metrics: dict[str, dict] = {}
    for key, label, entity, extra in _metrics(since_iso, eid):
        raw = {
            "entity": entity,
            "where": {"all": [_field("asset.engagement_id", "eq", eid), *extra]},
        }
        if key == "assets_not_ours":
            # Third-party assets are hidden from asset queries by default; without
            # this the count would be 0 whatever the data says.
            raw["include"] = {"third_party": True}
        q = validate(raw)
        res = query_compiler.count_query(db, q, user)
        metrics[key] = {"label": label, "query": _plain(q), "count": res["count"], "capped": res["capped"]}
        if key in WINDOWED:
            # The window's length is a fact too: "in the last 30 days" must ground.
            metrics[key]["window_days"] = WINDOW_DAYS

    tq = validate(top_findings_query(eid))
    rows = query_compiler.run_query(db, tq, user)["rows"]
    top = [{
        "id": r["finding.id"], "title": r["finding.title"], "severity": r["finding.severity"],
        "risk_score": r["finding.risk_score"], "risk_band": r["finding.risk_band"],
        "kev": r["finding.kev"], "cve_id": r["finding.cve_id"],
        "asset_id": r["asset.id"], "asset_value": r["asset.value"],
    } for r in rows]
    return {
        "as_of": as_of.isoformat(),
        "engagement": {"id": eid, "posture": engagement.posture},
        "metrics": metrics,
        # JSONB does not keep key order; renderers show metrics in this one.
        "metric_order": list(metrics),
        "top_findings": top,
        "top_findings_query": _plain(tq),
    }
