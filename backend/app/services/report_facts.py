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
LIST_ROWS = 25             # rows in each list of an M&A brief (planning#230 slice 2)
WINDOW_DAYS = 30           # the "new" / "resolved" window
WINDOWED = ("assets_new_30d", "findings_new_30d", "findings_resolved_30d")
OPEN_STATES = ["open", "acknowledged"]


def event_date_text(iso: str | None, precision: str | None) -> str | None:
    """A relation's date written only as precisely as it was recorded: a
    year-precision date is stored as January 1st and must read "2021", not
    "2021-01-01" (a label is a claim too). Unknown precision: no date."""
    if not iso:
        return None
    day = iso[:10]
    return {"day": day, "month": day[:7], "year": day[:4]}.get(precision or "")


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


def _count(db: Session, user: User, label: str, raw: dict) -> dict:
    """One metric: the validated query, and its count as `user`."""
    q = validate(raw)
    res = query_compiler.count_query(db, q, user)
    return {"label": label, "query": _plain(q), "count": res["count"], "capped": res["capped"]}


def _exec_metrics(db: Session, user: User, eid: str, as_of: datetime) -> dict[str, dict]:
    """The 15 engagement metrics, shared by every report kind."""
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
        metrics[key] = _count(db, user, label, raw)
        if key in WINDOWED:
            # The window's length is a fact too: "in the last 30 days" must ground.
            metrics[key]["window_days"] = WINDOW_DAYS
    return metrics


def _top_findings(db: Session, user: User, eid: str) -> tuple[list[dict], dict]:
    tq = validate(top_findings_query(eid))
    rows = query_compiler.run_query(db, tq, user)["rows"]
    top = [{
        "id": r["finding.id"], "title": r["finding.title"], "severity": r["finding.severity"],
        "risk_score": r["finding.risk_score"], "risk_band": r["finding.risk_band"],
        "kev": r["finding.kev"], "cve_id": r["finding.cve_id"],
        "asset_id": r["asset.id"], "asset_value": r["asset.value"],
    } for r in rows]
    return top, _plain(tq)


def build_facts(db: Session, engagement: Engagement, user: User, as_of: datetime) -> dict:
    eid = str(engagement.id)
    metrics = _exec_metrics(db, user, eid, as_of)
    top, top_query = _top_findings(db, user, eid)
    return {
        "as_of": as_of.isoformat(),
        "engagement": {"id": eid, "posture": engagement.posture},
        "metrics": metrics,
        # JSONB does not keep key order; renderers show metrics in this one.
        "metric_order": list(metrics),
        "top_findings": top,
        "top_findings_query": top_query,
    }


# ── M&A due-diligence brief (planning#230 slice 2) ──────────────────────────
#
# Unreviewed data is never stated as fact: every list holds CONFIRMED relations
# and ACCEPTED domains only; proposed ones are known only as COUNTS. The family
# is the subject entity plus everything reachable DOWN confirmed parent edges
# (`query_compiler.family_ids_cte`).

_FORMER_NAME_TYPES = ["formerly_named", "dba"]


def _ma_metrics(eid: str, sid: str) -> list[tuple[str, str, dict]]:
    """(key, label, raw query) for the family metrics."""
    in_family = _field("entity.family_of", "eq", eid)
    not_subject = {"not": _field("entity.id", "eq", sid)}

    def fam(*extra: dict) -> dict:
        return {"entity": "entity", "where": {"all": [in_family, not_subject, *extra]}}

    def rel(*conds: dict) -> dict:
        return {"entity": "relation", "where": {"all": list(conds)}}

    def dom(*conds: dict) -> dict:
        return {"entity": "domain", "where": {"all": [_field("domain.family_of", "eq", eid), *conds]}}

    return [
        ("family_entities", "Companies in the confirmed corporate family (excluding the subject)", fam()),
        ("family_subsidiaries", "Family companies confirmed as subsidiaries (a company can also be acquired)",
         fam(_field("entity.parent_relation", "eq", "subsidiary_of"))),
        ("family_acquired", "Family companies confirmed as acquired (a company can also be a subsidiary)",
         fam(_field("entity.parent_relation", "eq", "acquired"))),
        ("family_own_relationship",
         "Family companies that are themselves marked ours or are the subject of another engagement",
         fam(_field("entity.relationship", "is_null", False))),
        ("former_names", "Confirmed former-name or trading-name records of the subject",
         rel(_field("relation.type", "in", _FORMER_NAME_TYPES), _field("relation.status", "eq", "confirmed"),
             _field("relation.subject_id", "eq", sid))),
        ("relations_proposed", "Proposed relationship records awaiting review",
         rel(_field("relation.family_of", "eq", eid), _field("relation.status", "eq", "proposed"))),
        ("domains_accepted", "Accepted candidate domains of family companies",
         dom(_field("domain.status", "eq", "accepted"))),
        ("domains_proposed", "Candidate domains awaiting review",
         dom(_field("domain.status", "eq", "proposed"))),
    ]


def _list(db: Session, user: User, label: str, raw: dict, row_fn) -> dict:
    """One list: the validated query (so the UI can open it in Explore), up to
    LIST_ROWS rows, and whether more exist."""
    q = validate({**raw, "limit": LIST_ROWS})
    res = query_compiler.run_query(db, q, user)
    return {"label": label, "query": _plain(q), "rows": [row_fn(r) for r in res["rows"]],
            "truncated": res["truncated"]}


def build_ma_facts(db: Session, engagement: Engagement, user: User, as_of: datetime) -> dict:
    eid = str(engagement.id)
    if engagement.subject_entity_id is None:
        raise ValueError("an M&A brief needs an engagement with a subject entity")
    sid = str(engagement.subject_entity_id)

    # The subject's name through the query language, so the read scope applies to it too.
    name_q = validate({"entity": "entity", "where": _field("entity.id", "eq", sid), "limit": 1})
    name_rows = query_compiler.run_query(db, name_q, user)["rows"]
    subject_name = name_rows[0]["entity.name"] if name_rows else None

    metrics = _exec_metrics(db, user, eid, as_of)
    order = list(metrics)
    for key, label, raw in _ma_metrics(eid, sid):
        metrics[key] = _count(db, user, label, raw)
        order.append(key)

    in_family = _field("entity.family_of", "eq", eid)
    not_subject = {"not": _field("entity.id", "eq", sid)}
    confirmed = _field("relation.status", "eq", "confirmed")
    lists = {
        "family": _list(
            db, user, "Confirmed corporate family",
            {"entity": "entity", "where": {"all": [in_family, not_subject]},
             "sort": [{"field": "entity.name", "dir": "asc"}]},
            lambda r: {"entity_id": r["entity.id"], "name": r["entity.name"],
                       "relationship": r["entity.relationship"]}),
        "acquisitions": _list(
            db, user, "Confirmed acquisitions",
            {"entity": "relation", "where": {"all": [
                _field("relation.family_of", "eq", eid), _field("relation.type", "eq", "acquired"), confirmed]},
             "sort": [{"field": "relation.event_date", "dir": "desc"}]},
            lambda r: {"entity_id": r["relation.object_id"], "acquirer": r["relation.subject_name"],
                       "acquired": r["relation.object_name"],
                       "event_date": event_date_text(r["relation.event_date"], r["relation.event_date_precision"])}),
        "former_names": _list(
            db, user, "Confirmed former names",
            {"entity": "relation", "where": {"all": [
                _field("relation.subject_id", "eq", sid),
                _field("relation.type", "in", _FORMER_NAME_TYPES), confirmed]}},
            lambda r: {"entity_id": r["relation.object_id"], "name": r["relation.object_name"]}),
        "domains": _list(
            db, user, "Accepted candidate domains",
            {"entity": "domain", "where": {"all": [
                _field("domain.family_of", "eq", eid), _field("domain.status", "eq", "accepted")]},
             "sort": [{"field": "domain.name", "dir": "asc"}]},
            lambda r: {"entity_id": r["domain.entity_id"], "domain": r["domain.name"],
                       "entity_name": r["domain.entity_name"]}),
    }

    top, top_query = _top_findings(db, user, eid)
    return {
        "as_of": as_of.isoformat(),
        "engagement": {"id": eid, "posture": engagement.posture},
        "subject": {"id": sid, "name": subject_name},
        "metrics": metrics,
        "metric_order": order,
        "lists": lists,
        "list_order": ["family", "acquisitions", "former_names", "domains"],
        "top_findings": top,
        "top_findings_query": top_query,
    }
