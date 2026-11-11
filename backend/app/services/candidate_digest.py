"""app.services.candidate_digest - the organization discovery digest (planning#319).

A rule of kind `org_discovery` is sent in the daily digest only, and lists the
NEW OPEN organization discovery candidates since its previous digest, grouped
by root organization. The body is deterministic: each candidate carries its
strength and signal labels as they stood at the claim, and each organization
lists the groups of its listed candidates that share one matched value (two
domains on one nameserver, one registrant). An AI summary is planned
(planning#331 slice 2) and will cite only these body fields.

What a notification may mention is decided in ONE place,
`notification_scope`; this module never re-implements it. It is applied
when the body is built (`select_new`), when it is sent and when a stored body
is read back through the API (`filter_body`), so a deal that returns to a
restricting posture closes up in already-built digests by itself.

## Claiming

Each candidate is claimed by a rule exactly once (`digest_candidates`, unique
on `(rule_id, candidate_id)`), with the same grace window the finding digest
uses: `created_at` is the inserting transaction's start, so a pure time window
would lose or repeat a candidate whose transaction committed late. A candidate
that is not listed (ineligible or not open) is NOT claimed, so it is picked up
by a later digest if it becomes eligible while still inside the window.

`filter_body` takes its counts from the claim rows, never from the listed items
(those are capped at `LIST_CAP`).
"""

from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.models.digest import Digest, DigestCandidate
from app.models.notification_rule import NotificationRule
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.services import notification_dispatcher
from app.services import notification_scope
from app.services.org_discovery.strength import STRENGTH_RANK, strength_subquery
from app.services.org_discovery.tiers import CONTEXT, SIGNALS, STRONG, SUPPORTING

LIST_CAP = 50  # candidates listed per organization; counts stay exact

KIND = "org_discovery"
_KIND_LABEL = {"domain": "domain", "asn": "ASN", "cidr": "IP range"}
_TIER_ORDER = {STRONG: 0, SUPPORTING: 1, CONTEXT: 2}


@dataclass(frozen=True)
class CandidateSignals:
    """What the body says about one candidate, as of the claim."""
    strength: str = "context"
    types: tuple[str, ...] = ()
    matches: tuple[tuple[str, str], ...] = ()  # (signal type, matched value)


def select_new(
    db: Session, rule: NotificationRule, floor: datetime, now: datetime, *, grace: timedelta,
) -> list[tuple[ScopeCandidate, OrgEntity]]:
    """The candidates `rule` has not claimed yet that a notification may name:
    open, created in `(floor - grace, now]`, eligible per `notification_scope`."""
    claimed = exists().where(DigestCandidate.rule_id == rule.id, DigestCandidate.candidate_id == ScopeCandidate.id)
    rows = db.execute(
        select(ScopeCandidate, OrgEntity)
        .join(OrgEntity, OrgEntity.id == ScopeCandidate.root_entity_id)
        .where(
            ScopeCandidate.status == "open",
            ScopeCandidate.created_at > floor - grace,
            ScopeCandidate.created_at <= now,
            ~claimed,
            notification_scope.candidate_eligible_clause(ScopeCandidate, OrgEntity),
        )
        .order_by(OrgEntity.legal_name, OrgEntity.id, ScopeCandidate.kind, ScopeCandidate.value)
    ).all()
    return [(c, o) for c, o in rows]


def _org_url(base_url: str, org_id: uuid.UUID | str, has_domain: bool) -> str | None:
    if not base_url:
        return None
    tab = "domains" if has_domain else "asns"
    return f"{base_url}/organizations/{org_id}?tab={tab}&seg=candidates"


def candidate_signals(db: Session, candidate_ids: list[uuid.UUID]) -> dict[uuid.UUID, CandidateSignals]:
    """Strength, distinct signal types and (type, matched value) pairs for each
    candidate, in two queries. A candidate with no signals is 'context'."""
    ids = list(candidate_ids)
    if not ids:
        return {}
    st = strength_subquery(candidate_ids=ids)
    strengths = dict(db.execute(
        select(ScopeCandidate.id, st.strength)
        .outerjoin(st.subquery, st.candidate_id == ScopeCandidate.id)
        .where(ScopeCandidate.id.in_(ids))
    ).all())
    types: dict[uuid.UUID, set[str]] = {}
    matches: dict[uuid.UUID, set[tuple[str, str]]] = {}
    for cid, stype, matched in db.execute(
        select(ScopeSignal.candidate_id, ScopeSignal.signal_type, ScopeSignal.matched_values)
        .where(ScopeSignal.candidate_id.in_(ids))
        .distinct()
    ).all():
        types.setdefault(cid, set()).add(stype)
        for v in matched or []:
            matches.setdefault(cid, set()).add((stype, v))
    return {
        cid: CandidateSignals(
            strength=strength,
            types=tuple(sorted(types.get(cid, ()))),
            matches=tuple(sorted(matches.get(cid, ()))),
        )
        for cid, strength in strengths.items()
    }


def _signal_list(types: tuple[str, ...]) -> list[dict]:
    known = [t for t in types if t in SIGNALS]
    known.sort(key=lambda t: (_TIER_ORDER.get(SIGNALS[t].tier, 3), SIGNALS[t].label))
    return [{"type": t, "label": SIGNALS[t].label} for t in known]


def build_body(
    rule: NotificationRule, pairs: list[tuple[ScopeCandidate, OrgEntity]], *,
    period_start: datetime, period_end: datetime, base_url: str,
    signals: dict[uuid.UUID, CandidateSignals] | None = None,
) -> dict:
    """Deterministic, JSON-serialisable body (the frontend relies on its shape).
    `pairs` must already be in `select_new`'s order; `signals` comes from
    `candidate_signals` (absent = 'context', no signals). Within an organization
    the strongest candidates are listed first, so `LIST_CAP` keeps them."""
    signals = signals or {}
    none = CandidateSignals()
    by_org: dict[uuid.UUID, tuple[OrgEntity, list[ScopeCandidate]]] = {}
    for cand, org in pairs:
        by_org.setdefault(org.id, (org, []))[1].append(cand)
    organizations = []
    for org, cands in by_org.values():
        ordered = sorted(cands, key=lambda c: (-STRENGTH_RANK.get(signals.get(c.id, none).strength, 0), c.kind, c.value))
        listed = ordered[:LIST_CAP]
        # Groups never span organizations: built per org, from the listed candidates only.
        members: dict[tuple[str, str], list[str]] = {}
        for c in listed:
            for key in signals.get(c.id, none).matches:
                if key[0] in SIGNALS:
                    members.setdefault(key, []).append(str(c.id))
        shared = [
            {"type": t, "label": SIGNALS[t].label, "value": v, "candidate_ids": ids}
            for (t, v), ids in members.items() if len(ids) >= 2
        ]
        shared.sort(key=lambda g: (-len(g["candidate_ids"]), g["label"], g["value"]))
        organizations.append({
            "id": str(org.id),
            "name": org.legal_name,
            "candidate_count": len(cands),
            "url": _org_url(base_url, org.id, any(c.kind == "domain" for c in cands)),
            "candidates": [
                {
                    "id": str(c.id), "kind": c.kind, "value": c.value,
                    "strength": signals.get(c.id, none).strength,
                    "signals": _signal_list(signals.get(c.id, none).types),
                }
                for c in listed
            ],
            "shared": shared,
        })
    return {
        "kind": KIND,
        "rule": {"id": str(rule.id), "name": rule.name},
        "period": {"start": period_start.isoformat(), "end": period_end.isoformat()},
        "totals": {"candidates": len(pairs), "organizations": len(organizations)},
        "organizations": organizations,
    }


def filter_body(db: Session, digest: Digest) -> dict:
    """A COPY of `digest.body` with everything a notification may no longer
    mention removed. Counts come from the digest's claim rows. Never writes."""
    body = digest.body
    # Keyed on the ROW's kind, never the body's: a body cannot opt out of this.
    if digest.kind != KIND:
        return body
    claimed = db.execute(
        select(DigestCandidate.candidate_id, ScopeCandidate.root_entity_id)
        .join(ScopeCandidate, ScopeCandidate.id == DigestCandidate.candidate_id)
        .where(DigestCandidate.digest_id == digest.id)
    ).all()
    eligible = notification_scope.eligible_candidate_ids(db, [cid for cid, _root in claimed])
    per_org: dict[str, int] = {}
    for cid, root_id in claimed:
        if cid in eligible:
            per_org[str(root_id)] = per_org.get(str(root_id), 0) + 1

    out = copy.deepcopy(body)
    orgs = []
    for org in out.get("organizations", []):
        count = per_org.get(org["id"], 0)
        if count == 0:
            continue
        org["candidate_count"] = count
        org["candidates"] = [c for c in org["candidates"] if uuid.UUID(c["id"]) in eligible]
        # A group keeps only members still listed, and needs two to be a group.
        listed_ids = {c["id"] for c in org["candidates"]}
        if "shared" in org:
            for g in org["shared"]:
                g["candidate_ids"] = [i for i in g["candidate_ids"] if i in listed_ids]
            org["shared"] = [g for g in org["shared"] if len(g["candidate_ids"]) >= 2]
        orgs.append(org)
    out["organizations"] = orgs
    out["totals"] = {
        "candidates": sum(o["candidate_count"] for o in orgs),
        "organizations": len(orgs),
    }
    return out


def render(body: dict, base_url: str) -> tuple[str, str, str]:
    """Plain-language (subject, text, html). The link in each organization is
    the one stored in the body when it was built (null when no base URL was
    set then); `base_url` is accepted so the call matches `digest.render` but
    nothing here invents a link the body does not carry. No AI summary line."""
    from app.services import digest as digest_svc  # lazy: digest imports this module

    esc = notification_dispatcher._esc
    n = body["totals"]["candidates"]
    rule_name = body["rule"]["name"]
    subject = (
        f"Constellus: {n} new organization discovery candidate{'s' if n != 1 else ''} "
        f"to review ({digest_svc._line(rule_name)})"
    )
    text: list[str] = [
        f"Rule: {rule_name}",
        f"Period: {body['period']['start']} to {body['period']['end']}",
        "",
    ]
    html: list[str] = [
        f"<p><strong>Rule:</strong> {esc(rule_name)}<br>"
        f"Period: {esc(body['period']['start'])} to {esc(body['period']['end'])}</p>",
    ]
    for org in body["organizations"]:
        k = org["candidate_count"]
        header = f"{org['name']}: {k} new candidate{'s' if k != 1 else ''} to review"
        text.append(header)
        html.append(f"<h4>{esc(header)}</h4><ul>")
        for c in org["candidates"]:
            label = _KIND_LABEL.get(c["kind"], c["kind"])
            note = ""
            if c.get("strength"):
                note = f": {str(c['strength']).capitalize()}"
                names = [s["label"] for s in c.get("signals") or []]
                if names:
                    note += f" ({', '.join(names)})"
            text.append(f"  [{label}] {c['value']}{note}")
            html.append(f"<li>{esc(label)}: <code>{esc(c['value'])}</code>{esc(note)}</li>")
        html.append("</ul>")
        shared = org.get("shared") or []
        if shared:
            by_id = {c["id"]: c["value"] for c in org["candidates"]}
            text.append("  Shared by several candidates:")
            html.append("<p>Shared by several candidates:</p><ul>")
            for g in shared:
                vals = [by_id[i] for i in g["candidate_ids"] if i in by_id]
                line = f"{g['label']}: {g['value']} ({len(vals)} candidates: {', '.join(vals)})"
                text.append(f"    {line}")
                html.append(f"<li>{esc(line)}</li>")
            html.append("</ul>")
        extra = k - len(org["candidates"])
        if extra > 0:
            more = f"and {extra} more"
            text.append(f"  {more}")
            html.append(f"<p>{esc(more)}</p>")
        if org.get("url"):
            text.append(f"  Review them in Constellus: {org['url']}")
            html.append(f'<p><a href="{digest_svc._esc_attr(org["url"])}">Review them in Constellus</a></p>')
        text.append("")
    return subject, "\n".join(text), "".join(html)
