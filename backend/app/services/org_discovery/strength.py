"""Candidate strength, calculated on load in SQL (planning#277 S1a).

Nothing here is stored. A candidate's strength is a function of its
`scope_signals` rows and the tier table (`tiers.SIGNALS`), so changing a
type's tier re-ranks every candidate on the next read with no backfill.

- `strong`      -- at least one Strong signal
- `supporting`  -- no Strong, Supporting signals from >= 2 distinct families
- `lead`        -- exactly one Supporting family (stored; not in the default queue)
- `context`     -- anything else, and a candidate with no signals at all

`proposable` is `strong` or `supporting`: the bar `candidates.claim` enforces.

The tier / family lookups are `CASE` expressions built from `SIGNALS` at
import time, as bound `IN` lists; no SQL text is assembled at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, case, distinct, false, func, literal_column, select
from sqlalchemy.sql.elements import ColumnElement

from app.models.scope_candidate import ScopeSignal
from app.services.org_discovery.tiers import CONTEXT, SIGNALS, STRONG, SUPPORTING

STRENGTHS = ("strong", "supporting", "lead", "context")
# Sort order for "strength desc".
STRENGTH_RANK = {"strong": 3, "supporting": 2, "lead": 1, "context": 0}

STRONG_TYPES: tuple[str, ...] = tuple(sorted(t for t, s in SIGNALS.items() if s.tier == STRONG))
SUPPORTING_TYPES: tuple[str, ...] = tuple(sorted(t for t, s in SIGNALS.items() if s.tier == SUPPORTING))
CONTEXT_TYPES: tuple[str, ...] = tuple(sorted(t for t, s in SIGNALS.items() if s.tier == CONTEXT))
_SUPPORTING_FAMILIES: dict[str, list[str]] = {}
for _type in SUPPORTING_TYPES:
    _SUPPORTING_FAMILIES.setdefault(SIGNALS[_type].family, []).append(_type)


def _is_strong(sig: Any) -> ColumnElement[bool]:
    return sig.signal_type.in_(STRONG_TYPES)


def _is_supporting(sig: Any) -> ColumnElement[bool]:
    return sig.signal_type.in_(SUPPORTING_TYPES)


def _supporting_family(sig: Any) -> ColumnElement[str]:
    """The family of a Supporting signal, NULL for any other tier."""
    return case(
        *[(sig.signal_type.in_(types), family) for family, types in sorted(_SUPPORTING_FAMILIES.items())],
        else_=None,
    )


def tier_expr(sig: Any = ScopeSignal) -> ColumnElement[str]:
    return case((_is_strong(sig), STRONG), (_is_supporting(sig), SUPPORTING), else_=CONTEXT)


@dataclass(frozen=True)
class StrengthSQL:
    """The subquery plus coalesced column accessors for outer-joining it."""

    subquery: Any

    @property
    def candidate_id(self):
        return self.subquery.c.candidate_id

    @property
    def strength(self) -> ColumnElement[str]:
        return func.coalesce(self.subquery.c.strength, "context")

    @property
    def proposable(self) -> ColumnElement[bool]:
        return func.coalesce(self.subquery.c.proposable, false())

    @property
    def signal_count(self) -> ColumnElement[int]:
        return func.coalesce(self.subquery.c.signal_count, 0)

    @property
    def strong_types(self) -> ColumnElement[list[str]]:
        return func.coalesce(self.subquery.c.strong_types, literal_column("ARRAY[]::text[]"))

    @property
    def rank(self) -> ColumnElement[int]:
        return case(
            (self.strength == "strong", 3), (self.strength == "supporting", 2), (self.strength == "lead", 1), else_=0
        )


def strength_subquery(candidate_ids: Any = None) -> StrengthSQL:
    """One row per candidate that has at least one signal (a CTE). `candidate_ids`
    (a column, a list, or a subquery usable in `IN`) narrows the aggregation
    to those candidates; without it the whole table is aggregated. Callers
    outer-join it (`StrengthSQL.strength` etc. coalesce the missing row to
    'context' / not proposable)."""
    sig = ScopeSignal
    inner = select(
        sig.candidate_id.label("candidate_id"),
        func.bool_or(_is_strong(sig)).label("has_strong"),
        func.count(distinct(_supporting_family(sig))).label("supporting_families"),
        func.count().label("signal_count"),
        func.array_agg(distinct(sig.signal_type)).filter(_is_strong(sig)).label("strong_types"),
    ).group_by(sig.candidate_id)
    if candidate_ids is not None:
        inner = inner.where(sig.candidate_id.in_(candidate_ids))
    agg = inner.subquery("sig_agg")
    outer = select(
        agg.c.candidate_id,
        agg.c.has_strong,
        agg.c.supporting_families,
        agg.c.signal_count,
        agg.c.strong_types,
        case(
            (agg.c.has_strong, "strong"),
            (agg.c.supporting_families >= 2, "supporting"),
            (agg.c.supporting_families == 1, "lead"),
            else_="context",
        ).label("strength"),
        (agg.c.has_strong | (agg.c.supporting_families >= 2)).label("proposable"),
    )
    # MATERIALIZED: computed once per statement. Inlined, Postgres is free to
    # re-run the aggregate for every outer row, which it does when the tables
    # have no statistics yet (a fresh bulk load): 2,000 candidates took
    # ~850 ms that way and ~10 ms materialized.
    return StrengthSQL(outer.cte("sig_strength").prefix_with("MATERIALIZED"))


def default_affiliate_expr(candidate_id_col: Any) -> ColumnElement[Any]:
    """Correlated scalar subquery: the `via_entity_id` of the candidate's best
    signal (Strong before Supporting before Context, then earliest
    `first_seen_at`, then id for a stable tie-break). Used when the
    candidate has no stored `affiliated_entity_id`."""
    sig = ScopeSignal
    rank = case((_is_strong(sig), 0), (_is_supporting(sig), 1), else_=2)
    return (
        select(sig.via_entity_id)
        .where(sig.candidate_id == candidate_id_col)
        .order_by(rank, sig.first_seen_at, sig.id)
        .limit(1)
        .scalar_subquery()
    )


def is_to_review(status_col: Any, st: StrengthSQL) -> ColumnElement[bool]:
    """An open candidate that clears the propose bar."""
    return and_(status_col == "open", st.proposable)


def is_lead(status_col: Any, st: StrengthSQL) -> ColumnElement[bool]:
    """An open candidate below the propose bar that has at least one signal.
    The ONE definition: the organization list, the summary and the
    `leads_only` candidate filter all call it, so their counts agree."""
    return and_(status_col == "open", ~st.proposable, st.signal_count >= 1)
