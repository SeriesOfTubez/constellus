"""Row-level read scope: the one place that decides which rows a user may read.

**Today this grants everything**, by decision (Jason, 2026-10-10, planning#227):
the query language has parity with the existing asset and finding GETs, which
depend only on `get_current_user`. It exists so that real scoping
(planning#261, e.g. by engagement membership or pre-close posture) lands in ONE
function that every read path applies, instead of being retrofitted into each.

`query_compiler` applies these clauses to every row source it reads, including
the findings inside an `exists` block. The existing `/api/assets` and
`/api/findings` endpoints do not call them yet; moving them onto this module is
part of #261.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import true
from sqlalchemy.sql.elements import ColumnElement

from app.models.user import User


def asset_clause(user: User, asset: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `asset` (an AssetCanonical entity or alias) to what `user` may read."""
    return true()


def finding_clause(user: User, finding: Any, asset: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `finding` (a FindingCanonical entity or alias), whose asset is
    `asset`, to what `user` may read."""
    return true()


def entity_clause(user: User, entity: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `entity` (an OrgEntity entity or alias) to what `user` may read.
    The query language applies it to the `entity` root and to the entity joined onto a
    `relation` or `domain` row. **Today this grants everything**; planning#261 fills it."""
    return true()


def relation_clause(user: User, relation: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `relation` (an EntityRelation entity) to what `user` may read.
    **Today this grants everything**; planning#261 fills it."""
    return true()


def domain_clause(user: User, domain: Any) -> ColumnElement[bool]:
    """WHERE clause limiting `domain` (a CandidateDomain entity) to what `user` may read.
    **Today this grants everything**; planning#261 fills it."""
    return true()


def engagement_visible(user: User, engagement_id: Any) -> bool:
    """May `user` see `engagement_id`, and so its reports? The hook planning#261
    fills; report list, view and download all call it, and answer 404 (not 403)
    when it is False so an engagement a user may not see is not confirmed to
    exist. **Today this grants everything**, as the two clauses above do."""
    return True
