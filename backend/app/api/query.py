"""Attack-surface query API (planning#227).

`GET /api/query/schema` publishes the field registry and the JSON Schema of
the query object: the one description Explore's builder (#53) and Perseus
(#228) both read. `POST /api/query` validates a query object (422 with a
path per error, before any SQL is built) and returns table rows.

Read access: parity with `/api/assets` and `/api/findings` (any authenticated
user), applied through `services.read_scope` so planning#261 can scope it.
"""

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.services import query_compiler, query_schema

router = APIRouter()


@router.get("/schema")
def get_query_schema(_=Depends(get_current_user)) -> dict[str, Any]:
    return query_schema.published_schema()


@router.post("")
def run_query(
    body: Any = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        q = query_schema.validate(body)
    except query_schema.QueryError as exc:
        raise HTTPException(status_code=422, detail={"message": "Invalid query", "errors": exc.errors})
    return query_compiler.run_query(db, q, current_user)
