"""Perseus chat API (planning#228, slice 1).

Any authenticated user may use Perseus: its tools read exactly what that
user's own API calls would (see `services/perseus.py`). A user sees, asks
into and deletes only their own conversations; anyone else's answers 404,
the same as a missing one.

- `POST /api/perseus/conversations` `{question}` starts a conversation.
- `POST /api/perseus/conversations/{id}/messages` `{question}` continues one.
- `GET  /api/perseus/conversations` lists the caller's conversations.
- `GET  /api/perseus/conversations/{id}` returns one with its messages.
- `DELETE /api/perseus/conversations/{id}` deletes it.

Asking is synchronous: the response arrives when the answer is stored.
The audit middleware records these requests without their bodies, so no
question text reaches the (retention-free) audit log.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.services import llm_connector, perseus

router = APIRouter()


class QuestionIn(BaseModel):
    question: str


def _ask(user: User, question: str, conversation_id: uuid.UUID | None) -> dict[str, Any]:
    try:
        return perseus.ask(user, question, conversation_id)
    except perseus.ConversationNotFound:
        raise HTTPException(status_code=404, detail="Conversation not found")
    except perseus.ConversationLimit as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except perseus.InvalidQuestion as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except (llm_connector.LLMNotConfigured, llm_connector.LLMConfigError) as exc:
        # LLMConfigError covers ModelsNotConfigured and StrictPolicyRefused.
        raise HTTPException(status_code=503, detail=f"AI is not available: {exc}")
    except (llm_connector.LLMBudgetExhausted, llm_connector.LLMRateLimited) as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    except llm_connector.LLMError as exc:
        raise HTTPException(status_code=502, detail=f"The AI model failed: {type(exc).__name__}")


@router.post("/conversations", status_code=201)
def start_conversation(data: QuestionIn, current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    return _ask(current_user, data.question, None)


@router.post("/conversations/{conversation_id}/messages", status_code=201)
def continue_conversation(
    conversation_id: uuid.UUID, data: QuestionIn, current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return _ask(current_user, data.question, conversation_id)


@router.get("/conversations")
def list_conversations(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return perseus.list_conversations(db, current_user)


@router.get("/conversations/{conversation_id}")
def get_conversation(
    conversation_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        return perseus.get_conversation(db, current_user, conversation_id)
    except perseus.ConversationNotFound:
        raise HTTPException(status_code=404, detail="Conversation not found")


@router.delete("/conversations/{conversation_id}", status_code=204)
def delete_conversation(
    conversation_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user),
) -> Response:
    try:
        perseus.delete_conversation(db, current_user, conversation_id)
    except perseus.ConversationNotFound:
        raise HTTPException(status_code=404, detail="Conversation not found")
    db.commit()
    return Response(status_code=204)
