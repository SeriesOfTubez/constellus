"""Chat assistant API (planning#228, slice 1).

Any authenticated user may use the chat assistant: its tools read exactly what that
user's own API calls would (see `services/chat.py`). A user sees, asks
into and deletes only their own conversations; anyone else's answers 404,
the same as a missing one.

- `POST /api/chat/conversations` `{question}` starts a conversation.
- `POST /api/chat/conversations/{id}/messages` `{question}` continues one.
- `GET  /api/chat/conversations` lists the caller's conversations.
- `GET  /api/chat/conversations/{id}` returns one with its messages.
- `DELETE /api/chat/conversations/{id}` deletes it.

Asking is synchronous: the response arrives when the answer is stored.
The audit middleware records these requests without their bodies, so no
question text reaches the (retention-free) audit log.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.permissions import Permission
from app.core.database import get_db
from app.models.user import User
from app.services import chat, llm_connector

router = APIRouter()


class QuestionIn(BaseModel):
    question: str


def _ask(user: User, question: str, conversation_id: uuid.UUID | None) -> dict[str, Any]:
    try:
        return chat.ask(user, question, conversation_id)
    except chat.ConversationNotFound:
        raise HTTPException(status_code=404, detail="Conversation not found")
    except chat.ConversationLimit as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except chat.InvalidQuestion as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except (llm_connector.LLMNotConfigured, llm_connector.LLMConfigError) as exc:
        # LLMConfigError covers ModelsNotConfigured and StrictPolicyRefused.
        raise HTTPException(status_code=503, detail=f"AI is not available: {exc}")
    except llm_connector.InputBlocked:
        raise HTTPException(status_code=422, detail="the AI provider blocked this message as a likely prompt injection")
    except (llm_connector.LLMBudgetExhausted, llm_connector.LLMRateLimited) as exc:
        raise HTTPException(status_code=429, detail=str(exc))
    except llm_connector.LLMError as exc:
        raise HTTPException(status_code=502, detail=f"The AI model failed: {type(exc).__name__}")


@router.post("/conversations", status_code=201)
def start_conversation(data: QuestionIn, current_user: User = Depends(require_permission(Permission.CHAT_CREATE))) -> dict[str, Any]:
    return _ask(current_user, data.question, None)


@router.post("/conversations/{conversation_id}/messages", status_code=201)
def continue_conversation(
    conversation_id: uuid.UUID, data: QuestionIn, current_user: User = Depends(require_permission(Permission.CHAT_ASK)),
) -> dict[str, Any]:
    return _ask(current_user, data.question, conversation_id)


@router.get("/conversations")
def list_conversations(
    db: Session = Depends(get_db), current_user: User = Depends(require_permission(Permission.CHAT_READ)),
) -> list[dict[str, Any]]:
    return chat.list_conversations(db, current_user)


@router.get("/conversations/{conversation_id}")
def get_conversation(
    conversation_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(require_permission(Permission.CHAT_READ)),
) -> dict[str, Any]:
    try:
        return chat.get_conversation(db, current_user, conversation_id)
    except chat.ConversationNotFound:
        raise HTTPException(status_code=404, detail="Conversation not found")


@router.delete("/conversations/{conversation_id}", status_code=204)
def delete_conversation(
    conversation_id: uuid.UUID, db: Session = Depends(get_db), current_user: User = Depends(require_permission(Permission.CHAT_DELETE)),
) -> Response:
    try:
        chat.delete_conversation(db, current_user, conversation_id)
    except chat.ConversationNotFound:
        raise HTTPException(status_code=404, detail="Conversation not found")
    db.commit()
    return Response(status_code=204)
