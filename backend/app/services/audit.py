"""Audit trail — who did what, recorded at one choke point (planning#194).

`audit_logs` shipped in migration 0001 with every column and index it needs
and **no writer**. An empty audit table is worse than none: it reads as
coverage in a design review while no record exists of who added a target,
changed a role, enabled a connector or launched a scan.

## The coverage rule

**Every state-mutating request by an authenticated principal is audited, by
default.** Not an opt-in list of "important" actions — opt-in coverage
decays silently, and each new endpoint is a gap nobody notices. The opt-out
list is `UNAUDITED_ENDPOINTS` below, explicit and justified per entry, and
`test_audit_log.py` enumerates every route in `app/api/` so a new mutating
endpoint fails the suite rather than going quietly unaudited.

## Why a middleware and not a call in each handler

A per-handler `audit(...)` call is an opt-in list wearing a different hat:
it covers what its author remembered. `AuditMiddleware` sits outside the
app and sees every request, so a new endpoint is covered by construction.

The principal is the one thing an outer middleware cannot derive on its
own, so `get_current_user` stashes its ID on
`request.state.audit_actor_id` (`api/deps.py`) — the ID and not the `User`,
because the request's DB session is already closed by the time this runs
and a detached ORM object raises on every attribute access. That is the
same dependency every authenticated route
already resolves — `require_role` depends on it — so "authenticated" and
"audited" are the same set by construction rather than by discipline.

Requests are recorded whatever their outcome, with the status code in
`detail`. A VIEWER's 403 against an admin route and a 404 against a
deleted object are both things an operator will want to see later; an
audit log of successes only cannot answer "who has been trying".

## What is NOT recorded

Nothing from a request body is recorded by default. `detail` carries the
route, method, status, path parameters and any explicit enrichment a
handler adds via `record_detail()` — which is where before/after values for
a changed field come from, since a generic middleware cannot know what the
old value was. Anything that does land in `detail` goes through `scrub()`,
which redacts by key name: `detail` is free-form JSONB, and the failure
mode that turns an audit log into a credential store is a handler
enriching it with the connector config it just saved.

## Retention

Deliberately none. `audit_logs` is append-only: it is not partitioned, it
is not swept by `main._purge_old_logs` (that loop is scoped to
`system_logs`), and there is no API route that deletes from it — which is
the answer to planning#162's point that `DELETE /api/logs/` lets an admin
erase the trace. That endpoint truncates `system_logs`; the audit trail is
a different table with no delete path, and the act of clearing the system
log is itself audited. Volume is bounded by admin actions, not by scan
traffic, so this is affordable for a long time; revisit partitioning when
the row count justifies it, not before.
"""

import logging
from typing import Any

from starlette.concurrency import run_in_threadpool

log = logging.getLogger(__name__)

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Endpoints that mutate state without an authenticated principal, and so
# cannot be audited by the actor-keyed choke point. Keyed by
# "<module>:<function>" — a stable identity that survives a path change.
# Every entry needs a reason; "it was already here" is not one.
UNAUDITED_ENDPOINTS: dict[str, str] = {
    "auth:login": "Pre-authentication by definition — there is no principal yet.",
    "auth:refresh": "Pre-authentication: presents a refresh token, not a session.",
    "auth:setup": (
        "First-run bootstrap: creates the first admin when no user exists, so "
        "there is no actor to attribute it to."
    ),
    "saml:saml_acs": (
        "IdP-posted assertion — the principal is established BY this call, so "
        "there is none to attribute it to beforehand."
    ),
}

# Substrings matched case-insensitively against dict KEYS in `detail`. A key
# whose name contains any of these is replaced with the redaction marker
# rather than stored. Key-name matching is deliberately crude and
# deliberately broad: a false redaction costs an operator one lookup, a
# false negative puts a live credential in a table built to be read.
SECRET_KEY_HINTS: tuple[str, ...] = (
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "credential", "private_key", "privatekey", "client_secret", "auth",
    "authorization", "cert", "signature", "session", "cookie", "hash",
)

REDACTED = "[redacted]"

_MAX_DEPTH = 6
_MAX_STR = 2000


def _is_secret_key(key: str) -> bool:
    lowered = str(key).lower()
    return any(hint in lowered for hint in SECRET_KEY_HINTS)


def scrub(value: Any, _depth: int = 0) -> Any:
    """Recursively redact secret-looking keys and cap unbounded values.

    Applied to everything that reaches `detail`, including handler
    enrichment — a handler that helpfully passes the object it just saved
    must not be able to write a credential into the audit trail.
    """
    if _depth > _MAX_DEPTH:
        return "[truncated: max depth]"
    if isinstance(value, dict):
        return {
            str(k): (REDACTED if _is_secret_key(k) else scrub(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub(v, _depth + 1) for v in value[:100]]
    if isinstance(value, str):
        return value if len(value) <= _MAX_STR else value[:_MAX_STR] + "…[truncated]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:_MAX_STR]


def record_detail(request, **fields: Any) -> None:
    """Enrich the audit row this request will produce.

    The middleware knows who, what route and what outcome; only the handler
    knows that `aggressiveness` went from `polite` to `aggressive`. Call
    this from a handler that changes a value worth reconstructing later:

        audit.record_detail(request, aggressiveness={"from": old, "to": new})

    Merges, so several calls accumulate. Never raises — an audit
    enrichment that breaks a request would be a worse bug than the missing
    field it was added for.
    """
    try:
        existing = getattr(request.state, "audit_detail", None) or {}
        existing.update(fields)
        request.state.audit_detail = existing
    except Exception:  # pragma: no cover - defensive
        log.warning("Could not attach audit detail", exc_info=True)


def write(
    *,
    user_id,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Append one audit row on its own session.

    Its own session because the request's session may already be committed,
    closed, or in a failed transaction by the time the response has been
    sent — the audit row must not inherit the fate of the work it records.
    """
    from app.core.database import SessionLocal
    from app.models.audit import AuditLog

    db = SessionLocal()
    try:
        db.add(
            AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                detail=scrub(detail) if detail else None,
                ip_address=ip_address,
            )
        )
        db.commit()
    finally:
        db.close()


def _client_ip(scope) -> str | None:
    client = scope.get("client")
    return client[0] if client else None


def _forwarded_for(scope) -> str | None:
    """`X-Forwarded-For`, recorded as untrusted.

    It is client-supplied and trivially spoofed unless every hop in front
    of this app overwrites it. `ip_address` therefore always holds the real
    peer address from the socket; this goes in `detail` labelled for what
    it is, so a reader behind a known-good proxy can use it and a reader
    who is not does not mistake it for evidence.
    """
    for name, value in scope.get("headers") or []:
        if name == b"x-forwarded-for":
            return value.decode("latin-1")[:200]
    return None


def _resource_id(path_params: dict | None) -> str | None:
    """The single id-ish path parameter, if there is exactly one.

    Two would be ambiguous and guessing which is the subject would put a
    wrong answer in an audit trail; the full parameter set is in `detail`
    either way.
    """
    if not path_params:
        return None
    candidates = [str(v) for k, v in path_params.items() if k.endswith("_id") or k == "id"]
    return candidates[0] if len(candidates) == 1 else None


class AuditMiddleware:
    """Pure-ASGI middleware — records every mutating request that carried an
    authenticated principal.

    Pure ASGI rather than `BaseHTTPMiddleware` so the request body stream is
    never touched: reading it here to log it is the classic way to make
    every POST in an app hang, and nothing in the audit row needs it.

    The row is written after the response has been sent, in a threadpool, so
    a synchronous DB insert does not sit on the event loop. A failure to
    write is logged and swallowed: an audit trail that can take the API down
    would be turned off within a week, and the ERROR lands in the system log
    where a missing trail is at least visible.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") not in MUTATING_METHODS:
            return await self.app(scope, receive, send)

        seen: dict = {}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                seen["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            try:
                await self._record(scope, seen.get("status"))
            except Exception:
                log.error(
                    "Audit write failed for %s %s — the action happened and was NOT recorded",
                    scope.get("method"), scope.get("path"), exc_info=True,
                )

    async def _record(self, scope, status_code: int | None) -> None:
        actor_id = (scope.get("state") or {}).get("audit_actor_id")
        if actor_id is None:
            # Unauthenticated. Either an opt-out endpoint (see
            # UNAUDITED_ENDPOINTS) or a request rejected before any
            # dependency ran — a 401 with no token, a 404 on no route, a
            # 422 on a malformed path. Nothing happened and nobody did it.
            return

        route = scope.get("route")
        endpoint = getattr(route, "endpoint", None)
        module = (getattr(endpoint, "__module__", "") or "").rsplit(".", 1)[-1]
        name = getattr(route, "name", None) or getattr(endpoint, "__name__", "unknown")
        if f"{module}:{name}" in UNAUDITED_ENDPOINTS:
            return

        path_params = scope.get("path_params") or {}
        detail = {
            "method": scope.get("method"),
            "path": scope.get("path"),
            "status_code": status_code,
        }
        if path_params:
            detail["path_params"] = {k: str(v) for k, v in path_params.items()}
        forwarded = _forwarded_for(scope)
        if forwarded:
            detail["forwarded_for_untrusted"] = forwarded
        enrichment = (scope.get("state") or {}).get("audit_detail")
        if enrichment:
            detail["changes"] = enrichment

        await run_in_threadpool(
            write,
            user_id=actor_id,
            action=name,
            resource_type=module or None,
            resource_id=_resource_id(path_params),
            detail=detail,
            ip_address=_client_ip(scope),
        )
