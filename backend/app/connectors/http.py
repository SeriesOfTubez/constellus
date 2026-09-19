"""
Shared HTTP wrapper for all connector outbound calls.

All connectors MUST use connector_get() / connector_post() instead of calling
httpx directly. This provides:
  - Exponential backoff with jitter on transient failures and network errors
  - 429 handling — respects Retry-After header, falls back to computed backoff
  - Retry on 429 / 500 / 502 / 503 / 504; immediate return on all other status codes

Exception: _test() methods in connectors use httpx directly — fast failure is
preferable there so the UI gets immediate feedback rather than waiting through retries.
"""

import logging
import random
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)

_RETRY_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
_DEFAULT_RETRIES = 3
_BASE_DELAY = 1.0
_MAX_DELAY = 60.0
_JITTER = 1.0


def connector_get(
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    timeout: float = 15.0,
    max_retries: int = _DEFAULT_RETRIES,
    follow_redirects: bool = False,
) -> httpx.Response:
    """`follow_redirects` defaults to False — httpx's own default, and the
    behaviour every caller here has always had. It is opt-in per call rather
    than on globally because a redirect is an attacker-influencable hop for
    any connector whose URL derives from asset data, which is the class of
    thing app/core/ssrf.py exists to constrain. Turn it on only for a fixed,
    hardcoded URL (see cloud_ranges.py, where GitHub release assets 302 to a
    signed CDN host)."""
    return _request(
        "GET", url, headers=headers, params=params, timeout=timeout,
        max_retries=max_retries, follow_redirects=follow_redirects,
    )


def connector_post(
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    json: Any = None,
    data: Any = None,
    timeout: float = 15.0,
    max_retries: int = _DEFAULT_RETRIES,
) -> httpx.Response:
    return _request("POST", url, headers=headers, params=params, json=json, data=data, timeout=timeout, max_retries=max_retries)


# ── Internal ──────────────────────────────────────────────────────────────────

def _request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    json: Any = None,
    data: Any = None,
    timeout: float,
    max_retries: int,
    follow_redirects: bool = False,
) -> httpx.Response:
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            resp = httpx.request(
                method, url,
                headers=headers,
                params=params,
                json=json,
                data=data,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )

            if resp.status_code not in _RETRY_STATUSES:
                return resp

            if attempt == max_retries:
                return resp

            wait = _retry_after(resp) or _backoff(attempt)
            log.warning(
                "%s %s → %d, retry %d/%d in %.1fs",
                method, url, resp.status_code, attempt + 1, max_retries, wait,
            )
            time.sleep(wait)

        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
            last_exc = exc
            if attempt == max_retries:
                raise
            wait = _backoff(attempt)
            log.warning(
                "%s %s failed (%s), retry %d/%d in %.1fs",
                method, url, exc, attempt + 1, max_retries, wait,
            )
            time.sleep(wait)

    raise RuntimeError("unreachable") if last_exc is None else last_exc


def _backoff(attempt: int) -> float:
    delay = min(_BASE_DELAY * (2 ** attempt), _MAX_DELAY)
    return delay + random.uniform(0, _JITTER)


def _retry_after(resp: httpx.Response) -> float | None:
    header = resp.headers.get("retry-after") or resp.headers.get("Retry-After")
    if not header:
        return None
    try:
        return max(0.0, float(header))
    except ValueError:
        return None
