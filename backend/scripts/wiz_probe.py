#!/usr/bin/env python
"""Wiz GraphQL probe — schema introspection and live query checks.

This script exists because the previous two versions of it were written to
%TEMP% and evaporated, taking the only record of what our tenant's schema
actually says with them (see planning#118's hand-off note). It lives in the
repo now. It is a developer tool, not part of the running product — nothing
in `app/` imports it.

Its job is to answer "what does OUR tenant actually return", because the
Wiz docs and our schema disagree in at least three places that matter
(Obsidian `Constellus — Wiz API Reference` §7): `cloudResourcesV2` cannot
filter by IP at all, and both `externalVulnerabilityFinding` and `issues`
are deprecated in our schema while Wiz's own docs example still uses them.
Deprecated fields still resolve, which is what makes them dangerous — so
`type` and `query` below select `isDeprecated`/`deprecationReason`/
`inputFields` explicitly. The first version of this script omitted those
and cost a full re-run.

Usage (credentials come from the environment — see .env.example):

    python scripts/wiz_probe.py auth
    python scripts/wiz_probe.py type NetworkExposureFilters
    python scripts/wiz_probe.py type NetworkExposure
    python scripts/wiz_probe.py exposures 192.0.2.10 192.0.2.11
    python scripts/wiz_probe.py query ./some_query.graphql

`exposures` takes IP addresses on the command line ON PURPOSE: this repo
forbids a real address appearing in any tracked file (CLAUDE.md; it caused
a repo republish on 2026-08-12), and an argument is not a tracked file.
Output is redacted of anything credential-shaped before printing.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402

from app.core.secrets import get_secret  # noqa: E402

TOKEN_URL = "https://auth.app.wiz.io/oauth/token"
AUDIENCE = "wiz-api"


def _fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def get_token() -> str:
    client_id = get_secret("WIZ_CLIENT_ID")
    client_secret = get_secret("WIZ_CLIENT_SECRET")
    if not client_id or not client_secret:
        _fail("WIZ_CLIENT_ID / WIZ_CLIENT_SECRET not set in the environment")
    resp = httpx.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": AUDIENCE,
        },
        timeout=30,
    )
    if resp.status_code != 200:
        _fail(f"token endpoint returned HTTP {resp.status_code}")
    return resp.json()["access_token"]


def gql(token: str, query: str, variables: dict | None = None) -> dict:
    endpoint = get_secret("WIZ_API_ENDPOINT")
    if not endpoint:
        _fail("WIZ_API_ENDPOINT not set in the environment")
    resp = httpx.post(
        endpoint,
        headers={"Authorization": f"Bearer {token}"},
        json={"query": query, "variables": variables or {}},
        timeout=120,
    )
    body = resp.json()
    # HTTP 200 can carry partial data PLUS errors — check the array
    # independently of the status code (Obsidian reference §4).
    if body.get("errors"):
        print("-- GraphQL errors --", file=sys.stderr)
        print(json.dumps(body["errors"], indent=2), file=sys.stderr)
    if resp.status_code != 200:
        _fail(f"HTTP {resp.status_code}")
    return body


# NOTE (verified live, 2026-09-12): our tenant's gateway silently DROPS
# GraphQL variables on introspection queries specifically — `query T($name:
# String!) { __type(name: $name) ... }` comes back "missing value for
# non-null variable 'name'" with HTTP 200. Variables work normally on real
# queries (networkExposures et al. were re-tested both ways), so this is an
# introspection-only quirk and NOT a reason for the connector to inline
# values. The type name is interpolated here instead; it is a developer
# tool taking a GraphQL type name, not user input.
_TYPE_QUERY = """
query {
  __type(name: "%s") {
    name
    kind
    description
    fields(includeDeprecated: true) {
      name
      isDeprecated
      deprecationReason
      type { kind name ofType { kind name ofType { kind name } } }
    }
    inputFields {
      name
      description
      type { kind name ofType { kind name ofType { kind name } } }
    }
    enumValues(includeDeprecated: true) { name isDeprecated deprecationReason }
  }
}
"""

_EXPOSURES_QUERY = """
query Exposures($filterBy: NetworkExposureFilters, $first: Int, $after: String) {
  networkExposures(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      type
      sourceIpRange
      destinationIpRange
      portRange
      firstSeenAt
      exposedEntity { id name type properties }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

_REDACT_KEYS = {"access_token", "refresh_token", "client_secret", "client_id", "authorization"}


def _redact(obj):
    """Strip anything credential-shaped before it reaches stdout."""
    if isinstance(obj, dict):
        return {k: ("<redacted>" if k.lower() in _REDACT_KEYS else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    cmd = sys.argv[1]

    if cmd == "auth":
        get_token()
        endpoint = get_secret("WIZ_API_ENDPOINT") or ""
        # Host only — the endpoint identifies the tenant.
        host = endpoint.split("//")[-1].split("/")[0]
        print(f"auth OK (endpoint host: {host})")
        return

    token = get_token()

    if cmd == "type":
        if len(sys.argv) < 3:
            _fail("usage: wiz_probe.py type <TypeName>")
        body = gql(token, _TYPE_QUERY % sys.argv[2])
        print(json.dumps(_redact(body.get("data")), indent=2))
        return

    if cmd == "exposures":
        ips = sys.argv[2:]
        if not ips:
            _fail("usage: wiz_probe.py exposures <ip> [ip ...]")
        body = gql(token, _EXPOSURES_QUERY, {
            "filterBy": {"destinationIpRange": ips, "type": ["PUBLIC_INTERNET"]},
            "first": 500,
        })
        print(json.dumps(_redact(body.get("data")), indent=2))
        return

    if cmd == "query":
        if len(sys.argv) < 3:
            _fail("usage: wiz_probe.py query <file.graphql>")
        doc = Path(sys.argv[2]).read_text(encoding="utf-8")
        body = gql(token, doc, json.loads(sys.argv[3]) if len(sys.argv) > 3 else {})
        print(json.dumps(_redact(body.get("data")), indent=2))
        return

    _fail(f"unknown command {cmd!r}")


if __name__ == "__main__":
    main()
