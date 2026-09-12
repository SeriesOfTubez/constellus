"""Wiz cloud-inventory enrichment connector (planning#118a).

Answers exactly one question, per public IP in the scan's asset set: **does
this address belong to a resource in a cloud account we control?** When it
does, the connector emits a `cloud_inventory` claim attributed to the `wiz`
observer (seeded in migration 0048), which the projector promotes to
`estate = "proven_ours"` — outranking every other estate rule, because
credentialed inventory is the strongest ownership evidence the system has
(planning#142 D1, planning#145 L4).

This is the first INTERNAL claim source in the system. All 18 observers
seeded by migration 0039 look at an estate from the outside and infer
inward; this one reads the estate's own control plane.

Deliberately NOT in this slice (planning#118b): relayed-signal provenance —
Wiz-as-detector vs Wiz-as-relay, the `VulnerabilityOrigin` /
`ExternalToolOrigin` enums and the `ImportedAssetOrigin` registry — and Wiz
Code SCA findings, which are repo-scoped and need the unresolved
repo<->asset mapping question answered first. Neither is needed to
establish ownership, so neither is here.

── Why `networkExposures`, and why one query per IP ────────────────────────

`cloudResourcesV2` cannot do this. Its `CloudResourceV2Filters` has no IP or
CIDR filter of any kind — `ipAddresses` exists as an OUTPUT field on VM
types only, so you cannot ask it "who owns this address" (verified against
our own schema; see Obsidian `Constellus — Wiz API Reference` §2).
`networkExposures` is the query built for it, and its `destinationIpRange`
filter takes a list of addresses, ranges or CIDRs.

That filter accepts a LIST, so batching many IPs into one query is tempting.
It is not safe, and the reason is only visible in live data rather than in
the docs. Probing our tenant's 3,000+ PUBLIC_INTERNET exposures found that
the `destinationIpRange` a node comes BACK with is:

  * a single host, as a `/32` CIDR or a one-address `a-a` range (~64%);
  * a bare `"-"`, carrying no address at all (~3%);
  * or a **DNS hostname** — Cloud Run URLs, `cloudfunctions.net`,
    `googleusercontent.com`, `looker.app` — for managed/serverless resources
    with no stable address (~33%).

Not one of the 3,000 was a plain single IP string. So a batched query cannot
reliably attribute each returned node back to the input IP that matched it:
for a third of them there is no address in the response to match against at
all. Guessing there would mean claiming an address is ours on the strength
of an adjacent record, which is exactly the false-attribution failure an
EASM cannot afford. One query per IP makes Wiz's own server-side matching
the authority and removes the attribution step entirely.

The cost is affordable: a service account gets 10 queries/sec, and
enrichment already works this way (`shodan.py` is one lookup per IP with a
sleep between).

Round-trip verified live: for each of 8 single-host exposures harvested from
the tenant, re-querying that address returned the same `exposedEntity`, and
exactly one distinct entity (multiple nodes per IP are per-port rules for
the same resource). Negative controls (`8.8.8.8`, `1.1.1.1`, and RFC-5737
addresses) returned zero nodes.

── Other live-verified behaviour worth not rediscovering ───────────────────

  * Our tenant's gateway silently DROPS GraphQL variables on introspection
    queries (`__type`) — HTTP 200 with "missing value for non-null
    variable". It honours them normally on real queries, which is why this
    module uses variables rather than interpolating into the query document.
    See `scripts/wiz_probe.py`, which is in the repo precisely so the next
    person does not rediscover this from a deleted temp file.
  * HTTP 200 can carry partial `data` alongside an `errors` array, so the
    errors array is checked independently of the status code.
  * `exposedEntity.deletedAt` is honoured: a resource deleted in-cloud
    lingers in the Wiz graph for ~48h, and a deleted resource must not keep
    authorising probes against an address that may already have been
    reassigned to someone else.
  * Nulls on enrichment fields usually mean the graph is still being built
    asynchronously, not that a module is unlicensed — so a missing `name` or
    `type` degrades the claim's detail, never its `confirmed` verdict.
"""

import ipaddress
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.connectors.base import (
    DiscoveredAsset,
    EnrichmentConnector,
    PhaseResult,
    TestResult,
)
from app.connectors.http import connector_post
from app.core.secrets import get_secret
from app.models.asset import AssetType

log = logging.getLogger(__name__)

# Deployment-scoped, not tenant-scoped: Commercial tenants all use this one.
# (Wiz for Gov is auth.app.wiz.us, Commercial-on-GovCloud is auth.gov.wiz.io
# — neither applies here, so this stays a constant rather than a config field
# until a deployment actually needs one.)
_TOKEN_URL = "https://auth.app.wiz.io/oauth/token"
_AUDIENCE = "wiz-api"

# Wiz issues 24h tokens and explicitly asks integrations to cache them for
# their full validity — the token endpoint is itself rate-limited per tenant
# and per service account. A `refresh_token` comes back in the response but
# Wiz documents no grant flow that redeems it, so renewal is just another
# client_credentials POST. The skew keeps a long enrichment run from tripping
# over an expiry it started just inside.
_TOKEN_EXPIRY_SKEW = timedelta(minutes=5)

# Service-account budget is 10 queries/sec. This paces well under it; the
# shared connector_post wrapper handles any 429 we still earn, honouring
# Retry-After headers (never the 429 body, whose shape Wiz reserves the right
# to change).
_INTER_QUERY_DELAY = 0.15

# networkExposures caps `first` at 500 — half what some other typed queries
# allow. It also shares graphSearch's hard 10,000-result pagination ceiling,
# which is not a practical concern for a single-address filter but is why
# this pages a bounded number of times rather than looping unbounded.
_PAGE_SIZE = 500
_PAGE_LIMIT = 20

_EXPOSURES_QUERY = """
query ConstellusOwnership($filterBy: NetworkExposureFilters, $first: Int, $after: String) {
  networkExposures(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      type
      destinationIpRange
      firstSeenAt
      exposedEntity {
        id
        name
        type
        deletedAt
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# Stable observer slug — must match the row seeded by migration 0048.
_OBSERVER = "wiz"

# Cap on resources itemised in one claim_value. An address fronting more
# resources than this is still `confirmed`; only the itemised detail is
# truncated, because the claim's job is to answer "ours?", not to mirror the
# inventory.
_MAX_RESOURCES_PER_CLAIM = 20

_token_lock = threading.Lock()
_token_cache: dict[str, tuple[str, datetime]] = {}


def _is_public_ip(value: str) -> bool:
    """Globally routable, i.e. an address that could plausibly be a public
    cloud resource's.

    There are already six near-identical copies of this predicate
    (shodan.py, naabu.py, tlsx.py, httpx_probe.py, banner_grab.py,
    exposure_analyzer.py), all spelling it as a hand-rolled negation:

        not (is_private or is_loopback or is_multicast
             or is_link_local or is_reserved or is_unspecified)

    This one deliberately does NOT copy that spelling, because the negation
    has a hole: it accepts CGNAT space (100.64.0.0/10, RFC 6598), for which
    `is_private` is False while `is_global` is also False. Writing the
    known-incomplete version into new code to preserve symmetry would be
    propagating a bug for tidiness.

    `is_global` alone is not the fix either — it is True for multicast
    (224.0.0.0/4, ff00::/8), which the six-clause negation does exclude. The
    two predicates have complementary holes, so this pairs them. Verified
    across RFC-1918, loopback, link-local, multicast, unspecified, CGNAT and
    the RFC-5737/3849 documentation ranges (see
    `test_public_ip_filter_excludes_*`).

    The divergence is intentional and narrow; consolidating all seven call
    sites onto this pairing belongs in its own change, not in this slice.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


def _now() -> datetime:
    return datetime.now(timezone.utc)


class WizConnector(EnrichmentConnector):
    name = "Wiz"
    description = "Cloud asset correlation — maps public IPs to cloud resources and Wiz findings"
    env_key_map = {
        "client_id": "WIZ_CLIENT_ID",
        "client_secret": "WIZ_CLIENT_SECRET",
        "api_endpoint": "WIZ_API_ENDPOINT",
    }

    def get_config_schema(self) -> dict:
        return {
            "client_id": {
                "label": "Client ID",
                "type": "secret",
                "help": "Wiz service account client ID",
            },
            "client_secret": {
                "label": "Client Secret",
                "type": "secret",
                "help": "Wiz service account client secret",
            },
            "api_endpoint": {
                "label": "API Endpoint",
                "type": "string",
                "help": "Wiz API endpoint URL (e.g. https://api.us1.app.wiz.io/graphql)",
            },
        }

    def is_configured(self) -> bool:
        return bool(get_secret("WIZ_CLIENT_ID") and get_secret("WIZ_CLIENT_SECRET"))

    def _test(self, config: dict) -> TestResult:
        client_id = get_secret("WIZ_CLIENT_ID")
        client_secret = get_secret("WIZ_CLIENT_SECRET")

        if not client_id or not client_secret:
            return TestResult(success=False, message="Wiz credentials not configured")

        try:
            response = httpx.post(
                _TOKEN_URL,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "audience": _AUDIENCE,
                },
                timeout=15,
            )
            if response.status_code == 200:
                return TestResult(success=True, message="Connected successfully")
            return TestResult(
                success=False,
                message="Authentication failed",
                details={"status": response.status_code},
            )
        except Exception as e:
            return TestResult(success=False, message=str(e))

    # ── enrichment ─────────────────────────────────────────────────────────

    def enrich(self, assets: list[DiscoveredAsset], config: dict[str, Any]) -> PhaseResult:
        client_id = get_secret("WIZ_CLIENT_ID")
        client_secret = get_secret("WIZ_CLIENT_SECRET")
        api_endpoint = get_secret("WIZ_API_ENDPOINT")
        if not client_id or not client_secret or not api_endpoint:
            return PhaseResult()

        ips: list[str] = []
        seen: set[str] = set()
        for asset in assets:
            if asset.asset_type != AssetType.IP_ADDRESS:
                continue
            if asset.value in seen or not _is_public_ip(asset.value):
                continue
            seen.add(asset.value)
            ips.append(asset.value)

        if not ips:
            log.info(
                "Wiz: no public IPs in asset set (%d total assets) — nothing to correlate",
                len(assets),
            )
            return PhaseResult()

        try:
            token = _get_token(client_id, client_secret)
        except Exception:
            log.exception("Wiz: could not obtain an access token — skipping enrichment")
            return PhaseResult()

        log.info("Wiz: correlating %d public IP(s) against cloud inventory", len(ips))

        new_assets: list[DiscoveredAsset] = []
        confirmed = 0

        for index, ip in enumerate(ips):
            try:
                nodes = _exposures_for_ip(api_endpoint, token, ip)
            except Exception as exc:
                # One address failing must not abandon the rest of the batch.
                log.warning("Wiz: exposure lookup failed for an IP: %s", exc)
                _sleep_between(index, len(ips))
                continue

            claim = _claim_from_nodes(nodes)
            if claim is not None:
                confirmed += 1
                new_assets.append(DiscoveredAsset(
                    asset_type=AssetType.IP_ADDRESS,
                    value=ip,
                    parent_value=None,
                    observer=_OBSERVER,
                    asset_metadata={"sources": [_OBSERVER], "cloud_inventory": claim},
                ))
            _sleep_between(index, len(ips))

        log.info(
            "Wiz: %d of %d public IP(s) confirmed as cloud resources we control",
            confirmed, len(ips),
        )
        return PhaseResult(assets=new_assets)


# ── helpers ────────────────────────────────────────────────────────────────

def _sleep_between(index: int, total: int) -> None:
    if index < total - 1:
        time.sleep(_INTER_QUERY_DELAY)


def _get_token(client_id: str, client_secret: str) -> str:
    """Return a cached access token, fetching a new one when it is close to
    expiring. Keyed by client_id so a credential rotation does not keep
    serving the previous account's token."""
    with _token_lock:
        cached = _token_cache.get(client_id)
        if cached is not None:
            token, expires_at = cached
            if _now() + _TOKEN_EXPIRY_SKEW < expires_at:
                return token

        response = connector_post(
            _TOKEN_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": _AUDIENCE,
            },
            timeout=30,
        )
        if response.status_code != 200:
            # Deliberately status-only: the body of a failed token exchange
            # can echo back credential material.
            raise RuntimeError(f"Wiz token endpoint returned HTTP {response.status_code}")
        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise RuntimeError("Wiz token endpoint returned no access_token")
        expires_in = payload.get("expires_in")
        try:
            lifetime = timedelta(seconds=int(expires_in))
        except (TypeError, ValueError):
            lifetime = timedelta(hours=24)
        _token_cache[client_id] = (token, _now() + lifetime)
        return token


def _graphql(api_endpoint: str, token: str, query: str, variables: dict) -> dict:
    response = connector_post(
        api_endpoint,
        headers={"Authorization": f"Bearer {token}"},
        json={"query": query, "variables": variables},
        timeout=120,
    )
    try:
        body = response.json()
    except ValueError as exc:
        raise RuntimeError(f"Wiz returned a non-JSON body (HTTP {response.status_code})") from exc

    # A GraphQL error can arrive with HTTP 200 and partial data, so this is
    # checked independently of the status code rather than inside an
    # `if status != 200` branch.
    errors = body.get("errors")
    if errors:
        codes = sorted({
            (e.get("extensions") or {}).get("code")
            for e in errors if isinstance(e, dict)
        } - {None})
        first = errors[0].get("message") if isinstance(errors[0], dict) else None
        raise RuntimeError(f"Wiz GraphQL error{f' {codes}' if codes else ''}: {first}")

    if response.status_code != 200:
        raise RuntimeError(f"Wiz returned HTTP {response.status_code}")
    return body.get("data") or {}


def _exposures_for_ip(api_endpoint: str, token: str, ip: str) -> list[dict]:
    """Every PUBLIC_INTERNET exposure whose destination matches `ip`.

    Matching is Wiz's, server-side: the address goes in as the filter and the
    returned nodes are by construction the ones it matched. Nothing here
    re-derives the match from `destinationIpRange`, which for a third of real
    exposures is a hostname rather than an address (see module docstring)."""
    nodes: list[dict] = []
    after: str | None = None

    for _ in range(_PAGE_LIMIT):
        data = _graphql(api_endpoint, token, _EXPOSURES_QUERY, {
            "filterBy": {"destinationIpRange": [ip], "type": ["PUBLIC_INTERNET"]},
            "first": _PAGE_SIZE,
            "after": after,
        })
        exposures = data.get("networkExposures") or {}
        nodes.extend(n for n in (exposures.get("nodes") or []) if isinstance(n, dict))

        page = exposures.get("pageInfo") or {}
        if not page.get("hasNextPage"):
            return nodes
        after = page.get("endCursor")
        if not after:
            return nodes

    log.warning("Wiz: stopped paginating exposures after %d pages", _PAGE_LIMIT)
    return nodes


def _claim_from_nodes(nodes: list[dict]) -> dict | None:
    """Build a `cloud_inventory` claim value, or None if nothing confirms.

    Returning None rather than `{"confirmed": False}` is deliberate. A claim
    is a positive assertion by an observer; "Wiz has no exposure for this
    address" is not evidence that the address is NOT ours — it is equally
    consistent with an address in a cloud account Wiz does not cover, an
    on-prem address, or a resource whose graph entry is still being built.
    The absence layer (planning#145) is where "we looked and found nothing"
    belongs, and it reads a claim's absence. Writing `confirmed: False` here
    would turn "no evidence" into "evidence of no" — the inversion this
    codebase rejects elsewhere (an `unknown` estate still notifies; only an
    affirmative `not_ours` suppresses)."""
    resources: dict[str, dict] = {}
    exposure_ids: list[str] = []

    for node in nodes:
        entity = node.get("exposedEntity")
        if not isinstance(entity, dict):
            continue
        # A resource deleted in-cloud lingers in the graph for ~48h. Its
        # address may already belong to someone else, so it must not keep
        # authorising probes.
        if entity.get("deletedAt"):
            continue
        entity_id = entity.get("id")
        if not entity_id:
            continue
        resources.setdefault(entity_id, {
            "id": entity_id,
            "name": entity.get("name"),
            "type": entity.get("type"),
        })
        node_id = node.get("id")
        if node_id:
            exposure_ids.append(node_id)

    if not resources:
        return None

    ordered = sorted(resources.values(), key=lambda r: r["id"])
    return {
        "confirmed": True,
        # Empty, not absent, and NOT the resource names. Wiz proves the
        # ADDRESS is ours; it licenses no hostname. `exposedEntity.name` is a
        # cloud resource name ("prod-web-lb"), not a DNS name, and feeding it
        # to a name-addressed probe would send traffic to a string nobody
        # resolves. An explicit `[]` tells a future reader (planning#128,
        # which is expected to start consulting this key) that this producer
        # contributes no names — rather than leaving them to guess whether
        # the key was simply forgotten.
        "authorised_names": [],
        "resource_count": len(ordered),
        "resources": ordered[:_MAX_RESOURCES_PER_CLAIM],
        "exposure_count": len(exposure_ids),
        "evidence_ref": sorted(exposure_ids)[:_MAX_RESOURCES_PER_CLAIM],
    }
