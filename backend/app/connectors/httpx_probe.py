"""httpx connector — Service Identification Stack Layer 2.

Reads ports discovered by naabu (`ip.asset_metadata.open_ports[]`) and probes
each one with httpx — port-agnostic HTTP probing that works on any port, not
just 80/443. Non-HTTP ports produce no result from the worker and are left
untouched.

Architecturally identical to banner_grab: ScanningConnector subclass with a
no-op `scan()` and a real `port_scan(assets, config)` Phase 1.5 hook. Runs
after banner_grab (200) so its real Server-header/scheme data supersedes the
banner_grab stub for HTTP(S) ports.

What it adds per port:
  service          — scheme (http/https)
  service_version  — webserver (Server header)
  tech_stack       — Wappalyzer-detected technologies
  http_title       — page <title>
  favicon_hash     — mmh3 hash of /favicon.ico
  jarm             — JARM TLS fingerprint (also written by tlsx)
  sources          — "httpx" appended via the writer's union
"""

import ipaddress
import logging
import os
from typing import Any

import httpx

from app.connectors.base import (
    DiscoveredAsset,
    PhaseResult,
    ScanningConnector,
    TestResult,
    cdn_scan_targets,
)
from app.models.asset import AssetType

log = logging.getLogger(__name__)

_SCANNER_URL = os.environ.get("SCANNER_URL", "http://scanner-worker:8001")
_SCANNER_TOKEN = os.environ.get("SCANNER_INTERNAL_TOKEN", "")
_HEADERS = {"X-Internal-Token": _SCANNER_TOKEN}


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_multicast
        or addr.is_link_local or addr.is_reserved or addr.is_unspecified
    )


class HttpxConnector(ScanningConnector):
    name = "httpx"
    description = (
        "Service identification — probes each open port discovered by Naabu with httpx, "
        "capturing scheme, title, tech stack, favicon hash, and JARM fingerprint."
    )
    core = True

    # planning#148 — this connector's identity handle for the probe-
    # authorisation gate (app.services.probe_authorisation). Must match a
    # seeded `observers.name` row exactly — note this is "httpx", NOT
    # "httpx_probe" (the REGISTRY/connector-module id); the gate denies
    # outright (with a logged decision row) any Phase 1.5 connector missing
    # this attribute.
    observer = "httpx"

    # Runs AFTER banner_grab (200) — its scheme/Server-header data supersedes
    # the banner_grab stub for HTTP(S) ports.
    port_scan_order = 300

    def get_config_schema(self) -> dict:
        return {}

    def is_configured(self) -> bool:
        return bool(_SCANNER_TOKEN)

    def _test(self, config: dict) -> TestResult:
        try:
            resp = httpx.get(f"{_SCANNER_URL}/health", headers=_HEADERS, timeout=10)
            if resp.status_code == 200:
                return TestResult(success=True, message=f"Scanner worker reachable at {_SCANNER_URL}")
            return TestResult(success=False, message=f"Scanner worker returned HTTP {resp.status_code}")
        except httpx.ConnectError:
            return TestResult(success=False, message=f"Cannot reach scanner worker at {_SCANNER_URL}")
        except Exception as e:
            return TestResult(success=False, message=str(e))

    def scan(self, targets: list[str], config: dict[str, Any]) -> PhaseResult:
        # Phase 3 no-op — real work is the port_scan() hook below.
        return PhaseResult()

    def port_scan(
        self,
        assets: list[DiscoveredAsset],
        config: dict[str, Any],
    ) -> PhaseResult:
        tier_name = config.get("_tier", "")
        tier_profile = (config.get("_aggressiveness") or {}).get("httpx") or {}
        if not tier_profile.get("enabled", False):
            log.info("httpx probe skipped — disabled at %s tier", tier_name or "current")
            return PhaseResult()

        # Collect (ip, port) pairs from the open_ports[] metadata that naabu
        # (or any earlier port enricher) populated on each public IP.
        per_ip_ports: dict[str, set[int]] = {}
        for a in assets:
            if a.asset_type != AssetType.IP_ADDRESS:
                continue
            if not _is_public_ip(a.value):
                continue
            open_ports = (a.asset_metadata or {}).get("open_ports") or []
            if not isinstance(open_ports, list):
                continue
            for entry in open_ports:
                if not isinstance(entry, dict):
                    continue
                port = entry.get("port")
                if isinstance(port, int) and 1 <= port <= 65535:
                    per_ip_ports.setdefault(a.value, set()).add(port)

        # CDN-annotated CNAME records have no IP asset to read ports from — the
        # terminal CDN IP is suppressed. Probe the customer hostname directly on
        # the standard web ports so httpx sends the right Host header and
        # fingerprints the customer's app behind the CDN (not the CDN's default).
        # Results route back to the dns_record. Only observed ports are written.
        cdn_targets = cdn_scan_targets(assets)

        if not per_ip_ports and not cdn_targets:
            log.info("httpx probe skipped — no ports to probe")
            return PhaseResult()

        targets = [
            {"ip": ip, "port": port}
            for ip, ports in per_ip_ports.items()
            for port in sorted(ports)
        ] + [
            {"ip": hostname, "port": port}
            for hostname in sorted(cdn_targets)
            for port in (80, 443)
        ]

        timeout = float(tier_profile.get("timeout", 5.0))
        concurrency = int(tier_profile.get("concurrency", 20))

        log.info(
            "httpx probe starting — tier=%s targets=%d ips=%d cdn_hosts=%d timeout=%.1fs concurrency=%d",
            tier_name or "?", len(targets), len(per_ip_ports), len(cdn_targets),
            timeout, concurrency,
        )

        results = self._invoke_worker(
            targets=targets,
            timeout=timeout,
            concurrency=concurrency,
        )

        log.info("httpx probe returned %d results", len(results))

        return self._build_phase_result(results, cdn_targets=cdn_targets)

    # ── internals ────────────────────────────────────────────────────────

    def _invoke_worker(
        self,
        *,
        targets: list[dict],
        timeout: float,
        concurrency: int,
    ) -> list[dict]:
        payload: dict[str, Any] = {
            "targets": targets,
            "timeout": timeout,
            "concurrency": concurrency,
        }
        outer_timeout = max(60.0, timeout * (len(targets) / max(concurrency, 1) + 2))

        try:
            resp = httpx.post(
                f"{_SCANNER_URL}/httpx/probe",
                json=payload,
                headers=_HEADERS,
                timeout=outer_timeout,
            )
            resp.raise_for_status()
            body = resp.json()
            results = body.get("results", []) or []
            if body.get("timed_out"):
                log.warning(
                    "httpx worker call timed out for %d target(s) — %d result(s) recovered from partial "
                    "output before the subprocess was killed", len(targets), len(results),
                )
            return results
        except httpx.HTTPError:
            log.exception("httpx worker request failed (targets=%d)", len(targets))
            return []

    def _build_phase_result(
        self,
        rows: list[dict],
        cdn_targets: dict[str, dict] | None = None,
    ) -> PhaseResult:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        cdn_targets = cdn_targets or {}

        # An owner is the dns_record hostname for CDN probes (routed by the
        # worker's echoed input_host), else the resolved IP. The worker's -nf
        # flag makes httpx probe both http and https on the same port; for a TLS
        # port the bare-HTTP probe is just an upgrade/error page, so prefer the
        # https row when both are present for the same (owner, port).
        by_key: dict[tuple[str, str, int], dict] = {}  # (kind, owner, port)
        for row in rows:
            port = row.get("port")
            if not isinstance(port, int):
                continue
            input_host = row.get("input_host")
            if input_host and input_host in cdn_targets:
                key = ("dns", input_host, port)
            else:
                ip = row.get("ip")
                if not ip:
                    continue
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                key = ("ip", ip, port)
            if key not in by_key or row.get("scheme") == "https":
                by_key[key] = row

        # owner key (kind, value) -> list of port entries
        per_owner: dict[tuple[str, str], list[dict]] = {}

        for (kind, owner, port), row in by_key.items():
            entry: dict[str, Any] = {
                "port": port,
                "protocol": "tcp",
                "sources": ["httpx"],
                "last_seen_at": now,
            }
            # Only include identification fields when the worker filled them
            # in — empty/None values would override real data via the
            # writer's last-write-wins for non-empty values.
            scheme = row.get("scheme")
            if isinstance(scheme, str) and scheme:
                entry["service"] = scheme
            webserver = row.get("webserver")
            if isinstance(webserver, str) and webserver:
                entry["service_version"] = webserver
            tech = row.get("tech")
            if isinstance(tech, list) and tech:
                entry["tech_stack"] = tech
            title = row.get("title")
            if isinstance(title, str) and title:
                entry["http_title"] = title
            favicon = row.get("favicon")
            if isinstance(favicon, str) and favicon:
                entry["favicon_hash"] = favicon
            jarm = row.get("jarm")
            if isinstance(jarm, str) and jarm:
                entry["jarm"] = jarm

            # httpx only emits a row for an endpoint that returned an HTTP
            # response, so a scheme means a live HTTP service — positive
            # application-layer confirmation (a phantom port never responds).
            if entry.get("service"):
                entry["l7_confirmed"] = True

            per_owner.setdefault((kind, owner), []).append(entry)

        patches: list[DiscoveredAsset] = []
        for (kind, owner), entries in per_owner.items():
            meta: dict[str, Any] = {"sources": ["httpx"], "open_ports": entries}
            if kind == "dns":
                # Echo the CNAME's identity fields so the writer merges into the
                # existing record instead of creating a duplicate bare dns_record
                # (canonical key is value+record_type+content).
                ident = cdn_targets.get(owner, {})
                if ident.get("record_type"):
                    meta["record_type"] = ident["record_type"]
                if ident.get("content"):
                    meta["content"] = ident["content"]
            patches.append(DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD if kind == "dns" else AssetType.IP_ADDRESS,
                value=owner,
                parent_value=None,
                asset_metadata=meta,
            ))

        return PhaseResult(assets=patches)
