"""tlsx connector — Service Identification Stack Layer 3.

Reads ports discovered by naabu (`ip.asset_metadata.open_ports[]`) and
TLS-handshakes each one with tlsx — port-agnostic certificate/cipher/JARM
collection that works on any port, not just 443. Non-TLS ports produce no
result from the worker and are left untouched.

Architecturally identical to banner_grab/httpx: ScanningConnector subclass
with a no-op `scan()` and a real `port_scan(assets, config)` Phase 1.5 hook.
Runs after httpx (300) — harmless ordering since the two write disjoint
fields (httpx never writes cert_summary, tlsx never writes tech_stack), with
the exception of `jarm`, where last-write-wins is fine since both tools
compute the same value from the TLS handshake.

What it adds per port:
  cert_summary  — {subject_cn, sans, issuer_cn, issuer_org, not_before,
                   not_after, cipher, tls_version, fingerprint (sha256),
                   serial, ja3, ja3s}
  jarm          — JARM TLS fingerprint (also written by httpx)
  sources       — "tlsx" appended via the writer's union
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


class TlsxConnector(ScanningConnector):
    name = "tlsx"
    description = (
        "Service identification — TLS-handshakes each open port discovered by Naabu with "
        "tlsx, capturing certificate subject/issuer/validity, cipher, TLS version, and JARM."
    )
    core = True

    # planning#148 — this connector's identity handle for the probe-
    # authorisation gate (app.services.probe_authorisation). Must match a
    # seeded `observers.name` row exactly; the gate denies outright (with a
    # logged decision row) any Phase 1.5 connector missing this attribute.
    observer = "tlsx"

    # Runs after httpx (300) — disjoint output fields, ordering is cosmetic.
    port_scan_order = 310

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
        tier_profile = (config.get("_aggressiveness") or {}).get("tlsx") or {}
        if not tier_profile.get("enabled", False):
            log.info("tlsx scan skipped — disabled at %s tier", tier_name or "current")
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
        # terminal CDN IP is suppressed. TLS is always the relevant port on a
        # CDN, so probe 443 on the customer hostname directly: tlsx sends the
        # right SNI and returns the customer's cert (not the CDN's default).
        # Results route back to the dns_record. Only observed certs are written.
        cdn_targets = cdn_scan_targets(assets)

        if not per_ip_ports and not cdn_targets:
            log.info("tlsx scan skipped — no ports to probe")
            return PhaseResult()

        targets = [
            {"ip": ip, "port": port}
            for ip, ports in per_ip_ports.items()
            for port in sorted(ports)
        ] + [
            {"ip": hostname, "port": 443}
            for hostname in sorted(cdn_targets)
        ]

        timeout = float(tier_profile.get("timeout", 5.0))
        concurrency = int(tier_profile.get("concurrency", 20))

        log.info(
            "tlsx scan starting — tier=%s targets=%d ips=%d cdn_hosts=%d timeout=%.1fs concurrency=%d",
            tier_name or "?", len(targets), len(per_ip_ports), len(cdn_targets),
            timeout, concurrency,
        )

        results = self._invoke_worker(
            targets=targets,
            timeout=timeout,
            concurrency=concurrency,
        )

        log.info("tlsx scan returned %d results", len(results))

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
                f"{_SCANNER_URL}/tlsx/scan",
                json=payload,
                headers=_HEADERS,
                timeout=outer_timeout,
            )
            resp.raise_for_status()
            body = resp.json()
            results = body.get("results", []) or []
            if body.get("timed_out"):
                log.warning(
                    "tlsx worker call timed out for %d target(s) — %d result(s) recovered from partial "
                    "output before the subprocess was killed", len(targets), len(results),
                )
            return results
        except httpx.HTTPError:
            log.exception("tlsx worker request failed (targets=%d)", len(targets))
            return []

    def _build_phase_result(
        self,
        rows: list[dict],
        cdn_targets: dict[str, dict] | None = None,
    ) -> PhaseResult:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        cdn_targets = cdn_targets or {}
        per_ip: dict[str, list[dict]] = {}
        per_cdn_host: dict[str, list[dict]] = {}

        for row in rows:
            host = row.get("host") or ""
            ip = row.get("ip") or host
            port = row.get("port")
            if not host or not isinstance(port, int):
                continue

            subject_cn = row.get("subject_cn")
            subject_an = row.get("subject_an")
            if not subject_cn and not subject_an:
                # Non-TLS port — tlsx returned nothing useful for it.
                continue

            entry: dict[str, Any] = {
                "port": port,
                "protocol": "tcp",
                "sources": ["tlsx"],
                "last_seen_at": now,
                # Reached only when a real certificate was returned (see the
                # subject_cn/subject_an guard above) — a completed TLS handshake
                # is positive application-layer confirmation. A firewall phantom
                # never completes TLS, so it never reaches here.
                "l7_confirmed": True,
            }

            cert_summary: dict[str, Any] = {}
            if isinstance(subject_cn, str) and subject_cn:
                cert_summary["subject_cn"] = subject_cn
            if isinstance(subject_an, list) and subject_an:
                cert_summary["sans"] = subject_an
            issuer_cn = row.get("issuer_cn")
            if isinstance(issuer_cn, str) and issuer_cn:
                cert_summary["issuer_cn"] = issuer_cn
            issuer_org = row.get("issuer_org")
            if isinstance(issuer_org, str) and issuer_org:
                cert_summary["issuer_org"] = issuer_org
            not_before = row.get("not_before")
            if isinstance(not_before, str) and not_before:
                cert_summary["not_before"] = not_before
            not_after = row.get("not_after")
            if isinstance(not_after, str) and not_after:
                cert_summary["not_after"] = not_after
            cipher = row.get("cipher")
            if isinstance(cipher, str) and cipher:
                cert_summary["cipher"] = cipher
            tls_version = row.get("tls_version")
            if isinstance(tls_version, str) and tls_version:
                cert_summary["tls_version"] = tls_version
            # sha256 fingerprint (cross-asset cert-reuse key, #56) + JA3 + serial.
            fingerprint = row.get("fingerprint")
            if isinstance(fingerprint, str) and fingerprint:
                cert_summary["fingerprint"] = fingerprint
            serial = row.get("serial")
            if isinstance(serial, str) and serial:
                cert_summary["serial"] = serial
            ja3 = row.get("ja3")
            if isinstance(ja3, str) and ja3:
                cert_summary["ja3"] = ja3
            ja3s = row.get("ja3s")
            if isinstance(ja3s, str) and ja3s:
                cert_summary["ja3s"] = ja3s

            if cert_summary:
                entry["cert_summary"] = cert_summary

            jarm = row.get("jarm")
            if isinstance(jarm, str) and jarm:
                entry["jarm"] = jarm

            # Route CDN hostname results to dns_record patches; IP results to ip_address.
            if host in cdn_targets:
                per_cdn_host.setdefault(host, []).append(entry)
            else:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                per_ip.setdefault(ip, []).append(entry)

        patches: list[DiscoveredAsset] = []
        for ip, entries in per_ip.items():
            patches.append(DiscoveredAsset(
                asset_type=AssetType.IP_ADDRESS,
                value=ip,
                parent_value=None,
                asset_metadata={
                    "sources": ["tlsx"],
                    "open_ports": entries,
                },
            ))
        for hostname, entries in per_cdn_host.items():
            # Echo the CNAME's identity fields (record_type, content) so the
            # writer merges into the existing record instead of creating a
            # duplicate bare dns_record (canonical key is value+record_type+content).
            ident = cdn_targets.get(hostname, {})
            meta: dict[str, Any] = {"sources": ["tlsx"], "open_ports": entries}
            if ident.get("record_type"):
                meta["record_type"] = ident["record_type"]
            if ident.get("content"):
                meta["content"] = ident["content"]
            patches.append(DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD,
                value=hostname,
                parent_value=None,
                asset_metadata=meta,
            ))

        return PhaseResult(assets=patches)
