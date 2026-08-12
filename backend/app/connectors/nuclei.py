import logging
import os
import re
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.connectors.base import DiscoveredFinding, PhaseResult, ScanningConnector, TestResult
from app.models.finding import Severity

log = logging.getLogger(__name__)

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\[[0-9;]*m")

_SCANNER_URL = os.environ.get("SCANNER_URL", "http://scanner-worker:8001")
_SCANNER_TOKEN = os.environ.get("SCANNER_INTERNAL_TOKEN", "")
_HEADERS = {"X-Internal-Token": _SCANNER_TOKEN}

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def _cvss_version(vector: str | None) -> str | None:
    if not vector:
        return None
    if vector.startswith("CVSS:4."):
        return "4.0"
    if vector.startswith("CVSS:3.1"):
        return "3.1"
    if vector.startswith("CVSS:3.0"):
        return "3.0"
    if vector.startswith("AV:"):
        return "2.0"
    return None


def _port_from_matched_at(matched_at: str | None) -> int | None:
    """Extract the port a Nuclei match maps to. The port lives in the matched-at
    URL (the default 80/443 is omitted there). An explicit port wins; a URL with a
    scheme but no port falls back to the scheme default; a bare ``host:port`` is
    parsed via a synthetic scheme-relative prefix. Returns None when no port can be
    determined (e.g. a bare hostname, or an unparseable value). Normalises
    provenance so the UI can show + filter by port across sources (#71)."""
    if not matched_at:
        return None
    s = matched_at.strip()
    if not s:
        return None
    try:
        if re.match(r"^[a-z][a-z0-9+.-]*://", s, re.IGNORECASE):
            parts = urlsplit(s)
            if parts.port is not None:
                return parts.port
            scheme = parts.scheme.lower()
            return 443 if scheme == "https" else 80 if scheme == "http" else None
        return urlsplit(f"//{s}").port
    except ValueError:
        return None


class NucleiConnector(ScanningConnector):
    name = "Nuclei"
    env_key_map: dict = {}
    description = "Risk detection — CVEs, misconfigs, exposed files, default credentials, EOL software"
    core = True

    def get_config_schema(self) -> dict:
        return {
            "severity_filter": {
                "label": "Severity Filter",
                "type": "multiselect",
                "options": ["critical", "high", "medium", "low", "info"],
                "default": ["critical", "high", "medium"],
                "help": "Severity levels to include in results",
            },
        }

    def is_configured(self) -> bool:
        return bool(_SCANNER_TOKEN)

    def _test(self, config: dict) -> TestResult:
        try:
            resp = httpx.get(f"{_SCANNER_URL}/health", headers=_HEADERS, timeout=10)
            if resp.status_code == 200:
                return TestResult(success=True, message=f"Nuclei worker reachable at {_SCANNER_URL}")
            return TestResult(success=False, message=f"Nuclei worker returned HTTP {resp.status_code}")
        except httpx.ConnectError:
            return TestResult(success=False, message=f"Cannot reach Nuclei worker at {_SCANNER_URL}")
        except Exception as e:
            return TestResult(success=False, message=str(e))

    def scan(self, targets: list[str], config: dict[str, Any]) -> PhaseResult:
        if not targets:
            return PhaseResult()

        # Aggressiveness profile injected by scan_executor — tier-resolved
        # rate_limit / concurrency / exclude_tags + severity ceiling. Falls
        # back to the "polite" defaults if the connector is invoked outside
        # the executor (e.g. by a test harness).
        tier_profile = (config.get("_aggressiveness") or {}).get("nuclei") or {}
        rate_limit = int(tier_profile.get("rate_limit", 50))
        concurrency = int(tier_profile.get("concurrency", 25))
        exclude_tags = list(tier_profile.get("exclude_tags", ["intrusive", "fuzz", "dos"]))

        # Scan-wide detected-tech tag union, injected by scan_executor.
        # Empty/absent -> fail open (don't pass -tags at all, preserving
        # today's "scan everything minus -etags" behaviour).
        include_tags = config.get("_nuclei_include_tags") or set()

        # User-configured severity filter is capped by the tier's allowed
        # range — stealth tier never returns 'info' even if a user picks it.
        user_severities = config.get("severity_filter") or ["critical", "high", "medium"]
        tier_severities = tier_profile.get("severity_filter") or user_severities
        severities = [s for s in user_severities if s in tier_severities] or tier_severities

        try:
            resp = httpx.post(
                f"{_SCANNER_URL}/scan",
                json={
                    "targets": targets,
                    "severity": ",".join(severities),
                    "rate_limit": rate_limit,
                    "concurrency": concurrency,
                    "exclude_tags": ",".join(exclude_tags) if exclude_tags else "",
                    "tags": ",".join(sorted(include_tags)) if include_tags else "",
                },
                headers=_HEADERS,
                timeout=630,
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("timed_out"):
                log.warning(
                    "Nuclei scan-worker call timed out for %d target(s) — %d finding(s) recovered from "
                    "partial output before the subprocess was killed",
                    len(targets), len(body.get("findings", [])),
                )
            return PhaseResult(findings=self._parse_findings(body.get("findings", [])))
        except Exception:
            log.exception("Nuclei worker request failed for %d target(s)", len(targets))
            return PhaseResult()

    def _parse_findings(self, items: list[dict]) -> list[DiscoveredFinding]:
        findings = []
        for item in items:
            try:
                info = item.get("info", {})
                severity_raw = info.get("severity", "info").lower()
                severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)

                classification = info.get("classification", {})

                raw_cve = classification.get("cve-id")
                cve_id: str | None = None
                if isinstance(raw_cve, list) and raw_cve:
                    cve_id = raw_cve[0].upper()
                elif isinstance(raw_cve, str) and raw_cve:
                    cve_id = raw_cve.upper()

                raw_score = classification.get("cvss-score")
                cvss_score = float(raw_score) if raw_score is not None else None
                cvss_vector = classification.get("cvss-metrics") or None
                cvss_version = _cvss_version(cvss_vector)

                raw_cwe = classification.get("cwe-id")
                cwe: str | None = None
                if isinstance(raw_cwe, list) and raw_cwe:
                    cwe = raw_cwe[0]
                elif isinstance(raw_cwe, str) and raw_cwe:
                    cwe = raw_cwe

                findings.append(DiscoveredFinding(
                    asset_value=item.get("host", item.get("matched-at", "")),
                    finding_type=item.get("template-id", "nuclei-finding"),
                    source="nuclei",
                    severity=severity,
                    title=info.get("name", item.get("template-id", "Finding")),
                    description=info.get("description"),
                    detail={
                        "template_id": item.get("template-id"),
                        "matched_at": item.get("matched-at"),
                        "port": _port_from_matched_at(item.get("matched-at")),
                        "extracted_results": item.get("extracted-results", []),
                        "curl_command": item.get("curl-command"),
                        "tags": info.get("tags", []),
                        "references": info.get("reference", []),
                    },
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cvss_version=cvss_version,
                    cwe=cwe,
                ))
            except Exception:
                continue
        return findings
