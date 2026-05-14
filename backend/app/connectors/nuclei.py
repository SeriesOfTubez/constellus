import os
import re
from typing import Any

import httpx

from app.connectors.base import DiscoveredFinding, PhaseResult, ScanningConnector, TestResult
from app.models.finding import Severity

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\[[0-9;]*m")

_NUCLEI_URL = os.environ.get("NUCLEI_URL", "http://nuclei-worker:8001")
_NUCLEI_TOKEN = os.environ.get("NUCLEI_INTERNAL_TOKEN", "")
_HEADERS = {"X-Internal-Token": _NUCLEI_TOKEN}

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


class NucleiConnector(ScanningConnector):
    name = "Nuclei"
    env_key_map: dict = {}
    description = "Risk detection — CVEs, misconfigs, exposed files, default credentials, EOL software"

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
        return bool(_NUCLEI_TOKEN)

    def _test(self, config: dict) -> TestResult:
        try:
            resp = httpx.get(f"{_NUCLEI_URL}/health", headers=_HEADERS, timeout=10)
            if resp.status_code == 200:
                return TestResult(success=True, message=f"Nuclei worker reachable at {_NUCLEI_URL}")
            return TestResult(success=False, message=f"Nuclei worker returned HTTP {resp.status_code}")
        except httpx.ConnectError:
            return TestResult(success=False, message=f"Cannot reach Nuclei worker at {_NUCLEI_URL}")
        except Exception as e:
            return TestResult(success=False, message=str(e))

    def scan(self, targets: list[str], config: dict[str, Any]) -> PhaseResult:
        if not targets:
            return PhaseResult()

        severities = config.get("severity_filter", ["critical", "high", "medium"])

        try:
            resp = httpx.post(
                f"{_NUCLEI_URL}/scan",
                json={"targets": targets, "severity": ",".join(severities)},
                headers=_HEADERS,
                timeout=630,
            )
            resp.raise_for_status()
            return PhaseResult(findings=self._parse_findings(resp.json().get("findings", [])))
        except Exception:
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
