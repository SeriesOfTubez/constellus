import json
import re
import subprocess
import tempfile
from typing import Any

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m|\[[0-9;]*m")


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

from app.connectors.base import DiscoveredFinding, PhaseResult, ScanningConnector, TestResult
from app.models.finding import Severity


# Map Nuclei severity labels to our internal severity enum
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiConnector(ScanningConnector):
    name = "Nuclei"
    env_key_map: dict = {}
    description = "Risk detection — CVEs, misconfigs, exposed files, default credentials, EOL software"

    def get_config_schema(self) -> dict:
        return {
            "container_image": {
                "label": "Container Image",
                "type": "string",
                "default": "projectdiscovery/nuclei:latest",
                "help": "Nuclei Docker image to use for scanning",
            },
            "severity_filter": {
                "label": "Severity Filter",
                "type": "multiselect",
                "options": ["critical", "high", "medium", "low", "info"],
                "default": ["critical", "high", "medium"],
                "help": "Severity levels to include in results",
            },
        }

    def is_configured(self) -> bool:
        return True  # all fields have defaults; Docker availability is a runtime check (Test button)

    def _test(self, config: dict) -> TestResult:
        try:
            info = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=5)
            if info.returncode != 0:
                return TestResult(success=False, message=f"Docker unavailable: {(info.stderr or info.stdout)[:200].strip()}")
        except FileNotFoundError:
            return TestResult(success=False, message="Docker CLI not found in container")
        except Exception as e:
            return TestResult(success=False, message=f"Docker error: {e}")
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "projectdiscovery/nuclei:latest", "-version"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                raw = (result.stdout.strip() or result.stderr.strip()).splitlines()[0]
                version = _ANSI_RE.sub("", raw).strip()
                return TestResult(success=True, message=f"Nuclei ready — {version}")
            return TestResult(success=False, message=f"Nuclei container error: {result.stderr[:200].strip()}")
        except Exception as e:
            return TestResult(success=False, message=str(e))

    def scan(self, targets: list[str], config: dict[str, Any]) -> PhaseResult:
        if not targets or not self._docker_available():
            return PhaseResult()

        image = config.get("container_image", "projectdiscovery/nuclei:latest")
        severities = config.get("severity_filter", ["critical", "high", "medium"])
        severity_arg = ",".join(severities)

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(targets))
                targets_file = f.name

            with tempfile.NamedTemporaryFile(mode="r", suffix=".jsonl", delete=False) as out:
                output_file = out.name

            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{targets_file}:/targets.txt:ro",
                    "-v", f"{output_file}:/output.jsonl",
                    image,
                    "-list", "/targets.txt",
                    "-severity", severity_arg,
                    "-output", "/output.jsonl",
                    "-json",
                    "-silent",
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode not in (0, 1):
                return PhaseResult()

            findings = self._parse_output(output_file)
            return PhaseResult(findings=findings)

        except Exception:
            return PhaseResult()

    def _parse_output(self, output_file: str) -> list[DiscoveredFinding]:
        findings = []
        try:
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    info = item.get("info", {})
                    severity_raw = info.get("severity", "info").lower()
                    severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)

                    classification = info.get("classification", {})

                    # CVE ID — classification is more reliable than tag string parsing
                    raw_cve = classification.get("cve-id")
                    cve_id: str | None = None
                    if isinstance(raw_cve, list) and raw_cve:
                        cve_id = raw_cve[0].upper()
                    elif isinstance(raw_cve, str) and raw_cve:
                        cve_id = raw_cve.upper()

                    # CVSS
                    raw_score = classification.get("cvss-score")
                    cvss_score = float(raw_score) if raw_score is not None else None
                    cvss_vector = classification.get("cvss-metrics") or None
                    cvss_version = _cvss_version(cvss_vector)

                    # CWE
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
            pass
        return findings

    def _docker_available(self) -> bool:
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
