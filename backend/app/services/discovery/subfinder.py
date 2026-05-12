"""
Passive subdomain enumeration via subfinder (ProjectDiscovery).

Aggregates ~40 passive sources (Shodan, SecurityTrails, VirusTotal, Censys,
crt.sh, etc.) in a single Docker run. No direct contact with the target.
Accepts API keys for sources via environment variables passed to the container.
"""

import json
import logging
import subprocess
import tempfile

from app.connectors.base import DiscoveredAsset, PhaseResult
from app.models.asset import AssetType

log = logging.getLogger(__name__)

IMAGE = "projectdiscovery/subfinder:latest"


def available() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def run(domain: str) -> PhaseResult:
    """Run subfinder against the given domain and return discovered subdomains."""
    if not available():
        log.warning("subfinder: Docker not available, skipping")
        return PhaseResult()

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
            output_file = out.name

        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{output_file}:/output.json",
                IMAGE,
                "-d", domain,
                "-o", "/output.json",
                "-json",
                "-silent",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode not in (0, 1):
            log.warning("subfinder exited %d for %s", result.returncode, domain)
            return PhaseResult()

        return _parse(output_file, domain)

    except Exception:
        log.exception("subfinder failed for %s", domain)
        return PhaseResult()


def _parse(output_file: str, domain: str) -> PhaseResult:
    assets: list[DiscoveredAsset] = []
    seen: set[str] = set()
    try:
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    host = item.get("host", "").lower().strip()
                    source = item.get("source", "subfinder")
                except (json.JSONDecodeError, AttributeError):
                    host = line.lower().strip()
                    source = "subfinder"

                if not host or host in seen:
                    continue
                seen.add(host)
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.DNS_RECORD,
                    value=host,
                    parent_value=domain if host != domain else None,
                    asset_metadata={"sources": ["subfinder"], "subfinder_source": source},
                ))
    except Exception:
        log.exception("subfinder output parse failed")

    log.info("subfinder found %d subdomains for %s", len(assets), domain)
    return PhaseResult(assets=assets)
