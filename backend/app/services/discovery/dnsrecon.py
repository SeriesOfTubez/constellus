"""
Active DNS enumeration via dnsrecon.

Performs standard DNS enumeration: SOA, NS, MX, A, AAAA, SPF, zone transfer
attempts. Makes direct DNS queries to the target's nameservers — active but
non-intrusive. Off by default in scan options.
"""

import json
import logging
import subprocess
import tempfile

from app.connectors.base import DiscoveredAsset, PhaseResult
from app.models.asset import AssetType

log = logging.getLogger(__name__)

IMAGE = "darkoperator/dnsrecon"

_TYPE_MAP = {
    "A": AssetType.DNS_RECORD,
    "AAAA": AssetType.DNS_RECORD,
    "CNAME": AssetType.DNS_RECORD,
    "MX": AssetType.DNS_RECORD,
    "NS": AssetType.DNS_RECORD,
    "TXT": AssetType.DNS_RECORD,
    "SRV": AssetType.DNS_RECORD,
}


def available() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def run(domain: str) -> PhaseResult:
    if not available():
        log.warning("dnsrecon: Docker not available, skipping")
        return PhaseResult()

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as out:
            output_file = out.name

        subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{output_file}:/output.json",
                IMAGE,
                "-d", domain,
                "-t", "std",
                "-j", "/output.json",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        return _parse(output_file, domain)

    except Exception:
        log.exception("dnsrecon failed for %s", domain)
        return PhaseResult()


def _parse(output_file: str, domain: str) -> PhaseResult:
    assets: list[DiscoveredAsset] = []
    seen: set[str] = set()
    try:
        with open(output_file) as f:
            data = json.load(f)

        for record in data:
            rtype = record.get("type", "")
            name = record.get("name", "").lower().rstrip(".")
            address = record.get("address", "")

            if not name or name in seen:
                continue
            seen.add(name)

            assets.append(DiscoveredAsset(
                asset_type=AssetType.DNS_RECORD,
                value=name,
                parent_value=domain if name != domain else None,
                asset_metadata={
                    "sources": ["dnsrecon"],
                    "record_type": rtype,
                    "content": address or record.get("target", ""),
                },
            ))

            if rtype in ("A", "AAAA") and address and address not in seen:
                seen.add(address)
                assets.append(DiscoveredAsset(
                    asset_type=AssetType.IP_ADDRESS,
                    value=address,
                    parent_value=name,
                    asset_metadata={"sources": ["dnsrecon"]},
                ))

    except Exception:
        log.exception("dnsrecon output parse failed")

    log.info("dnsrecon found %d records for %s", len(assets), domain)
    return PhaseResult(assets=assets)
