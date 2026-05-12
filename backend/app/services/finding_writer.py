import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredFinding
from app.models.finding import Finding, FindingState
from app.services.finding_category import categorize, extract_cve_id


def write_findings(
    db: Session,
    scan_run_id: uuid.UUID,
    findings: list[DiscoveredFinding],
) -> list[Finding]:
    if not findings:
        return []

    now = datetime.now(timezone.utc)
    rows = []
    for f in findings:
        tags: list[str] = f.detail.get("tags", []) if f.detail else []
        template_id: str = f.detail.get("template_id", "") if f.detail else ""
        # Connector-provided CVE ID wins; fall back to tag/template-id parsing
        cve_id = f.cve_id or extract_cve_id(tags, template_id)
        rows.append(Finding(
            id=uuid.uuid4(),
            discovered_at=now,
            scan_run_id=scan_run_id,
            asset_value=f.asset_value,
            finding_type=f.finding_type,
            source=f.source,
            severity=f.severity,
            title=f.title,
            description=f.description,
            detail=f.detail or {},
            state=FindingState.OPEN,
            category=categorize(tags),
            cve_id=cve_id,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            cvss_version=f.cvss_version,
            cwe=f.cwe,
        ))

    db.bulk_save_objects(rows)
    db.commit()
    return rows
