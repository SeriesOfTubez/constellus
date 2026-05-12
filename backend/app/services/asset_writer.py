import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.connectors.base import DiscoveredAsset
from app.models.asset import Asset


def write_assets(
    db: Session,
    scan_run_id: uuid.UUID,
    assets: list[DiscoveredAsset],
) -> list[Asset]:
    """
    Persist a batch of discovered assets for a scan run.
    Each call inserts new rows — assets are time-series data (one record per scan).
    """
    if not assets:
        return []

    now = datetime.now(timezone.utc)
    rows = [
        Asset(
            id=uuid.uuid4(),
            discovered_at=now,
            scan_run_id=scan_run_id,
            asset_type=a.asset_type,
            value=a.value,
            parent_value=a.parent_value,
            asset_metadata=a.asset_metadata or {},
        )
        for a in assets
    ]

    db.bulk_save_objects(rows)
    db.commit()
    return rows
