"""Asset type enumeration.

Used by the connector + canonical layer to classify discovered assets.
Previously this module also defined the `Asset` SQLAlchemy class for the
legacy `assets` hypertable — that table was dropped in migration 0025
once all readers moved to assets_canonical. The enum remains because
many connectors and writers still reference it as the source of truth
for asset-type strings.
"""

from enum import Enum


class AssetType(str, Enum):
    DNS_RECORD = "dns_record"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"
    CLOUD_RESOURCE = "cloud_resource"
    INTERNAL_HOST = "internal_host"
