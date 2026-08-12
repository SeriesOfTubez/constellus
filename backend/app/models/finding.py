"""Finding-related enumerations.

Previously this module also defined the `Finding` SQLAlchemy class for the
legacy `findings` hypertable — that table was dropped in migration 0025
once all readers moved to findings_canonical. The enums remain because
many connectors and the API still reference them as the source of truth
for severity / source / state strings.
"""

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingSource(str, Enum):
    NUCLEI = "nuclei"
    CLOUDFLARE = "cloudflare"
    FORTIMANAGER = "fortimanager"
    TENABLE = "tenable"
    MANUAL = "manual"


class FindingState(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
