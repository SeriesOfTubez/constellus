"""The dates on a finding's exposure timeline (planning#360), as typed data.

Built at read time by `services/finding_timeline.py` from the finding, its CVE
record and the attribution the detail route already builds. Served on
`GET /api/findings/{id}` as `timeline`; Trace question 3 (planning#362) draws it.

One event per date we have. A date we do not have is left out, never guessed.
The list is sorted by `date`, then `at`: the order of the kinds is not fixed (a
CVE can be listed as exploited before it is published).

`date` is a calendar day (UTC) and `precision` says how much of it is known: a
month-precision date is the first of its month. `at` is the full timestamp when
the record holds one. `source` names where the date came from and is None for
dates that are our own record (first seen, claimed, Confirmed ours).
"""

import uuid
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

TimelineKind = Literal[
    "cve_published",
    "listed_exploited_cisa",
    "listed_exploited_vulncheck",
    "acquired",
    "claimed",
    "first_seen",
    # The first time the ownership verdict became confirmed_ours. The label is
    # "Confirmed ours", never bare "confirmed".
    "ownership_confirmed",
    "due",
]

Precision = Literal["day", "month", "year"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TimelineDate(_Model):
    """Another source's date for the same acquisition, where it differs."""

    date: date
    precision: Precision
    source: str | None = None


class TimelineEvent(_Model):
    kind: TimelineKind
    date: date
    precision: Precision
    at: datetime | None = None
    source: str | None = None
    # acquired: the entity that was acquired, and the hop above it (the acquirer).
    entity_id: uuid.UUID | None = None
    entity_name: str | None = None
    acquirer_id: uuid.UUID | None = None
    # claimed: the scope that was claimed.
    target_id: uuid.UUID | None = None
    target_value: str | None = None
    # acquired: the other sources' dates that differ from `date`/`precision`.
    other_dates: list[TimelineDate] = Field(default_factory=list)
