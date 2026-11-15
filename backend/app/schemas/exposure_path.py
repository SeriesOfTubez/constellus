"""The exposure path of a finding (planning#347): the hops between the
internet and the flaw, as typed data.

One `ExposurePath` per place the finding was observed (`finding_endpoints`),
built at read time by `services/exposure_path.py`. Every hop says how the
record supports it:

* `observed`       — a source recorded this hop itself.
* `derived`        — worked out from other records (DNS), not seen by the
                     source that observed the finding. Always a list of
                     `candidates`; one name is never promoted to be the answer.
* `unknown`        — nothing on record singles it out. `reason` says why.
* `not_applicable` — the hop does not exist for this kind of finding.

`reason` is plain language about the record, set whenever the status is not
`observed`.
"""

import uuid
from datetime import datetime
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

HopStatus = Literal["observed", "derived", "unknown", "not_applicable"]

# `current`: the place was seen in the finding's latest observation.
# `not_reobserved`: the finding has been seen since, this place has not. It
#   says nothing about why (the scan may not have looked there).
# `not_recorded`: the source recorded no place for this finding at all.
PathObservation = Literal["current", "not_reobserved", "not_recorded"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HopCandidate(_Model):
    """An asset the DNS records link to a hop. The reader may read every
    candidate listed; assets they may not read are left out without a trace."""

    asset_id: uuid.UUID
    asset_type: Literal["dns_record", "ip_address"]
    value: str
    # The DNS record that makes the link (A, AAAA, CNAME); None when the edge
    # did not keep it.
    record_type: str | None = None
    # Record hops between the candidate and the address: 1 = the name's own
    # address record, 2 = one CNAME above it, and so on.
    distance: int
    # When the link was recorded. `resolves_to` edges carry no observer.
    link_first_seen_at: datetime | None = None
    link_last_seen_at: datetime | None = None


class _Hop(_Model):
    status: HopStatus
    reason: str | None = None
    # What recorded this hop. Empty when nothing did, or when the record keeps
    # no observer (DNS links).
    sources: list[str] = Field(default_factory=list)
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class InternetHop(_Hop):
    kind: Literal["internet"] = "internet"


class HostHop(_Hop):
    kind: Literal["host"] = "host"
    asset_id: uuid.UUID | None = None
    hostname: str | None = None
    candidates: list[HopCandidate] = Field(default_factory=list)
    # More readable candidates exist than are listed.
    candidates_truncated: bool = False


class AddressHop(_Hop):
    kind: Literal["address"] = "address"
    asset_id: uuid.UUID | None = None
    address: str | None = None
    candidates: list[HopCandidate] = Field(default_factory=list)
    candidates_truncated: bool = False


class PortHop(_Hop):
    kind: Literal["port"] = "port"
    port: int | None = None
    # None = the source did not record the protocol. Never read as tcp.
    protocol: Literal["tcp", "udp"] | None = None


class ServiceHop(_Hop):
    kind: Literal["service"] = "service"
    # The asset whose port inventory this came from.
    asset_id: uuid.UUID | None = None
    service: str | None = None
    version: str | None = None
    # The protocol the INVENTORY records for the port (it is keyed by port
    # number alone), which is a separate observation from the finding's.
    protocol: str | None = None


class FindingHop(_Hop):
    kind: Literal["finding"] = "finding"
    finding_id: uuid.UUID
    finding_type: str


ExposureHop = Annotated[
    Union[InternetHop, HostHop, AddressHop, PortHop, ServiceHop, FindingHop],
    Field(discriminator="kind"),
]


class ExposurePath(_Model):
    # The `finding_endpoints` row this path is for; None when the source
    # recorded no place (`observation == "not_recorded"`).
    endpoint_id: uuid.UUID | None = None
    observation: PathObservation
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    # internet, host, address, port, service, finding — always in that order.
    hops: list[ExposureHop]
