"""What each signal type is worth (planning#277 S1a).

Propose bar: >= 1 STRONG signal, OR Supporting signals from >= 2 DISTINCT
families. CONTEXT never counts toward the bar. One Supporting family alone
is a LEAD: stored, not shown in the default queue.

`built` says whether a generator or verifier for the type exists in the
code base today. A type that is not built is still in the table (and in
migration 0083's CHECK) so the SQL strength calculation and the tests can
exercise it before its generator lands; the invariant test refuses a
`record_signal(signal_type=...)` call site for a type that is not built.

`SIGNALS.keys()` must equal migration 0083's `SIGNAL_TYPES`
(`test_org_discovery_schema.py`).
"""

from __future__ import annotations

from dataclasses import dataclass

STRONG, SUPPORTING, CONTEXT = "strong", "supporting", "context"
TIERS = (STRONG, SUPPORTING, CONTEXT)


@dataclass(frozen=True)
class SignalSpec:
    tier: str
    family: str
    built: bool  # has a generator/verifier in this slice
    description: str


SIGNALS: dict[str, SignalSpec] = {
    "admin_seed": SignalSpec(STRONG, "seed", True, "An admin named this domain when adding the organization."),
    "person_evidence": SignalSpec(STRONG, "person", True, "A person added the domain with a sourced excerpt."),
    "filer_10k_website": SignalSpec(
        STRONG, "filings", True, "A confirmed filer's own 10-K names it as its website."
    ),
    "connector_zone": SignalSpec(
        STRONG, "connector", True, "An active zone in a connector account we hold (credentialed proof of control)."
    ),
    "registrant_email_claimed": SignalSpec(
        STRONG, "registration", False, "Registrant email on a claimed domain (deferred: domain RDAP follow-up)."
    ),
    "redirect_to_claimed": SignalSpec(
        STRONG, "capture", False, "The domain redirects into a claimed domain (planning#280)."
    ),
    "shared_vanity_ns": SignalSpec(
        SUPPORTING, "dns_hosting", True, "Shares a vanity nameserver with a claimed domain."
    ),
    "mx_into_claimed": SignalSpec(SUPPORTING, "mail", True, "Its mail is routed through a claimed domain's MX."),
    "spf_sender_shared": SignalSpec(SUPPORTING, "mail", True, "Its SPF names a sender shared with a claimed domain."),
    "dmarc_report_to_claimed": SignalSpec(
        SUPPORTING, "mail", False, "Its DMARC reports go to a claimed domain."
    ),
    "dmarc_exact_vendor": SignalSpec(
        SUPPORTING, "mail", False, "Its DMARC reporting address matches a claimed domain's at a known vendor."
    ),
    "registrant_org_match": SignalSpec(
        SUPPORTING, "registration", True, "Registrant organization matches a claimed domain's."
    ),
    "research_quote": SignalSpec(
        SUPPORTING, "research", False, "A researched source quotes the domain as the organization's."
    ),
    "reverse_ip_dedicated": SignalSpec(
        SUPPORTING, "hosting", True, "Shares a dedicated IP with a claimed domain."
    ),
    "dmarc_exact_generic": SignalSpec(
        CONTEXT, "mail", False, "Its DMARC reporting address matches a claimed domain's at a generic provider."
    ),
    "name_similarity": SignalSpec(CONTEXT, "name", False, "The domain resembles a claimed domain's name."),
    "ai_mention": SignalSpec(CONTEXT, "research", False, "An AI read mentioned the domain."),
}


def tier_of(signal_type: str) -> str:
    return SIGNALS[signal_type].tier


def family_of(signal_type: str) -> str:
    return SIGNALS[signal_type].family
