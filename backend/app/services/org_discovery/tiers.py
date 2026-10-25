"""What each signal type is worth (planning#277 S1a).

Propose bar: >= 1 STRONG signal, OR Supporting signals from >= 2 DISTINCT
families. CONTEXT never counts toward the bar. One Supporting family alone
is a LEAD: stored, not shown in the default queue.

`built` says whether a generator or verifier for the type exists in the
code base today. A type that is not built is still in the table (and in
migrations 0083 / 0087's CHECK) so the SQL strength calculation and the tests can
exercise it before its generator lands; the invariant test refuses a
`record_signal(signal_type=...)` call site for a type that is not built.

`SIGNALS.keys()` must equal migration 0087's `SIGNAL_TYPES`
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
    label: str = ""  # short human name for the UI (every entry sets one; a test enforces it)


SIGNALS: dict[str, SignalSpec] = {
    "admin_seed": SignalSpec(STRONG, "seed", True, "An admin named this domain when adding the organization.", label="Admin seed"),
    "person_evidence": SignalSpec(STRONG, "person", True, "A person added the domain with a sourced excerpt.", label="Person evidence"),
    "filer_10k_website": SignalSpec(
        STRONG, "filings", True, "A confirmed filer's own 10-K names it as its website.", label="Filer 10-K website"),
    "connector_zone": SignalSpec(
        STRONG, "connector", True, "An active zone in a connector account we hold (credentialed proof of control).", label="Connector zone"),
    "registrant_email_claimed": SignalSpec(
        STRONG, "registration", False, "Registrant email on a claimed domain (deferred: domain RDAP follow-up).", label="Registrant email on claimed"),
    "redirect_to_claimed": SignalSpec(
        STRONG, "capture", False, "The domain redirects into a claimed domain (planning#280).", label="Redirects to claimed"),
    "shared_vanity_ns": SignalSpec(
        SUPPORTING, "dns_hosting", True, "Shares a vanity nameserver with a claimed domain.", label="Shared vanity nameserver"),
    "mx_into_claimed": SignalSpec(SUPPORTING, "mail", True, "Its mail is routed through a claimed domain's MX.", label="MX into claimed"),
    "spf_sender_shared": SignalSpec(SUPPORTING, "mail", True, "Its SPF names a sender shared with a claimed domain.", label="Shared SPF sender"),
    "dmarc_report_to_claimed": SignalSpec(
        SUPPORTING, "mail", True, "Its DMARC reports go to a claimed domain.", label="DMARC reports to claimed"),
    "dmarc_exact_vendor": SignalSpec(
        SUPPORTING, "mail", True, "Its DMARC reporting address matches a claimed domain's at a known vendor.", label="DMARC vendor address match"),
    "registrant_org_match": SignalSpec(
        SUPPORTING, "registration", True, "Registrant organization matches a claimed domain's.", label="Registrant organization match"),
    "research_quote": SignalSpec(
        SUPPORTING, "research", False, "A researched source quotes the domain as the organization's.", label="Research quote"),
    "reverse_ip_dedicated": SignalSpec(
        SUPPORTING, "hosting", True, "Shares a dedicated IP with a claimed domain.", label="Dedicated IP shared"),
    "dmarc_exact_generic": SignalSpec(
        CONTEXT, "mail", True, "Its DMARC reporting address matches a claimed domain's, but the address is shared or not at a known vendor.", label="DMARC address match (generic)"),
    "name_similarity": SignalSpec(CONTEXT, "name", False, "The domain resembles a claimed domain's name.", label="Name similarity"),
    "ai_mention": SignalSpec(CONTEXT, "research", False, "An AI read mentioned the domain.", label="AI mention"),
    "rir_contact_email_claimed": SignalSpec(
        STRONG, "rir", True,
        "A validated RIR organization, person or role contact email is at a claimed domain, on a handle that holds RIR-issued resources.",
        label="RIR contact email on claimed"),
    "rir_contact_email_unvalidated": SignalSpec(
        SUPPORTING, "rir_unvalidated", True,
        "An RIR contact email is at a claimed domain, on a resource-holding handle, but the contact has not passed the RIR's validation.",
        label="RIR contact email (unvalidated)"),
    "rir_allocation_dedicated_ip": SignalSpec(
        SUPPORTING, "rir_ip", False,
        "The handle holds an allocation containing a claimed IP address classified as dedicated.",
        label="Allocation holds a dedicated IP"),
    "peeringdb_website_claimed": SignalSpec(
        SUPPORTING, "peeringdb", False, "The PeeringDB organization's website is a claimed domain.",
        label="PeeringDB website is claimed"),
    "rir_reassigned_elsewhere": SignalSpec(
        CONTEXT, "rir", True,
        "The prefix lies inside a matched handle's allocation but is reassigned to another handle.",
        label="Reassigned to another handle"),
    "bgp_announced_not_allocated": SignalSpec(
        CONTEXT, "bgp", False, "A matched ASN announces the prefix, but it is allocated to another handle.",
        label="Announced, not allocated"),
}


def tier_of(signal_type: str) -> str:
    return SIGNALS[signal_type].tier


def family_of(signal_type: str) -> str:
    return SIGNALS[signal_type].family
