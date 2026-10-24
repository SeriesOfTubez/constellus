"""Vocabulary the org-discovery verifiers need (planning#277 S1b).

These are code constants for now; planning#285 promotes them to admin
settings. They exist to stop a shared PROVIDER from being read as a shared
OWNER: two unrelated domains on the same managed-DNS host, bulk mailer or
privacy-proxied WHOIS record say nothing about who owns them.

Matching is always on whole labels: the host equals the entry, or ends with
`.` + the entry. Case and a trailing dot are ignored.
"""

from __future__ import annotations

import re
import unicodedata

# ── managed-DNS providers: a nameserver here is never "vanity" ──────────────

PROVIDER_NS_SUFFIXES: tuple[str, ...] = (
    "ns.cloudflare.com",  # Cloudflare
    "cloudflare.com",
    "azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info",  # Azure DNS
    "googledomains.com", "google.com", "googlehosted.com",  # Google Cloud DNS / Google Domains
    "domaincontrol.com",  # GoDaddy
    "registrar-servers.com",  # Namecheap
    "nsone.net",  # NS1
    "dnsmadeeasy.com",  # DNS Made Easy
    "ultradns.com", "ultradns.net", "ultradns.org", "ultradns.biz", "ultradns.info",  # UltraDNS
    "akam.net", "akamai.net", "akamaiedge.net",  # Akamai
    "dynect.net",  # Dyn
    "digitalocean.com",  # DigitalOcean
    "linode.com",  # Linode
    "hetzner.com", "hetzner.de", "your-server.de",  # Hetzner
    "ovh.net", "ovh.com", "anycast.me",  # OVH
    "gandi.net",  # Gandi
    "dnsimple.com",  # DNSimple
    "vercel-dns.com",  # Vercel
    "wixdns.net",  # Wix
    "squarespacedns.com",  # Squarespace
    "worldnic.com",  # Network Solutions
    "name.com",  # Name.com
    "dnspod.net",  # DNSPod
    "he.net",  # Hurricane Electric
    "afraid.org",  # FreeDNS
    "porkbun.com",  # Porkbun
    "dreamhost.com",  # DreamHost
    "bluehost.com",  # Bluehost
    "hostgator.com",  # HostGator
    "1and1.com", "ui-dns.com", "ui-dns.de", "ui-dns.biz", "ui-dns.org",  # IONOS
    "easydns.com", "easydns.net", "easydns.org",  # easyDNS
    "constellix.com",  # Constellix
    "rackspace.com",  # Rackspace
    "netlify.com",  # Netlify
    "fastly.net",  # Fastly
    "alidns.com", "hichina.com",  # Alibaba Cloud DNS
    "cloudns.net",  # ClouDNS
    "bunny.net",  # Bunny DNS
)

# AWS Route 53: ns-123.awsdns-45.com / .net / .org / .co.uk. The shard numbers
# differ per customer, so this needs a pattern, not a suffix.
_PROVIDER_NS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^ns-\d+\.awsdns-\d+\.(?:com|net|org|co\.uk)$"),
)


def _norm_host(host: str | None) -> str:
    return (host or "").strip().rstrip(".").lower()


def _under(host: str, suffixes: tuple[str, ...]) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def is_provider_ns(host: str) -> bool:
    h = _norm_host(host)
    if not h:
        return False
    return _under(h, PROVIDER_NS_SUFFIXES) or any(p.match(h) for p in _PROVIDER_NS_PATTERNS)


# ── bulk SPF senders: a shared include here is a shared vendor, not an owner ─

SPF_BULK_PROVIDER_INCLUDES: tuple[str, ...] = (
    "_spf.google.com", "spf.google.com", "_netblocks.google.com",  # Google Workspace
    "spf.protection.outlook.com", "protection.outlook.com",  # Microsoft 365
    "sendgrid.net",  # SendGrid
    "mailgun.org",  # Mailgun
    "amazonses.com",  # Amazon SES
    "servers.mcsv.net", "spf.mandrillapp.com", "mandrillapp.com",  # Mailchimp / Mandrill
    "_spf.salesforce.com", "salesforce.com",  # Salesforce
    "mktomail.com",  # Marketo
    "mail.zendesk.com", "zendesk.com",  # Zendesk
    "spf.mtasv.net", "mtasv.net",  # Postmark
    "sparkpostmail.com",  # SparkPost
    "hubspot.com", "hubspotemail.net", "hs-email.net",  # HubSpot
    "pphosted.com", "ppe-hosted.com",  # Proofpoint
    "mimecast.com", "mimecast-offshore.com",  # Mimecast
    "zoho.com", "zoho.eu", "zohomail.com",  # Zoho
    "_spf.atlassian.net", "atlassian.net", "atlassian.com",  # Atlassian
    "email.freshdesk.com", "freshdesk.com", "freshworks.com",  # Freshdesk
    "intercom.io", "intercomrades.com",  # Intercom
    "klaviyomail.com", "klaviyo.com",  # Klaviyo
    "spf.constantcontact.com", "constantcontact.com",  # Constant Contact
    "spf.brevo.com", "spf.sendinblue.com", "sendinblue.com", "brevo.com",  # Brevo / Sendinblue
    "spf.messagelabs.com", "messagelabs.com",  # Broadcom / Symantec
    "_spf.mlsend.com", "mailerlite.com",  # MailerLite
    "mailjet.com", "spf.mailjet.com",  # Mailjet
    "spf.elasticemail.com", "elasticemail.com",  # Elastic Email
    "campaignmonitor.com", "createsend.com",  # Campaign Monitor
    "helpscoutemail.com",  # Help Scout
    "spf.messagingengine.com", "messagingengine.com",  # Fastmail
    "mcdlv.net", "rsgsv.net",  # Mailchimp delivery
    "secureserver.net",  # GoDaddy mail
    "spf.emailsrvr.com", "emailsrvr.com",  # Rackspace Email
    "mailchimp.com",
    "_spf.mailhostbox.com", "mailhostbox.com",
    "sendpulse.com",  # SendPulse
    "smtp.com", "spf.smtp.com",
)


def is_bulk_spf_include(domain: str) -> bool:
    d = _norm_host(domain)
    return bool(d) and _under(d, SPF_BULK_PROVIDER_INCLUDES)


# ── registrant organizations ────────────────────────────────────────────────

# Lower-case SUBSTRINGS (not regexes) that mark a redacted or privacy-proxy
# WHOIS organization. A match means the field says nothing about the owner.
REGISTRANT_PRIVACY_PATTERNS: tuple[str, ...] = (
    "redacted", "privacy", "proxy", "withheld", "not disclosed", "data protected",
    "whoisguard", "identity protect", "private registration", "registration private",
    "gdpr", "statutory masking", "on behalf of", "whois agent", "domain protection",
    "perfect privacy", "contact privacy", "domains by proxy",
)

_PLACEHOLDERS = frozenset({"n/a", "na", "none", "null", "-", "not available", "unknown"})


def fold_org(raw: str | None) -> str | None:
    """Comparable form of a WHOIS organization, or None when it cannot carry
    evidence (empty, placeholder, too short, redacted or privacy-proxied).

    Legal suffixes are KEPT: "Example Holdings, Inc." folds to
    "example holdings inc", which is not "example holdings llc". Stripping
    suffixes once dropped a real subsidiary."""
    if raw is None:
        return None
    lowered = unicodedata.normalize("NFKC", raw).lower().strip()
    if not lowered or lowered in _PLACEHOLDERS:
        return None
    folded = "".join(ch if ch.isalnum() else " " for ch in lowered)
    folded = " ".join(folded.split())
    if len(folded) < 3 or folded in _PLACEHOLDERS:
        return None
    if any(p in lowered or p in folded for p in REGISTRANT_PRIVACY_PATTERNS):
        return None
    return folded
