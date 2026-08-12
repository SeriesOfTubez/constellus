"""Scan aggressiveness — central knob for every active scanning tool.

Modelled on `nmap -T0..T5` and Tenable's Polite/Normal/Insane, but expressed
in user-meaningful tiers instead of raw rate knobs. The tier controls how
loud the *active* scanning phase is; passive sources (CT logs, Shodan API,
DNS connectors) are unaffected because they don't generate traffic against
the target.

Single source of truth for every tool's flag set. Each new active scanner
(naabu, nmap, httpx, tlsx, …) adds its slice to _PROFILES and exposes a
`{tool}_profile(tier)` accessor — connectors never hardcode rates.

Resolution order:
    per-run options["aggressiveness"]  →  app_settings["aggressiveness"]
                                       →  DEFAULT_TIER ("polite")
"""

from typing import Iterable

from sqlalchemy.orm import Session

from app.services import app_settings as settings_svc


TIERS: tuple[str, ...] = ("stealth", "polite", "standard", "aggressive")
DEFAULT_TIER = "polite"


# Per-tool flag dicts, keyed by tier. New tools register their slice here.
# Tools currently wired: nuclei, naabu, dnsrecon, bruteforce, banner_grab,
# httpx, tlsx.
# Reserved slots (no consumers yet): nmap.
#
# naabu tier intent — top_ports is one of {100, 1000, 65535}, matching naabu's
# -top-ports flag (which sources port rankings from nmap-services). Stealth is
# disabled entirely because a port scan is the loudest active probe in the
# pipeline; users who explicitly want a stealthy port scan can per-run-enable
# the connector.
_PROFILES: dict[str, dict[str, dict]] = {
    "stealth": {
        "nuclei": {
            "rate_limit": 10,
            "concurrency": 5,
            "severity_filter": ["critical", "high", "medium"],
            # default-login templates attempt known default credentials, which
            # can trip account lockouts even when "successful". Stealth tier
            # keeps them off; polite tier and above accept the lockout risk.
            "exclude_tags": ["intrusive", "fuzz", "dos", "default-login"],
        },
        "naabu": {
            "enabled": False,
            "top_ports": 100,
            "rate": 100,
            "concurrency": 5,
        },
        # Banner grab is gated on naabu's output, so the stealth tier
        # disables it implicitly via naabu. Keeping the explicit
        # `enabled: False` here makes the intent obvious from the profile.
        "banner_grab": {"enabled": False},
        # httpx/tlsx probe the ports banner_grab would have found — disabled
        # in lockstep for the same reason.
        "httpx": {"enabled": False},
        "tlsx": {"enabled": False},
        "dnsrecon": {"enabled": False},
        "bruteforce": {"enabled": False, "wordlist": "small"},
    },
    "polite": {
        "nuclei": {
            "rate_limit": 50,
            "concurrency": 25,
            "severity_filter": ["critical", "high", "medium", "low"],
            "exclude_tags": ["intrusive", "fuzz", "dos"],
        },
        "naabu": {
            "enabled": True,
            "top_ports": 100,
            "rate": 500,
            "concurrency": 10,
        },
        "banner_grab": {
            "enabled": True,
            "timeout": 4.0,
            "concurrency": 20,
        },
        "httpx": {
            "enabled": True,
            "timeout": 5.0,
            "concurrency": 20,
        },
        "tlsx": {
            "enabled": True,
            "timeout": 5.0,
            "concurrency": 20,
        },
        "dnsrecon": {"enabled": True},
        "bruteforce": {"enabled": True, "wordlist": "small"},
    },
    "standard": {
        "nuclei": {
            "rate_limit": 150,
            "concurrency": 50,
            "severity_filter": ["critical", "high", "medium", "low", "info"],
            "exclude_tags": ["fuzz", "dos"],
        },
        "naabu": {
            "enabled": True,
            "top_ports": 1000,
            "rate": 1000,
            "concurrency": 25,
        },
        "banner_grab": {
            "enabled": True,
            "timeout": 5.0,
            "concurrency": 50,
        },
        "httpx": {
            "enabled": True,
            "timeout": 7.0,
            "concurrency": 40,
        },
        "tlsx": {
            "enabled": True,
            "timeout": 7.0,
            "concurrency": 40,
        },
        "dnsrecon": {"enabled": True},
        "bruteforce": {"enabled": True, "wordlist": "medium"},
    },
    "aggressive": {
        "nuclei": {
            "rate_limit": 500,
            "concurrency": 100,
            "severity_filter": ["critical", "high", "medium", "low", "info"],
            # 'dos' templates are explicit denial-of-service tests; kept off
            # at every tier so an aggressive scan doesn't accidentally take
            # the target down. Users who want them can pass exclude_tags via
            # connector config.
            "exclude_tags": ["dos"],
        },
        "naabu": {
            "enabled": True,
            "top_ports": 65535,  # full TCP range
            "rate": 5000,
            "concurrency": 50,
        },
        "banner_grab": {
            "enabled": True,
            "timeout": 8.0,
            "concurrency": 100,
        },
        "httpx": {
            "enabled": True,
            "timeout": 10.0,
            "concurrency": 80,
        },
        "tlsx": {
            "enabled": True,
            "timeout": 10.0,
            "concurrency": 80,
        },
        "dnsrecon": {"enabled": True},
        "bruteforce": {"enabled": True, "wordlist": "large"},
    },
}


def normalize(tier: str | None) -> str:
    """Coerce a tier string to a known value, falling back to the default."""
    if tier in TIERS:
        return tier
    return DEFAULT_TIER


def resolve(db: Session, options: dict | None = None) -> str:
    """Determine the effective tier for a scan run.

    Per-run override (options["aggressiveness"]) wins over the global
    app_settings value. Unknown or missing values fall back to "polite".
    """
    if options:
        override = options.get("aggressiveness")
        if override in TIERS:
            return override
    return normalize(settings_svc.get(db, "aggressiveness"))


def effective_for_target(
    target_tier: str | None,
    template_or_run_tier: str | None,
    global_tier: str,
) -> str:
    """Most-specific-wins cascade: target > template/run > global.

    `target_tier` is the value on `targets.aggressiveness` (null = inherit).
    `template_or_run_tier` is the run/template options override (null = inherit).
    `global_tier` is the resolved global app_settings value (always non-null
    after normalize()).

    Any value not in TIERS is treated as null (defence against historical
    junk rows or future schema mismatch).
    """
    for candidate in (target_tier, template_or_run_tier, global_tier):
        if candidate in TIERS:
            return candidate
    return DEFAULT_TIER


def profile(tier: str) -> dict[str, dict]:
    """Return the full per-tool flag bundle for a tier. Used for logging
    and telemetry; tools should usually call their typed accessor below."""
    return _PROFILES[normalize(tier)]


def nuclei_profile(tier: str) -> dict:
    return dict(_PROFILES[normalize(tier)]["nuclei"])


def naabu_profile(tier: str) -> dict:
    return dict(_PROFILES[normalize(tier)]["naabu"])


def banner_grab_profile(tier: str) -> dict:
    return dict(_PROFILES[normalize(tier)]["banner_grab"])


def httpx_profile(tier: str) -> dict:
    return dict(_PROFILES[normalize(tier)]["httpx"])


def tlsx_profile(tier: str) -> dict:
    return dict(_PROFILES[normalize(tier)]["tlsx"])


def dnsrecon_profile(tier: str) -> dict:
    return dict(_PROFILES[normalize(tier)]["dnsrecon"])


def bruteforce_profile(tier: str) -> dict:
    return dict(_PROFILES[normalize(tier)]["bruteforce"])


def intersect_severities(user_filter: Iterable[str] | None, tier: str) -> list[str]:
    """Combine a user-configured severity filter with the tier's floor.

    Tier's severity_filter is the *ceiling* of what's allowed. If the user
    narrowed it further, honour that. If the user widened it past the tier
    (e.g. asked for 'info' under stealth), the tier's filter still caps it.
    Empty intersection falls back to the tier filter so a misconfigured
    user filter doesn't silently disable scanning.
    """
    tier_allowed = _PROFILES[normalize(tier)]["nuclei"]["severity_filter"]
    if not user_filter:
        return list(tier_allowed)
    intersected = [s for s in user_filter if s in tier_allowed]
    return intersected or list(tier_allowed)
