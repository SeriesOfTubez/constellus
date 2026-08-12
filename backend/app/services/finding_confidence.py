"""Finding confidence — how directly a finding was established (#66 D4).

`confirmed`  — directly observed/validated: an active probe that fired (nuclei),
               an authenticated scan (tenable), or our own observation (the
               exposed port itself).
`potential`  — inferred from version/CPE intelligence without confirming the
               specific weakness is present: Shodan's CPE→CVE firehose and our
               own native version→CVE matching. Backport-blind, so it can
               overstate (D6) — hence a separate, honestly-labelled tier.

Source-derived (no stored column needed for read-time use). Chunk C persists this
onto a `confidence` column + backfills; the read-time rollup (D) and the
verified/unverified toggle (E) consume the same map so they never diverge.
"""

# Everything not listed here is a direct observation → confirmed.
POTENTIAL_SOURCES: frozenset[str] = frozenset({"shodan", "version_match"})


def confidence_for(source: str | None) -> str:
    return "potential" if (source or "") in POTENTIAL_SOURCES else "confirmed"


def strongest(a: str, b: str) -> str:
    """max(confirmed > potential) — confirmed wins."""
    return "confirmed" if "confirmed" in (a, b) else "potential"
