import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Integer, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# verification values that exclude a finding from the main list, dashboard/
# score aggregates, and notifications by default — shared low-level constant
# so api/findings.py, api/assets.py, and services/notification_dispatcher.py
# all consolidate onto one definition (a future 5th excluded value is one
# edit, not several). See the `verification` column comment below.
EXCLUDED_VERIFICATIONS = ("rejected_shared_infra", "ownership_unverifiable")


class FindingCanonical(Base):
    """Durable identity for a finding. One row per logical finding —
    (asset, finding_type, source, fingerprint). Subsequent observations from
    later scans update last_seen_at; resolution is set by recheck logic.

    fingerprint is a source-specific uniqueness key:
      - Nuclei findings: template_id
      - Shodan CVE findings: cve_id
      - Shodan tag findings: tag name
      - WHOIS expiry findings: f"expiry:{domain}"
    """

    __tablename__ = "findings_canonical"
    __table_args__ = (
        UniqueConstraint(
            "asset_canonical_id", "finding_type", "source", "fingerprint",
            name="uq_findings_canonical_fingerprint",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_canonical_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("assets_canonical.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(Text, nullable=False, default="open", server_default=text("'open'"), index=True)
    category: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Who produced cvss_score — 'nvd' | 'cna' | a connector id. NULL = unknown
    # provenance, never a default. Since NVD stopped routinely re-scoring CVEs
    # a CNA had already scored (April 2026), cvss_version alone can't answer
    # this. Same trust-signal role ssvc_source plays for SSVC (migration 0038).
    cvss_source: Mapped[str | None] = mapped_column(Text, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    cwe: Mapped[str | None] = mapped_column(Text, nullable=True)
    # ── Constellus Risk Score (migration 0031) ──────────────────────────────
    # Signal columns (populated post-scan by vulncheck_enrichment / vulnx_enrichment);
    # all nullable so scoring degrades gracefully without VulnCheck/PDCP keys.
    has_exploit: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    exploit_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ransomware_use: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    canary_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_template: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    is_poc: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    vulncheck_kev: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    epss_score_previous: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Computed columns (risk_scorer): risk_band is derivable from risk_score but
    # stored for query/sort convenience. building_velocity is the orthogonal momentum flag.
    building_velocity: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    risk_band: Mapped[str | None] = mapped_column(Text, nullable=True)
    # v1.1 context (does not modulate score): consequence class + VulnCheck XDB exploit-type tags.
    impact_class: Mapped[str | None] = mapped_column(Text, nullable=True)
    exploit_types: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    # ── SSVC (CISA Vulnrichment, migration 0034) ────────────────────────────
    # Stakeholder-Specific Vulnerability Categorization decision points, ingested
    # per-CVE from the CVE.org CISA-ADP block (ssvc_enrichment). Orthogonal Risk-Score
    # signals (Automatable → capability; Technical Impact → impact term) and the basis
    # for a BOD-26-04 remediation-deadline lens. ssvc_source marks vulnrichment vs a
    # derived CVSS-vector fallback; all nullable (degrade to derived/none when CISA
    # hasn't scored the CVE). ssvc_scored_at = CISA's SSVC timestamp (provenance).
    ssvc_exploitation: Mapped[str | None] = mapped_column(Text, nullable=True)        # none | poc | active
    ssvc_automatable: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ssvc_technical_impact: Mapped[str | None] = mapped_column(Text, nullable=True)    # total | partial
    ssvc_source: Mapped[str | None] = mapped_column(Text, nullable=True)              # vulnrichment | derived
    ssvc_scored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # ── Shared-infra verification (migrations 0036/0037, planning#77/#103/#108) ─
    # Orthogonal to `state` (analyst triage): whether the automated verifier
    # (services/shared_infra_verifier.py) could confirm this host-level/
    # passive finding is actually attributable to an asset we own, via the
    # domain-affinity primitive (planning#102). NULL = never checked (most
    # findings — this is scoped to host-level/passive sources).
    # rejected_shared_infra = direct disproof (unanimous not_affine).
    # ownership_unverifiable = inferential — positive corroboration the
    # origin serves someone else, without unanimous disproof (epic#81 Phase
    # D, planning#108) — same exclusion treatment as rejected, distinct
    # epistemic claim.
    verification: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)  # unverified | confirmed_ours | rejected_shared_infra | ownership_unverifiable
    verification_evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    suppressed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default=text("'{}'"))
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, default=list, server_default=text("'[]'"))
