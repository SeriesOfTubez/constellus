import { type ReactNode } from "react"
import { Link } from "react-router-dom"
import {
  Tag, SlidersHorizontal,
  Crosshair, Radar, Telescope, GitCompareArrows, CalendarClock, ShieldCheck, ScanSearch,
  type LucideIcon,
} from "lucide-react"
import { type Finding } from "@/lib/api"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { OverflowCell } from "@/components/ui/overflow-cell"

// CVE findings with no NVD-curated name fall back to the bare CVE id as their
// title (see vulncheck_enrichment.py) — show that as "-" rather than repeating
// the CVE id in both the title and the CVE column.
export function findingTitle(f: Finding): string {
  return f.cve_id && f.title === f.cve_id ? "-" : f.title
}

/** Pulls the exposure severity-override off a finding's detail, or null when
 *  there isn't one (every non-exposure finding, and default-severity exposures).
 *  Shared by the pill and the narrative callout so they can't disagree. */
export function exposureOverride(
  finding: Finding,
): { kind: "tag" | "banner" | "unknown"; tag: string | null; label: string } | null {
  const d = finding.detail
  if (!d) return null
  const label = typeof d.severity_override === "string" ? d.severity_override : null
  if (!label) return null
  // `override_kind` is absent on findings written before it existed — don't guess
  // the source (it could be tag OR banner); render neutral wording until re-scan.
  const kind = d.override_kind === "tag" ? "tag" : d.override_kind === "banner" ? "banner" : "unknown"
  const tag = typeof d.override_tag === "string" ? d.override_tag : null
  return { kind, tag, label }
}

/** Exposure-finding override pill — surfaces WHY an exposure was re-rated
 *  (a user tag vs a detected-product banner), so the title stays clean. Returns
 *  null for findings with no override. */
export function ExposureOverrideBadge({ finding }: { finding: Finding }) {
  const o = exposureOverride(finding)
  if (!o) return null

  const isTag = o.kind === "tag"
  const Icon = isTag ? Tag : SlidersHorizontal
  const text = isTag ? "Downgraded by tag" : "Severity adjusted"
  const tip = isTag && o.tag ? `${o.tag} — ${o.label}` : o.label
  const cls = isTag
    ? "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"
    : "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-400"

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium cursor-help ${cls}`}>
          <Icon className="h-2.5 w-2.5" />{text}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">{tip}</TooltipContent>
    </Tooltip>
  )
}

// Exposure classification (why the service is flagged). `infrastructure` is the
// "should be internal — exposure is usually accidental" bucket the engine sets
// in detail.exposure_class.
const EXPOSURE_CLASS_LABEL: Record<string, string> = {
  remote_access:  "Remote Access",
  data_store:     "Data Store",
  infrastructure: "Infrastructure",
  orchestration:  "Orchestration",
}
const EXPOSURE_CLASS_COLOR: Record<string, string> = {
  remote_access:  "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
  data_store:     "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  infrastructure: "border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400",
  orchestration:  "border-cyan-500/40 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400",
}
const EXPOSURE_CLASS_TIP: Record<string, string> = {
  remote_access:  "Interactive/admin access service exposed — direct compromise vector.",
  data_store:     "Database or cache exposed — data exposure risk.",
  infrastructure: "Infrastructure service rarely meant to be public — exposure is usually accidental, and a recon/amplification vector.",
  orchestration:  "Container/cluster control plane exposed — control-plane takeover risk.",
}

/** Exposure-class pill (only on exposure findings carrying detail.exposure_class).
 *  Lets you spot at a glance e.g. infra services that shouldn't face the internet. */
export function ExposureClassBadge({ finding }: { finding: Finding }) {
  const cls = (finding.detail as Record<string, unknown> | null)?.exposure_class
  if (typeof cls !== "string" || !EXPOSURE_CLASS_LABEL[cls]) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium cursor-help ${EXPOSURE_CLASS_COLOR[cls]}`}>
          {EXPOSURE_CLASS_LABEL[cls]}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">{EXPOSURE_CLASS_TIP[cls]}</TooltipContent>
    </Tooltip>
  )
}

// Dangling-DNS detection layer (epic#81 Phase B, planning#105) — which
// signal produced the finding, set in detail.layer by dangling_dns_analyzer.py.
// Distinct from severity: this is "what kind of evidence," severity is
// "how urgent."
const DETECTION_LAYER_LABEL: Record<string, string> = {
  fingerprint:                  "Fingerprint match",
  affinity_not_affine:          "No ownership signal",
  affinity_unreachable:         "Origin unreachable",
  affinity_corroborated_alive:  "Origin serves others",
}
const DETECTION_LAYER_COLOR: Record<string, string> = {
  fingerprint:                  "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
  affinity_not_affine:          "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
  affinity_unreachable:         "border-slate-500/40 bg-slate-500/10 text-slate-600 dark:text-slate-400",
  affinity_corroborated_alive:  "border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400",
}
const DETECTION_LAYER_TIP: Record<string, string> = {
  fingerprint:                  "A nuclei takeover-signature match on the CNAME target — directly claimable now.",
  affinity_not_affine:          "The record's origin is reachable but shows no evidence of serving content for this hostname (shared-hosting origin, no ownership signal).",
  affinity_unreachable:         "The record's origin did not respond on any probed port — may be masked by an edge/redirect, or simply retired.",
  affinity_corroborated_alive:  "The origin didn't answer for this hostname, but Constellus confirmed it actively serves another hostname — live shared hosting that has moved on, not a dead origin.",
}

/** Dangling-DNS detection-layer pill (only on findings carrying detail.layer,
 *  i.e. dangling_dns findings). Surfaces which signal fired as the severity
 *  rationale — a fingerprint hit reads very differently from an affinity
 *  abstention even at the same glance. */
export function DetectionLayerBadge({ finding }: { finding: Finding }) {
  const layer = (finding.detail as Record<string, unknown> | null)?.layer
  if (typeof layer !== "string" || !DETECTION_LAYER_LABEL[layer]) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium cursor-help ${DETECTION_LAYER_COLOR[layer]}`}>
          {DETECTION_LAYER_LABEL[layer]}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">{DETECTION_LAYER_TIP[layer]}</TooltipContent>
    </Tooltip>
  )
}

// Shared-infra verification (migrations 0036/0037, epic#81 Phases A/D) — only
// badged for the two states that exclude a finding from the main list/score;
// `confirmed_ours`/`unverified` are the normal default states, not worth a
// pill. Deliberately a single neutral slate style for both — this is an
// attribution-CONFIDENCE signal, not a severity, so it must never borrow the
// locked severity palette (see Design Decisions — severity palette lock).
const VERIFICATION_LABEL: Record<string, string> = {
  rejected_shared_infra:  "Rejected — shared infra",
  ownership_unverifiable: "Ownership unverifiable",
}
const VERIFICATION_TIP: Record<string, string> = {
  rejected_shared_infra:  "Every owned hostname on this asset's IP showed no affinity with the origin — directly disproven as ours. Excluded from the main list and Risk Score.",
  ownership_unverifiable: "The origin shows positive evidence of serving a different, unrelated tenant (shared hosting) — not directly disproven, but excluded from the main list and Risk Score pending review.",
}

/** Shared-infra verification pill — shown wherever a rejected/unverifiable
 *  finding is reached outside its dedicated saved view (search, asset
 *  drill-down), so the exclusion is never a silent surprise. */
export function VerificationBadge({ finding }: { finding: Finding }) {
  const v = finding.verification
  if (!v || !VERIFICATION_LABEL[v]) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium cursor-help border-slate-500/40 bg-slate-500/10 text-slate-600 dark:text-slate-400">
          {VERIFICATION_LABEL[v]}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">{VERIFICATION_TIP[v]}</TooltipContent>
    </Tooltip>
  )
}

/** Inline "why" for a rejected/unverifiable finding — No Data Wasted applied
 *  to the verifier's own evidence: don't just show a badge, show the actual
 *  signals (hosting classification, corroborating hostname + cert/HTTP
 *  evidence, tech-absence) that produced the verdict. */
export function VerificationEvidencePanel({ finding }: { finding: Finding }) {
  const ev = finding.verification_evidence
  const v = finding.verification
  if (!ev || !v || !VERIFICATION_LABEL[v]) return null

  const lines: string[] = []
  if (ev.hosting_class?.company_name) {
    lines.push(
      `Origin IP ${ev.ip ?? "?"} belongs to ${ev.hosting_class.company_name}` +
      `${ev.hosting_class.asn ? ` (AS${ev.hosting_class.asn})` : ""} — a hosting/datacenter network.`
    )
  }
  if (ev.corroboration?.corroborating_hostname) {
    const kind = ev.corroboration.evidence === "tls_san_match" ? "a matching TLS certificate" : "a live HTTP response"
    lines.push(`Origin serves ${ev.corroboration.corroborating_hostname} (${kind}) — a different, unrelated hostname.`)
  }
  if (ev.tech_absence) {
    const verb = ev.tech_absence.expected_tech_absent ? "not detected" : "detected"
    const ports = ev.tech_absence.checked_ports.length ? ev.tech_absence.checked_ports.join(", ") : "n/a"
    lines.push(`CVE tied to ${ev.tech_absence.cve_product} — ${ev.tech_absence.cve_product} was ${verb} on this asset's own vhost (ports ${ports}).`)
  }
  if (ev.reason) lines.push(ev.reason)
  if (lines.length === 0) return null

  return (
    <div className="rounded border border-border bg-muted/30 p-3 text-sm space-y-1.5">
      <div className="font-medium text-muted-foreground">Why this was excluded</div>
      {lines.map((line, i) => <div key={i} className="text-muted-foreground">{line}</div>)}
    </div>
  )
}

export const SEVERITY_COLOR: Record<Finding["severity"], string> = {
  critical: "bg-red-500/15 text-red-500 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-500 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-500 border-blue-500/30",
  info:     "bg-muted text-muted-foreground border-border",
}

export const SEVERITY_ORDER: Finding["severity"][] = ["critical", "high", "medium", "low", "info"]

export function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold capitalize ${SEVERITY_COLOR[severity]}`}>
      {severity}
    </span>
  )
}

// ── Constellus Risk Score verdict (locked vocabulary) ──────────────────────────
type RiskBand = NonNullable<Finding["risk_band"]>

// "Imminent Threat" is deliberately outcome-neutral — the verdict communicates
// urgency, while the impact-class tag (ImpactClassBadge) carries the "what's at
// stake" so a DoS-only finding doesn't read as a breach it isn't.
export const RISK_BAND_LABEL: Record<RiskBand, string> = {
  imminent_compromise: "Imminent Threat",
  high:                "High Risk",
  elevated:            "Elevated Risk",
  low:                 "Low Risk",
  secure:              "Secure Posture",
}

// Verdict colours map to the locked severity palette (meaning, not decoration).
export const RISK_BAND_COLOR: Record<RiskBand, string> = {
  imminent_compromise: "bg-red-500/15 text-red-500 border-red-500/30",
  high:                "bg-orange-500/15 text-orange-500 border-orange-500/30",
  elevated:            "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30",
  low:                 "bg-blue-500/15 text-blue-500 border-blue-500/30",
  secure:              "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
}

// Short labels for compact contexts (filter pills, chips).
export const RISK_BAND_SHORT: Record<RiskBand, string> = {
  imminent_compromise: "Imminent",
  high:                "High",
  elevated:            "Elevated",
  low:                 "Low",
  secure:              "Secure",
}

// Findings are never "secure" — that's an asset/org-only state. Worst→best.
export const RISK_BAND_ORDER: RiskBand[] = ["imminent_compromise", "high", "elevated", "low"]

// Raw severity → band, a fallback for findings not yet risk-scored. Mirrors
// the backend risk_scorer _SEVERITY_TO_BAND mapping.
const SEVERITY_TO_BAND: Record<Finding["severity"], RiskBand> = {
  critical: "imminent_compromise",
  high:     "high",
  medium:   "elevated",
  low:      "low",
  info:     "low",
}

/** The finding's verdict band, falling back to its severity-derived band when
 *  the Risk Score hasn't been computed yet. */
export function effectiveBand(f: Finding): RiskBand {
  return f.risk_band ?? SEVERITY_TO_BAND[f.severity]
}

/** The Risk Score verdict chip. Leads with the verdict label; shows the 0–100
 *  score when present. Falls back to the raw severity badge until scored. */
export function RiskBandBadge({ band, score }: { band: Finding["risk_band"]; score: number | null }) {
  if (!band) return null
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-semibold ${RISK_BAND_COLOR[band]}`}>
      {RISK_BAND_LABEL[band]}
      {score != null && <span className="font-mono opacity-70">{score}</span>}
    </span>
  )
}

/** A finding's primary risk indicator: the Risk Score band when scored, else raw
 *  CVSS severity. Use this anywhere a single finding badge is shown so surfaces
 *  don't drift (the Risk Score band can promote above raw CVSS via EPSS/KEV). */
export function FindingRiskBadge({ finding }: { finding: Finding }) {
  return finding.risk_band
    ? <RiskBandBadge band={finding.risk_band} score={finding.risk_score} />
    : <SeverityBadge severity={finding.severity} />
}

/** Orthogonal momentum flag — rides alongside the verdict, not part of it.
 *  Animated ⚡ to draw the eye without disrupting the severity colour system. */
export function BuildingVelocityBadge({ active }: { active: boolean | null | undefined }) {
  if (!active) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-center gap-0.5 rounded border border-amber-500/40 bg-amber-500/15 px-1.5 py-0.5 text-xs font-semibold text-amber-600 dark:text-amber-400 cursor-help animate-pulse">
          <span aria-hidden>⚡</span> Building Velocity
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="whitespace-pre-line">
        Exploitation signals are accelerating — this finding may jump severity tiers soon.
      </TooltipContent>
    </Tooltip>
  )
}

export const CATEGORY_LABEL: Record<string, string> = {
  cve:                    "CVE",
  app_security:           "App Security",
  exposed_asset:          "Exposed Asset",
  exposure:               "Exposure",
  information_disclosure: "Info Disclosure",
  configuration:          "Configuration",
  network_security:       "Network Security",
  outdated_software:      "Outdated Software",
  other:                  "Other",
}

const CATEGORY_COLOR: Record<string, string> = {
  cve:                    "bg-red-500/10 text-red-600 dark:text-red-400",
  app_security:           "bg-purple-500/10 text-purple-600 dark:text-purple-400",
  exposed_asset:          "bg-orange-500/10 text-orange-600 dark:text-orange-400",
  exposure:               "bg-rose-500/10 text-rose-600 dark:text-rose-400",
  information_disclosure: "bg-yellow-500/10 text-yellow-600 dark:text-yellow-400",
  configuration:          "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  network_security:       "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400",
  outdated_software:      "bg-slate-500/10 text-slate-600 dark:text-slate-400",
  other:                  "bg-muted text-muted-foreground",
}

export function CategoryBadge({ category }: { category: string | null }) {
  if (!category) return null
  const label = CATEGORY_LABEL[category] ?? category
  const color = CATEGORY_COLOR[category] ?? "bg-muted text-muted-foreground"
  return (
    <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium ${color}`}>
      {label}
    </span>
  )
}

// ── Impact class (consequence category — context, not the verdict) ─────────────
type ImpactClass = NonNullable<Finding["impact_class"]>

// "Denial of Service" → "Service Disruption": the consequence, not the
// mechanism — carries the business stakes without implying a breach.
export const IMPACT_CLASS_LABEL: Record<ImpactClass, string> = {
  rce:               "Code Execution",
  data_exposure:     "Data Exposure",
  denial_of_service: "Service Disruption",
  tampering:         "Tampering",
  other:             "Other Impact",
}

// VulnCheck XDB exploit-type vocabulary equivalent, for de-duplication against
// ExploitTypeBadges — independent of the display label above.
const IMPACT_CLASS_EXPLOIT_DUP: Record<ImpactClass, string> = {
  rce:               "code execution",
  data_exposure:     "data exposure",
  denial_of_service: "denial of service",
  tampering:         "tampering",
  other:             "other",
}

// Neutral "eyebrow" chip — raised fill, identical in light & dark. Deliberately
// the only impact-class style: color is reserved for the verdict band, so this
// tag never competes with it (used both above the verdict on cards/heroes and
// as an adjacent pill in dense table rows).
const IMPACT_CLASS_CLS = "bg-muted text-muted-foreground"

// SSVC Technical Impact degree → adjective prefix on the consequence label
// ("Total Code Execution" / "Partial Code Execution"). Bare label when SSVC hasn't
// rated the degree. Both dimensions (kind + degree) in one neutral chip — no extra pill.
const SSVC_TI_DEGREE: Record<NonNullable<Finding["ssvc_technical_impact"]>, string> = {
  total:   "Total",
  partial: "Partial",
}

/** Consequence-category tag ("what's at stake"), degree-prefixed by SSVC Technical
 *  Impact when available. Honest framing without changing the verdict's urgency;
 *  neutral by design (the band owns colour). Deep-links to the impact-filtered list;
 *  the title carries the technical-impact degree + provenance. */
export function ImpactClassBadge({ finding }: { finding: Finding }) {
  const impactClass = finding.impact_class
  if (!impactClass) return null
  const ti = finding.ssvc_technical_impact
  const degree = ti ? `${SSVC_TI_DEGREE[ti]} ` : ""
  const prov = finding.ssvc_source === "vulnrichment" ? "CISA Vulnrichment" : "inferred from CVSS vector"
  const title = ti
    ? `Technical impact: ${ti === "total" ? "total control" : "partial control"} (${prov}). Click to filter by impact.`
    : "Consequence category. Click to filter by impact."
  return (
    <Link
      to={`/findings?impact_class=${impactClass}`}
      title={title}
      className={`self-start inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide hover:opacity-80 transition-opacity ${IMPACT_CLASS_CLS}`}
    >
      {degree}{IMPACT_CLASS_LABEL[impactClass]}
    </Link>
  )
}

// ── SSVC evidence (flyout / detail overview) ───────────────────────────────────
const SSVC_TI_LABEL: Record<NonNullable<Finding["ssvc_technical_impact"]>, string> = {
  total:   "Total control",
  partial: "Partial control",
}
const SSVC_EXPL_LABEL: Record<NonNullable<Finding["ssvc_exploitation"]>, string> = {
  none:   "None observed",
  poc:    "Proof of concept",
  active: "Active exploitation",
}

/** SSVC decision points (CISA Vulnrichment or derived) — the structural evidence
 *  behind the verdict: Technical Impact, Automatable, Exploitation. Values deep-link
 *  to their filters. Renders nothing when the finding has no SSVC at all. Exploitation
 *  is shown only for real Vulnrichment (the derived fallback can't infer it). */
export function SsvcEvidence({ finding }: { finding: Finding }) {
  const src = finding.ssvc_source
  if (!src) return null
  const derived = src === "derived"
  const ti = finding.ssvc_technical_impact
  const auto = finding.ssvc_automatable
  const expl = finding.ssvc_exploitation
  return (
    <div className="rounded-md border p-4 space-y-2.5">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">SSVC</p>
        <span
          className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${derived
            ? "border-border bg-muted/40 text-muted-foreground"
            : "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-400"}`}
          title={derived
            ? "Inferred from the CVSS vector — CISA Vulnrichment hasn't scored this CVE"
            : "Scored by CISA Vulnrichment"}
        >
          {derived ? "Derived" : "CISA Vulnrichment"}
        </span>
      </div>
      {ti && (
        <div className="flex items-center gap-3 text-sm">
          <span className="text-xs text-muted-foreground w-28 shrink-0">Technical impact</span>
          <Link to={`/findings?tech_impact=${ti}`} className="font-medium hover:opacity-80 transition-opacity" title="Filter by technical impact">
            {SSVC_TI_LABEL[ti]}
          </Link>
        </div>
      )}
      {auto != null && (
        <div className="flex items-center gap-3 text-sm">
          <span className="text-xs text-muted-foreground w-28 shrink-0">Automatable</span>
          {auto
            ? <Link to="/findings?automatable=true" className="font-medium hover:opacity-80 transition-opacity" title="Show automatable findings">Yes</Link>
            : <span className="font-medium">No</span>}
        </div>
      )}
      {!derived && expl && (
        <div className="flex items-center gap-3 text-sm">
          <span className="text-xs text-muted-foreground w-28 shrink-0">Exploitation</span>
          <span className="font-medium">{SSVC_EXPL_LABEL[expl]}</span>
        </div>
      )}
    </div>
  )
}

/** VulnCheck XDB exploit-type tags (initial-access / infoleak / …). Searchable
 *  signal of how a CVE is weaponized. Overflowed past 2 like every multi-value cell.
 *  Pass `impactClass` to drop tags already shown by the ImpactClassBadge (same
 *  words, different source — e.g. avoids two "Denial of Service" pills). */
export function ExploitTypeBadges({ types, impactClass }: { types: string[] | null | undefined; impactClass?: Finding["impact_class"] }) {
  if (!types || types.length === 0) return null
  const dupLabel = impactClass ? IMPACT_CLASS_EXPLOIT_DUP[impactClass] : null
  const shown = dupLabel ? types.filter(t => t.replace(/-/g, " ").toLowerCase() !== dupLabel) : types
  if (shown.length === 0) return null
  const chip = (t: string) => (
    <span key={t} className="inline-flex items-center rounded border border-purple-500/30 bg-purple-500/10 px-1.5 py-0.5 text-xs font-medium text-purple-600 dark:text-purple-400 capitalize">
      {t.replace(/-/g, " ")}
    </span>
  )
  return (
    <OverflowCell
      items={shown}
      limit={2}
      emptyLabel=""
      renderItem={chip}
      renderOverflowItem={chip}
      getLabel={(t) => t}
    />
  )
}

// ── BOD-26-04 Remediation SLA badge ───────────────────────────────────────────

const BOD_WINDOW_COLOR: Record<NonNullable<NonNullable<Finding["bod_sla"]>["window"]>, string> = {
  "3d":        "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
  "3d+triage": "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400",
  "14d":       "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  "60d":       "border-border bg-muted/50 text-muted-foreground",
  "upgrade":   "border-border bg-muted/50 text-muted-foreground",
}

/** BOD-26-04 compliance deadline badge. Only rendered when the finding has real
 *  Vulnrichment SSVC data and a CVE (i.e., bod_sla is non-null). Color by urgency:
 *  overdue or 3-day window → red; 14d → amber; 60d/upgrade → neutral. */
export function BodSlaBadge({ finding }: { finding: Finding }) {
  const sla = finding.bod_sla
  if (!sla) return null

  const colorCls = sla.overdue
    ? "border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400"
    : BOD_WINDOW_COLOR[sla.window]

  let deadline: string
  if (sla.window === "upgrade") {
    deadline = "fix on upgrade"
  } else if (sla.overdue) {
    deadline = "overdue"
  } else if (sla.days_remaining === 0) {
    deadline = "due today"
  } else {
    deadline = `${sla.days_remaining}d left`
  }

  const label = sla.window === "upgrade"
    ? `BOD: ${deadline}`
    : `BOD: ${sla.window.replace("+triage", "")} · ${deadline}`

  const triage = sla.forensic_triage ? " + forensic triage required" : ""
  const dueStr = sla.due_date
    ? `Due: ${sla.due_date}${triage}`
    : triage || "No fixed date (upgrade path)"

  const tooltip = `CISA BOD 26-04 remediation SLA\nWindow: ${sla.window}${triage}\n${dueStr}`

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium cursor-help ${colorCls}`}>
          {label}{sla.forensic_triage ? " + triage" : ""}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="whitespace-pre-line max-w-xs">{tooltip}</TooltipContent>
    </Tooltip>
  )
}

const STATE_COLOR: Record<Finding["state"], string> = {
  open:         "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  acknowledged: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  suppressed:   "bg-muted text-muted-foreground",
  resolved:     "bg-slate-500/10 text-slate-500",
}

export function StateBadge({ state }: { state: Finding["state"] }) {
  return (
    <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium capitalize ${STATE_COLOR[state]}`}>
      {state}
    </span>
  )
}

export function cvssColor(score: number): string {
  if (score >= 9.0) return "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30"
  if (score >= 7.0) return "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30"
  if (score >= 4.0) return "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30"
  return "bg-blue-500/15 text-blue-500 border-blue-500/30"
}

// EPSS scores are heavily right-skewed: ~90% of CVEs are below 1%.
// Thresholds are set at meaningful exploit-probability inflection points,
// not evenly spaced like CVSS.
export function epssColor(score: number): string {
  if (score >= 0.50) return "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30"
  if (score >= 0.10) return "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30"
  if (score >= 0.01) return "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30"
  return "bg-muted border-border"
}

type EnrichmentItem = { key: string; label: string; tooltip: string; badgeClass: string }

export function EnrichmentBadges({ finding }: { finding: Finding }) {
  const items: EnrichmentItem[] = []

  if (finding.kev) {
    items.push({
      key: "kev",
      label: "KEV",
      tooltip: finding.kev_date_added
        ? `CISA Known Exploited Vulnerability\nAdded ${finding.kev_date_added}`
        : "CISA Known Exploited Vulnerability",
      badgeClass: "bg-red-500 text-white border-red-600 font-bold",
    })
  }
  if (finding.vulncheck_kev && !finding.kev) {
    items.push({
      key: "vckev",
      label: "VC-KEV",
      tooltip: "VulnCheck KEV — confirmed exploited (often listed ahead of CISA KEV)",
      badgeClass: "bg-red-500 text-white border-red-600 font-bold",
    })
  }
  if (finding.ransomware_use) {
    items.push({
      key: "ransomware",
      label: "Ransomware",
      tooltip: "Associated with a known ransomware campaign (VulnCheck)",
      badgeClass: "bg-red-600 text-white border-red-700 font-bold",
    })
  }
  if (finding.canary_detected) {
    items.push({
      key: "canary",
      label: "Canary",
      tooltip: "Observed exploited in the wild by VulnCheck canaries (ground-truth)",
      badgeClass: "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30 font-semibold",
    })
  }
  if (finding.has_exploit) {
    const n = finding.exploit_count ?? 0
    items.push({
      key: "exploit",
      label: n > 0 ? `Exploit ×${n}` : "Exploit",
      tooltip: n > 0
        ? `${n} public exploit${n === 1 ? "" : "s"} in VulnCheck XDB`
        : "Public exploit available (VulnCheck XDB)",
      badgeClass: "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30 font-semibold",
    })
  }
  if (finding.cvss_score != null) {
    const headline = finding.cvss_version
      ? `CVSS v${finding.cvss_version} — ${finding.cvss_score.toFixed(1)}`
      : `CVSS ${finding.cvss_score.toFixed(1)}`
    items.push({
      key: "cvss",
      label: `CVSS ${finding.cvss_score.toFixed(1)}`,
      tooltip: finding.cvss_vector ? `${headline}\n${finding.cvss_vector}` : headline,
      badgeClass: cvssColor(finding.cvss_score),
    })
  }
  if (finding.epss_score != null) {
    const pct = (finding.epss_score * 100).toFixed(1)
    const detail = finding.epss_percentile != null
      ? `EPSS ${(finding.epss_score * 100).toFixed(2)}% exploit probability\n${(finding.epss_percentile * 100).toFixed(0)}th percentile`
      : `EPSS ${(finding.epss_score * 100).toFixed(2)}% exploit probability`
    items.push({
      key: "epss",
      label: `EPSS ${pct}%`,
      tooltip: detail,
      badgeClass: epssColor(finding.epss_score),
    })
  }
  if (finding.is_template) {
    items.push({
      key: "template",
      label: "Nuclei",
      tooltip: "A Nuclei template exists — automated attack tooling is available (vulnx)",
      badgeClass: "bg-purple-500/15 text-purple-600 dark:text-purple-400 border-purple-500/30",
    })
  }
  if (finding.is_poc && !finding.has_exploit) {
    items.push({
      key: "poc",
      label: "PoC",
      tooltip: "A public proof-of-concept exists (vulnx)",
      badgeClass: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30",
    })
  }
  if (finding.cwe) {
    items.push({
      key: "cwe",
      label: finding.cwe,
      tooltip: finding.cwe,
      badgeClass: "bg-muted/50 border-border text-muted-foreground",
    })
  }

  return (
    <OverflowCell
      items={items}
      limit={2}
      emptyLabel=""
      renderItem={(item) => (
        <Tooltip key={item.key}>
          <TooltipTrigger asChild>
            <span className={`inline-flex items-center rounded border px-1 py-0.5 text-xs font-mono cursor-help ${item.badgeClass}`}>
              {item.label}
            </span>
          </TooltipTrigger>
          <TooltipContent side="top" className="whitespace-pre-line">
            {item.tooltip}
          </TooltipContent>
        </Tooltip>
      )}
      // Rich hover card: each hidden signal as its colored badge + what it means.
      renderOverflowItem={(item) => (
        <div className="flex items-start gap-2">
          <span className={`inline-flex items-center rounded border px-1 py-0.5 text-xs font-mono shrink-0 ${item.badgeClass}`}>
            {item.label}
          </span>
          <span className="text-muted-foreground whitespace-pre-line leading-snug pt-0.5">{item.tooltip}</span>
        </div>
      )}
      getLabel={(item) => item.label}
    />
  )
}

// ── Provenance: source(s) + port + upstream evidence (#71) ─────────────────────
// Surfaces WHAT produced a finding and WHAT evidence backs it — the missing trust
// signal that makes e.g. a Shodan host-attributed CVE legible as "Shodan said so,
// not our scan." `source` is on every row; the read-time CVE rollup adds `sources[]`
// (a logical finding can have several), `confidence`, and `fixed_version`.

type SourceMeta = { label: string; cls: string; Icon: LucideIcon; blurb: string }

const SOURCE_META: Record<string, SourceMeta> = {
  nuclei: {
    label: "Nuclei",
    cls: "border-purple-500/40 bg-purple-500/10 text-purple-600 dark:text-purple-400",
    Icon: Crosshair,
    blurb: "Actively probed by Nuclei against this asset — a template matched on our own scan.",
  },
  shodan: {
    label: "Shodan",
    cls: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-400",
    Icon: Radar,
    blurb: "Attributed by Shodan's host fingerprinting — Shodan's own data, separate from Constellus's scan.",
  },
  constellus: {
    label: "Constellus exposure",
    cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
    Icon: Telescope,
    blurb: "Flagged by the Constellus exposure analyzer from an open port/service we observed.",
  },
  version_match: {
    label: "Version match",
    cls: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400",
    Icon: GitCompareArrows,
    blurb: "Inferred by matching the detected product version against known-vulnerable ranges — backport-blind, so it can overstate.",
  },
  whois: {
    label: "WHOIS",
    cls: "border-slate-500/40 bg-slate-500/10 text-slate-600 dark:text-slate-400",
    Icon: CalendarClock,
    blurb: "Derived from the domain's WHOIS registration record.",
  },
  tenable: {
    label: "Tenable",
    cls: "border-blue-500/40 bg-blue-500/10 text-blue-600 dark:text-blue-400",
    Icon: ShieldCheck,
    blurb: "Imported from a Tenable vulnerability scan.",
  },
}

function sourceMeta(source: string): SourceMeta {
  return SOURCE_META[source] ?? {
    label: source,
    cls: "border-border bg-muted/50 text-muted-foreground",
    Icon: ScanSearch,
    blurb: `Reported by ${source}.`,
  }
}

/** Friendly label for a source (e.g. "version_match" → "Version match"). Used by
 *  the Findings source filter Select. */
export function sourceLabel(source: string): string {
  return sourceMeta(source).label
}

/** Every source that contributed to this (rolled-up) finding; falls back to the
 *  single `source` for un-rolled findings. */
export function findingSources(f: Finding): string[] {
  return f.sources && f.sources.length > 0 ? f.sources : [f.source]
}

/** The port a finding maps to, when we have one. An explicit `detail.port`
 *  (exposure, version_match) wins; for Nuclei we derive it from the `matched_at`
 *  URL (the port lives there, with the default 80/443 omitted). Shodan host-level
 *  CVEs have no port by nature → null. */
export function findingPort(f: Finding): number | null {
  const d = (f.detail ?? {}) as Record<string, unknown>
  if (typeof d.port === "number" && Number.isFinite(d.port)) return d.port
  const matchedAt = typeof d.matched_at === "string" ? d.matched_at : null
  return matchedAt ? portFromMatchedAt(matchedAt) : null
}

/** Parse the port out of a Nuclei matched-at value: an explicit port wins; a URL
 *  with a scheme but no port falls back to the scheme default; a bare `host:port`
 *  is parsed via a synthetic scheme. Returns null when no port can be determined. */
function portFromMatchedAt(raw: string): number | null {
  const s = raw.trim()
  if (!s) return null
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
      const u = new URL(s)
      if (u.port) return Number(u.port)
      const proto = u.protocol.replace(":", "").toLowerCase()
      return proto === "https" ? 443 : proto === "http" ? 80 : null
    }
    const u = new URL(`x://${s}`)
    return u.port ? Number(u.port) : null
  } catch {
    return null
  }
}

/** Provenance pill — which producer reported this finding. Deep-links to the
 *  source-filtered findings list (mirrors CategoryBadge). */
export function SourceBadge({ source }: { source: string }) {
  const { label, cls, Icon, blurb } = sourceMeta(source)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Link
          to={`/findings?source=${encodeURIComponent(source)}`}
          title={`Show ${label} findings`}
          className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium hover:opacity-80 transition-opacity ${cls}`}
        >
          <Icon className="h-3 w-3" />{label}
        </Link>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">{blurb}</TooltipContent>
    </Tooltip>
  )
}

/** One SourceBadge per contributing source (usually one; CVEs rolled up across
 *  shodan + version_match + nuclei show all). */
export function SourceBadges({ finding }: { finding: Finding }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {findingSources(finding).map(s => <SourceBadge key={s} source={s} />)}
    </span>
  )
}

/** The port a finding maps to, deep-linking to the port-filtered list. Renders
 *  nothing when there's no port (e.g. Shodan host-level CVEs). */
export function PortBadge({ port }: { port: number | null }) {
  if (port == null) return null
  return (
    <Link
      to={`/findings?port=${port}`}
      title="Show findings on this port"
      className="inline-flex items-center rounded border border-border bg-muted/50 px-1.5 py-0.5 text-xs font-mono text-muted-foreground hover:opacity-80 transition-opacity"
    >
      :{port}
    </Link>
  )
}

/** Confirmed (directly observed/validated) vs Potential (inferred from
 *  version/CPE intelligence). Mirrors the backend confidence tiering. */
function ConfidenceChip({ confidence }: { confidence?: "confirmed" | "potential" }) {
  if (!confidence) return null
  const confirmed = confidence === "confirmed"
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium cursor-help ${confirmed
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
          : "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400"}`}>
          {confirmed ? "Confirmed" : "Potential"}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs">
        {confirmed
          ? "Directly observed or validated — an active probe fired, or it's our own observation of the exposed service."
          : "Inferred from version/CPE intelligence without confirming the weakness is present — backport-blind, so it can overstate."}
      </TooltipContent>
    </Tooltip>
  )
}

/** Upstream-evidence panel for a finding's flyout / full detail. Always renders
 *  (every finding has a source). Header shows the source badge(s), the port (or a
 *  host-level marker), and the confidence tier; the body renders the source-specific
 *  evidence we hold in `detail`. Nuclei's matched-URL / extracted / curl already
 *  render in the Overview, so they aren't duplicated here. */
export function UpstreamEvidence({ finding }: { finding: Finding }) {
  const d = (finding.detail ?? {}) as Record<string, unknown>
  const primary = finding.source
  const sources = findingSources(finding)
  const port = findingPort(finding)
  // "Host-level" only when Shodan is the *sole* source: a mixed shodan+version_match
  // rollup also has our own port-based evidence, so the "nothing in our scan" framing
  // wouldn't be honest there.
  const hostLevel = sources.length === 1 && sources[0] === "shodan" && port == null

  const str = (k: string): string | null => (typeof d[k] === "string" && d[k] ? String(d[k]) : null)
  const num = (k: string): number | null => (typeof d[k] === "number" ? (d[k] as number) : null)

  const rows: { label: string; value: ReactNode }[] = []
  const mono = (v: string) => <span className="font-mono break-all">{v}</span>

  // Constellus exposure
  if (str("rule_id")) rows.push({ label: "Rule", value: mono(str("rule_id")!) })
  if (str("service")) {
    // detail.confidence here is the service-identification confidence (separate
    // from the source-level Confirmed/Potential chip): mark unconfirmed inline.
    const unconfirmed = str("confidence") === "potential"
    rows.push({
      label: "Service",
      value: unconfirmed
        ? <>{str("service")} <span className="text-muted-foreground">(unconfirmed)</span></>
        : str("service"),
    })
  }
  if (str("protocol")) rows.push({ label: "Protocol", value: str("protocol")!.toUpperCase() })
  // Version match
  if (str("product") && str("installed_version")) rows.push({ label: "Detected", value: `${str("product")} ${str("installed_version")}` })
  if (str("affected_range")) rows.push({ label: "Affected", value: str("affected_range") })
  const fixed = finding.fixed_version ?? str("fixed_version")
  if (fixed) rows.push({ label: "Fixed in", value: fixed })
  if (str("cpe")) rows.push({ label: "CPE", value: mono(str("cpe")!) })
  // Shodan
  if (num("shodan_cvss") != null) rows.push({ label: "Shodan CVSS", value: num("shodan_cvss")!.toFixed(1) })
  if (typeof d.shodan_verified === "boolean") rows.push({ label: "Shodan", value: d.shodan_verified ? "Verified" : "Unverified" })
  // Nuclei
  if (str("template_id")) rows.push({ label: "Template", value: mono(str("template_id")!) })
  // WHOIS (defensive — no producer yet)
  if (str("expiration_date")) rows.push({ label: "Expires", value: str("expiration_date") })
  // Dangling-DNS origin corroboration (epic#81 Phase C, planning#106) —
  // detail.corroboration is a nested object, not a flat str()/num() key.
  const corroboration = d.corroboration as Record<string, unknown> | undefined
  if (corroboration?.attempted) {
    const probed = Array.isArray(corroboration.hostnames_probed) ? corroboration.hostnames_probed.length : 0
    rows.push({
      label: "Corroboration",
      value: corroboration.origin_serves_others
        ? <>Confirmed alive via <span className="font-mono">{String(corroboration.corroborating_hostname)}</span></>
        : `No signal from ${probed} other known hostname${probed !== 1 ? "s" : ""} on this origin`,
    })
  }

  return (
    <div className="rounded-md border p-4 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Provenance</p>
        <ConfidenceChip confidence={finding.confidence} />
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <SourceBadges finding={finding} />
        {port != null
          ? <PortBadge port={port} />
          : hostLevel
          ? <span className="inline-flex items-center rounded border border-border bg-muted/50 px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground" title="No port — Shodan attributes this at the host/IP level">host-level</span>
          : null}
      </div>

      {/* Always-visible prose only for single-source findings — for a multi-source
          rollup the representative's blurb wouldn't describe the others, so we lean on
          each SourceBadge's own tooltip instead. */}
      {sources.length === 1 && (
        <p className="text-xs text-muted-foreground leading-relaxed">{sourceMeta(primary).blurb}</p>
      )}

      {hostLevel && (
        <div className="rounded border-l-2 border-l-sky-500 bg-sky-500/5 px-3 py-2">
          <p className="text-xs text-sky-700 dark:text-sky-400 leading-relaxed">
            Shodan attributes this at the host/IP level from its own fingerprinting — there may be nothing
            in Constellus's scan data for this asset that corresponds to it.
          </p>
        </div>
      )}

      {rows.length > 0 && (
        <div className="space-y-1.5 pt-1">
          {rows.map((r, i) => (
            <div key={i} className="flex items-start gap-3 text-sm">
              <span className="text-xs text-muted-foreground w-24 shrink-0">{r.label}</span>
              <span className="break-all">{r.value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
