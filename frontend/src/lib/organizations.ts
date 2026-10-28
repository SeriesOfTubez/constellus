// Organizations page (planning#277 S2): API types + the pure helpers the page
// and its tests share. Field names mirror `backend/app/api/organizations.py`.

export type Tier = "strong" | "supporting" | "context"
export type CandidateStatus = "open" | "claimed" | "rejected"
export type Strength = "strong" | "supporting" | "lead" | "context"
export type SeverityKey = "critical" | "high" | "medium" | "low" | "unknown"

export interface EngagementRef { id: string; name: string; posture: string; deal_reference: string | null }

export interface OrganizationSummary {
  id: string
  name: string
  relationship: "ours" | "ma_target"
  seed_domain: string | null
  engagement: EngagementRef | null
  claimed: number
  proposed: number
  leads: number
  rejected: number
}

export interface TreeNode {
  entity_id: string
  name: string
  parent_id: string | null
  relation: "subsidiary_of" | "acquired" | null
  event_date: string | null
  status: "confirmed" | "proposed"
  depth: number
}

export interface OrgDetailSummary {
  claimed: number
  to_review: number
  leads: number
  rejected: number
  assets_under_claimed_scope: number
  affiliates: number
  proposed_affiliates: number
  has_filer: boolean
}

export interface SignalType {
  signal_type: string
  tier: Tier
  family: string
  label: string
  description: string
  built: boolean
}

export interface SignalSummary { signal_type: string; tier: Tier; family: string; count: number }
export type SeverityCounts = Record<SeverityKey, number>

export interface CandidateRow {
  id: string
  root_entity_id: string
  value: string
  kind: string
  status: CandidateStatus
  strength: Strength
  proposable: boolean
  affiliated: { id: string | null; name: string | null }
  affiliated_is_default: boolean
  signals: SignalSummary[]
  first_seen_at: string | null
  previously_rejected: { reason: string | null; at: string } | null
  target_id: string | null
  decided_by_connector_instance_id: string | null
  asset_count: number | null
  open_findings: SeverityCounts | null
  worst_severity: SeverityKey | null
  /** Lowercase RIR (arin|ripe|apnic|lacnic|afrinic) and its handle; set for asn/cidr, null for domain. */
  rir: string | null
  rir_handle: string | null
}

export interface CandidatePage { items: CandidateRow[]; total: number }

export interface AnchorDetail {
  kind: string
  candidate_id: string | null
  candidate_value: string | null
  entity_id: string | null
  entity_name: string | null
  user_id: string | null
}

export interface SignalDetail {
  id: string
  signal_type: string
  tier: Tier
  family: string
  anchor: AnchorDetail
  via_entity: { id: string | null; name: string | null }
  quote: string | null
  evidence_id: string | null
  matched_values: string[] | null
  first_seen_at: string
  last_seen_at: string
}

export interface CandidateEvent {
  event: "claimed" | "rejected" | "unlocked"
  at: string
  user_id: string | null
  reason: string | null
  signal_id: string | null
  connector_instance_id: string | null
}

export interface CandidateDetail extends CandidateRow {
  signal_details: SignalDetail[]
  events: CandidateEvent[]
  rejection_reason: string | null
  decided_at: string | null
  accepted_into: string | null
  engagement_id: string | null
  decided_by_id: string | null
  decided_by_connector_name: string | null
}

/** One page capture (mirrors the backend CaptureResponse). `redirect_chain` entries are
 *  `{url, status}` hops from the capture browser; typed loosely because the API sends `list`. */
export interface PageCapture {
  id: string
  status: "queued" | "done" | "failed" | string
  failure_reason: string | null
  error: string | null
  requested_at: string
  finished_at: string | null
  requested_by_id: string | null
  domain: string
  requested_url: string
  final_url: string | null
  http_status: number | null
  redirect_chain: unknown[] | null
  title: string | null
  user_agent: string | null
  user_agent_mode: string
  image_max_bytes: number
  cert: Record<string, unknown> | null
  cert_san_dns: string[] | null
  cert_sha256: string | null
  pinned_ip: string | null
  proxy_log_truncated: boolean
  image_bytes: number | null
  image_sha256: string | null
  image_quality: number | null
  image_omitted_reason: string | null
  image_pruned_at: string | null
  has_image: boolean
  request_count: number
}

// ── registry observations (planning#278 S3d) ───────────────────────────────

export type NewHolderKind = "org" | "customer" | "unknown" | "unregistered"

/** A registry observation, NOT a finding: the registry now lists part of a claimed
 *  prefix under another holder. Never changes the claim. */
export interface ReassignmentRow {
  id: string
  candidate_id: string
  candidate_value: string
  rir: string | null
  rir_handle: string | null
  prefix: string
  new_holder_kind: NewHolderKind
  new_holder_handle: string | null
  evidence_id: string | null
  first_detected_at: string
  last_seen_at: string
}

export interface ReassignmentPage { items: ReassignmentRow[]; total: number }

export interface RecheckAccepted { claimed_domains: number }

export function rirLabel(rir: string | null): string {
  return rir ? rir.toUpperCase() : "The registry"
}

export function registryChangeText(
  r: Pick<ReassignmentRow, "rir" | "prefix" | "new_holder_kind" | "new_holder_handle">,
): string {
  const who = rirLabel(r.rir)
  if (r.new_holder_kind === "unregistered") return `${who} shows ${r.prefix} is no longer registered to anyone`
  if ((r.new_holder_kind === "org" || r.new_holder_kind === "customer") && r.new_holder_handle) {
    return `${who} now lists ${r.prefix} under ${r.new_holder_handle} (${r.new_holder_kind === "org" ? "organization" : "customer"})`
  }
  return `${who} now lists ${r.prefix} under an unidentified holder`
}

/** "ARIN · EXAMPLE-ORG-1"; a dash when the row carries no registry data. */
export function registryHolder(row: CandidateRow): string {
  if (!row.rir && !row.rir_handle) return "—"
  return [rirLabel(row.rir), row.rir_handle].filter(Boolean).join(" · ")
}

// ── segments / query params ─────────────────────────────────────────────────

export type Segment = "all" | "candidates" | "claimed" | "rejected"
export const SEGMENTS: Segment[] = ["all", "candidates", "claimed", "rejected"]

/** Candidates is the review queue, so it is the default view, except for an org with
 *  nothing to review but something claimed (e.g. just added from its seed), where an
 *  empty Candidates view would hide the claimed domains. */
export function defaultSegment(org: Pick<OrganizationSummary, "claimed" | "proposed">): Segment {
  return org.proposed === 0 && org.claimed > 0 ? "all" : "candidates"
}
export const SEGMENT_LABEL: Record<Segment, string> = {
  all: "All", candidates: "Candidates", claimed: "Claimed", rejected: "Rejected",
}

/** Candidates = the API default (`open`: proposable only). */
export function segmentStatus(segment: Segment): "open" | "claimed" | "rejected" | "all" {
  return segment === "candidates" ? "open" : segment === "all" ? "all" : segment
}

export interface CandidateFilters {
  segment: Segment
  q?: string
  strength?: string
  signalType?: string
  subtreeOf?: string | null
  leadsOnly?: boolean
  kind?: "domain" | "asn" | "cidr"
  reassigned?: boolean
  limit?: number
  offset?: number
}

export function candidateParams(f: CandidateFilters): URLSearchParams {
  const p = new URLSearchParams()
  if (f.leadsOnly) p.set("leads_only", "true")
  else p.set("status", segmentStatus(f.segment))
  if (f.q) p.set("q", f.q)
  if (f.strength && f.strength !== "all") p.set("strength", f.strength)
  if (f.signalType && f.signalType !== "all") p.set("signal_type", f.signalType)
  if (f.subtreeOf) p.set("subtree_of", f.subtreeOf)
  if (f.kind && f.kind !== "domain") p.set("kind", f.kind)
  if (f.reassigned !== undefined) p.set("reassigned", f.reassigned ? "true" : "false")
  p.set("limit", String(f.limit ?? 200))
  if (f.offset) p.set("offset", String(f.offset))
  return p
}

/** Total shown on a segment pill / tab, from the summary. */
export function segmentCount(segment: Segment, s: OrgDetailSummary): number {
  switch (segment) {
    case "candidates": return s.to_review
    case "claimed": return s.claimed
    case "rejected": return s.rejected
    case "all": return s.claimed + s.to_review + s.rejected
  }
}

// ── tiers ───────────────────────────────────────────────────────────────────

/** Tier chips use the brand accent / muted only: the severity palette means
 *  severity and nothing else. */
export function tierChipClass(tier: string): string {
  switch (tier) {
    case "strong": return "bg-primary text-primary-foreground border-primary"
    case "supporting": return "bg-transparent text-primary border-primary"
    default: return "bg-muted text-muted-foreground border-border"
  }
}

export const TIER_LABEL: Record<string, string> = { strong: "Strong", supporting: "Supporting", context: "Context" }
export const STRENGTH_LABEL: Record<string, string> = { strong: "Strong", supporting: "Supporting", lead: "Lead", context: "Context" }
export const TIER_LEGEND = "Strong — enough alone · Supporting — two from different families · Context — never counts"

const TIER_RANK: Record<string, number> = { strong: 0, supporting: 1, context: 2 }
export function tierRank(tier: string): number { return TIER_RANK[tier] ?? 3 }

// ── state / anchors / severity ─────────────────────────────────────────────

export interface StateInfo {
  label: string
  viaConnector: boolean
  previouslyRejected: boolean
}

export function stateInfo(row: CandidateRow): StateInfo {
  const seed = row.signals.some(s => s.signal_type === "admin_seed")
  const label =
    row.status === "claimed" ? (seed ? "Claimed · seed" : "Claimed")
    : row.status === "rejected" ? "Rejected"
    : "Candidate"
  return {
    label,
    viaConnector: row.decided_by_connector_instance_id !== null,
    previouslyRejected: row.previously_rejected !== null,
  }
}

export function anchorText(a: AnchorDetail): string {
  switch (a.kind) {
    case "claimed_candidate": return `via claimed domain ${a.candidate_value ?? "(unknown)"}`
    case "filer_filing": return `via filer ${a.entity_name ?? "(unknown)"}`
    case "person": return "via a person"
    case "connector_instance": return "via connector"
    default: return `via ${a.kind}`
  }
}

export const SEVERITY_KEYS: SeverityKey[] = ["critical", "high", "medium", "low", "unknown"]
/** Solid fills matching the locked severity palette (finding-badges SEVERITY_COLOR). */
export const SEVERITY_BAR_CLASS: Record<SeverityKey, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  unknown: "bg-muted-foreground/40",
}

export interface BarSegment { severity: SeverityKey; count: number; pct: number }
export function severityBar(counts: SeverityCounts | null): { segments: BarSegment[]; total: number; worst: SeverityKey | null } {
  if (!counts) return { segments: [], total: 0, worst: null }
  const total = SEVERITY_KEYS.reduce((n, k) => n + (counts[k] ?? 0), 0)
  const segments = SEVERITY_KEYS
    .filter(k => (counts[k] ?? 0) > 0)
    .map(k => ({ severity: k, count: counts[k], pct: total ? (counts[k] / total) * 100 : 0 }))
  return { segments, total, worst: segments.length ? segments[0].severity : null }
}

// ── tree ────────────────────────────────────────────────────────────────────

export function relationNote(relation: TreeNode["relation"], eventDate: string | null): string | null {
  if (relation === "acquired") {
    const year = eventDate ? /^(\d{4})/.exec(eventDate)?.[1] : null
    return year ? `acquired ${year}` : "acquired"
  }
  if (relation === "subsidiary_of") return "subsidiary"
  return null
}

export interface TreeRow {
  node: TreeNode
  indent: number
  note: string | null
  selectable: boolean
}

export function treeRows(nodes: TreeNode[]): TreeRow[] {
  return nodes.map(node => ({
    node,
    indent: node.depth,
    note: relationNote(node.relation, node.event_date),
    selectable: node.status === "confirmed",
  }))
}

export function confirmedNodes(nodes: TreeNode[]): TreeNode[] {
  return nodes.filter(n => n.status === "confirmed")
}

// ── header / copy ───────────────────────────────────────────────────────────

export function headerSubtitle(org: OrganizationSummary, s: OrgDetailSummary | undefined): string {
  const parts: string[] = []
  if (org.seed_domain) parts.push(org.seed_domain)
  parts.push(org.relationship === "ours" ? "Ours" : `M&A target · ${org.engagement?.posture ?? "no engagement"}`)
  if (s?.has_filer) parts.push("SEC filer linked")
  if (s) parts.push(`${s.affiliates} affiliates (${s.proposed_affiliates} proposed)`)
  return parts.join(" · ")
}

export function destinationText(org: OrganizationSummary): string {
  return org.relationship === "ours"
    ? "our estate"
    : `engagement ${org.engagement?.name ?? "(none)"}${org.engagement ? ` (${org.engagement.posture})` : ""}`
}

export function orgPill(org: OrganizationSummary): string {
  return org.relationship === "ours" ? "ours" : (org.engagement?.posture ?? "M&A").replace(/_/g, "-")
}

// ── grouping (client-side over the loaded page) ────────────────────────────

export type OrgGroupMode = "organization" | "state" | "strength" | "signal"
export const GROUP_OPTIONS: Array<{ value: OrgGroupMode; label: string }> = [
  { value: "organization", label: "Group by organization" },
  { value: "state", label: "Group by state" },
  { value: "strength", label: "Group by strength" },
  { value: "signal", label: "Group by signal" },
]

export function groupRows(
  rows: CandidateRow[], mode: OrgGroupMode, labelOf: (signalType: string) => string,
): Array<{ key: string; label: string; rows: CandidateRow[] }> {
  const m = new Map<string, CandidateRow[]>()
  const add = (k: string, r: CandidateRow) => { const a = m.get(k) ?? []; a.push(r); m.set(k, a) }
  for (const r of rows) {
    if (mode === "organization") add(r.affiliated.name ?? "Unattributed", r)
    else if (mode === "state") add(stateInfo(r).label, r)
    else if (mode === "strength") add(STRENGTH_LABEL[r.strength] ?? r.strength, r)
    else if (r.signals.length === 0) add("No signals", r)
    else for (const s of r.signals) add(labelOf(s.signal_type), r) // a row appears under each of its signals
  }
  return [...m.entries()].map(([key, rs]) => ({ key, label: key, rows: rs }))
}

/** Sorts a flyout's signals Strong first, then Supporting; Context is split out. */
export function splitSignals(details: SignalDetail[]): { counting: SignalDetail[]; context: SignalDetail[] } {
  const by = (a: SignalDetail, b: SignalDetail) => tierRank(a.tier) - tierRank(b.tier)
  return {
    counting: details.filter(s => s.tier !== "context").sort(by),
    context: details.filter(s => s.tier === "context"),
  }
}

export function eventText(e: CandidateEvent, connectorName: string | null): string {
  const by = e.connector_instance_id ? ` by ${connectorName ? `connector ${connectorName}` : "a connector"}` : ""
  const reason = e.reason ? `: ${e.reason}` : ""
  return `${e.event}${by}${reason}`
}

// ── add-organization flow (planning#277 S2c) ────────────────────────────────

export type OrgRelationship = "ours" | "ma_target"

export interface FilingStats {
  total_filings: number
  first_filing: string | null
  last_filing: string | null
  latest_10k: string | null
  partial: boolean
}

export interface FilerHit {
  cik: string
  display_name: string | null
  edgar_url: string
  matched_filings: { form: string; file_date: string | null; accession: string }[]
  why: string[]
  stats: FilingStats | null
  entity_id: string | null
}

export interface AddOrganizationResponse {
  organization_id: string
  relationship: OrgRelationship
  engagement: unknown | null
  candidate_id: string | null
  target_id: string | null
  assignment_role: string | null
  ingest_run_id: string | null
  ingest: "queued" | "already_running" | "not_requested"
}

export interface AddOrgState {
  domain: string
  /** The chosen filer's CIK; null = "None of these: continue without a filer". */
  cik: string | null
  orgName: string
  relationship: OrgRelationship | null
  reference: string
  engagementName: string
}

export interface AddOrgRequest {
  seed_domain: string
  org_name: string
  cik: string | null
  relationship: OrgRelationship
  reference: string
  engagement_name: string | null
}

/** "N filings, YYYY–YYYY, latest 10-K YYYY-MM-DD (partial)". Null without stats. */
export function filerStatsLine(stats: FilingStats | null): string | null {
  if (!stats) return null
  const parts = [`${stats.total_filings} filing${stats.total_filings === 1 ? "" : "s"}`]
  if (stats.first_filing && stats.last_filing) {
    const a = stats.first_filing.slice(0, 4)
    const b = stats.last_filing.slice(0, 4)
    parts.push(a === b ? a : `${a}–${b}`)
  }
  if (stats.latest_10k) parts.push(`latest 10-K ${stats.latest_10k}`)
  const line = parts.join(", ")
  return stats.partial ? `${line} (partial)` : line
}

export function addOrgRequest(s: AddOrgState): AddOrgRequest {
  if (!s.relationship) throw new Error("relationship is required")
  return {
    seed_domain: s.domain.trim(),
    org_name: s.orgName.trim(),
    cik: s.cik,
    relationship: s.relationship,
    reference: s.reference.trim(),
    engagement_name: s.relationship === "ma_target" ? s.engagementName.trim() : null,
  }
}

/** Cosmetic gating; the server enforces. Step 2 (filer) is always valid: "none" is a choice. */
export function addOrgStepValid(step: 1 | 2 | 3, s: AddOrgState, canMarkOurs: boolean): boolean {
  if (step === 1) return s.domain.trim().length > 0
  if (step === 2) return true
  if (!s.orgName.trim() || !s.reference.trim() || !s.relationship) return false
  if (s.relationship === "ours") return canMarkOurs
  return s.engagementName.trim().length > 0
}

export interface RelationshipOption { value: OrgRelationship; label: string; disabled: boolean; hint: string | null }

const OURS_HINT = "Needs permission to mark organizations as ours"

export function relationshipOptions(canMarkOurs: boolean, preset?: OrgRelationship): RelationshipOption[] {
  const ours: RelationshipOption = {
    value: "ours", label: "Ours", disabled: !canMarkOurs, hint: canMarkOurs ? null : OURS_HINT,
  }
  const target: RelationshipOption = { value: "ma_target", label: "M&A target", disabled: false, hint: null }
  if (preset === "ours") return [ours]
  if (preset === "ma_target") return [target]
  return [ours, target]
}

// ── entity links (planning#277 S2c) ───────────────────────────────────────────

/** The one page link to a company. The route resolves which organization (and
 *  which node in its tree) the entity belongs to, then redirects there. */
export function entityHref(id: string): string {
  return `/organizations/entity/${id}`
}

export interface LocateResponse { org_id: string; node: string | null }

/** Where `locate` sends the browser: the org workspace, Companies tab, with the
 *  node selected unless the entity is the root. */
export function orgEntityTarget({ org_id, node }: LocateResponse): string {
  const q = new URLSearchParams({ tab: "companies" })
  if (node) q.set("node", node)
  return `/organizations/${org_id}?${q.toString()}`
}

// Acquisitions roll-up (planning#277 S4a). Mirrors AcquisitionRow / AcquisitionRollup
// in backend/app/api/organizations.py.
export interface AcquisitionRow {
  entity_id: string | null
  name: string
  organic: boolean
  closed: string | null
  closed_precision: string | null
  postures: string[]
  domains_claimed: number
  domains_to_review: number
  asns_claimed: number
  cidrs_claimed: number
  ip_to_review: number
  assets: number
  open_findings: SeverityCounts
  worst_severity: SeverityKey | null
  kev: number
  risk_score_sum: number
  risk_share: number | null
}
export interface AcquisitionRollup {
  rows: AcquisitionRow[]
  estate_risk_score_sum: number
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

/** ISO date -> display text, split by hand: new Date("2021-03-01") is UTC midnight and
 *  would show the previous day west of UTC. Precisions: day | month | year | unknown. */
export function formatClosed(closed: string | null, precision: string | null): string {
  if (!closed) return "—"
  const [y, m, d] = closed.slice(0, 10).split("-")
  const month = MONTHS[Number(m) - 1]
  if (precision === "year") return y
  if (!month) return y || "—"
  if (precision === "month") return `${month} ${y}`
  return `${Number(d)} ${month} ${y}`
}

export function formatShare(share: number | null): string {
  if (share === null) return "—"
  if (share === 0) return "0%"
  if (share < 0.01) return "<1%"
  return `${Math.round(share * 100)}%`
}

export function ipSpaceLabel(row: Pick<AcquisitionRow, "asns_claimed" | "cidrs_claimed">): string {
  const parts: string[] = []
  if (row.asns_claimed > 0) parts.push(`${row.asns_claimed} ${row.asns_claimed === 1 ? "ASN" : "ASNs"}`)
  if (row.cidrs_claimed > 0) parts.push(`${row.cidrs_claimed} ${row.cidrs_claimed === 1 ? "prefix" : "prefixes"}`)
  return parts.length ? parts.join(" · ") : "—"
}

const POSTURE_LABEL: Record<string, string> = {
  pre_close: "pre-close", day_0: "day 0", integrated: "integrated", abandoned: "abandoned", estate: "estate",
}
export function postureLabel(p: string): string {
  return POSTURE_LABEL[p] ?? p
}
