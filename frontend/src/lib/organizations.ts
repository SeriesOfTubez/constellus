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

// ── segments / query params ─────────────────────────────────────────────────

export type Segment = "all" | "candidates" | "claimed" | "rejected"
export const SEGMENTS: Segment[] = ["all", "candidates", "claimed", "rejected"]
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
