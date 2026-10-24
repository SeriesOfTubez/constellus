/**
 * Reports (planning#230 slice 1): types, API calls and the pure display rules.
 *
 * Every number shown comes from `facts.metrics`; the narrative's text is never
 * parsed for numbers.
 */
import { api } from "@/lib/api"
import { exploreHref, isInternalHref, type QueryObject } from "@/lib/chat"
import { entityHref } from "@/lib/organizations"

export type ReportKind = "exec_summary" | "ma_brief"

export type ReportStatus = "queued" | "running" | "done" | "failed"

export interface ReportListItem {
  id: string
  kind: ReportKind
  status: ReportStatus
  as_of: string
  created_at: string
  finished_at: string | null
  statements_returned: number
  statements_dropped: number
  cost_usd: number | null
}

export interface Metric {
  label: string
  query: Record<string, unknown>
  count: number
  capped: boolean
}

export interface TopFinding {
  id: string
  title: string
  severity: string
  risk_score: number | null
  risk_band: string | null
  kev: boolean | null
  cve_id: string | null
  asset_id: string
  asset_value: string
}

export interface Citation {
  path: string
  value: string
  kind: "metric" | "finding" | "fact" | "entity"
  ref: string | null
}

export type Section =
  | "posture" | "exposure" | "priorities" | "gaps"
  | "family" | "acquisitions" | "domains"

export type ListRow = Record<string, string | null>

export interface FactList {
  label: string
  query: Record<string, unknown>
  rows: ListRow[]
  truncated: boolean
}

export interface Statement {
  section: Section
  text: string
  citations: Citation[]
}

export interface Report extends ReportListItem {
  engagement_id: string
  model: string | null
  forced_strict: boolean
  error: string | null
  drop_reasons: Record<string, number>
  facts: {
    as_of: string
    engagement: { id: string; posture: string }
    metrics: Record<string, Metric>
    top_findings: TopFinding[]
    top_findings_query: Record<string, unknown>
    /** Display order of `metrics` (JSONB does not keep key order). */
    metric_order?: string[]
    /** ma_brief only. */
    subject?: { id: string; name: string }
    lists?: Record<string, FactList>
    list_order?: string[]
  } | null
  payload: { statements: Statement[] } | null
}

type ExecSection = "posture" | "exposure" | "priorities" | "gaps"

export const SECTION_ORDER: ExecSection[] = ["posture", "exposure", "priorities", "gaps"]

export const SECTION_LABELS: Record<ExecSection, string> = {
  posture: "Posture",
  exposure: "Exposure",
  priorities: "Priorities",
  gaps: "What we don't know",
}

export const KIND_LABELS: Record<ReportKind, string> = {
  exec_summary: "Executive summary",
  ma_brief: "M&A due-diligence brief",
}

export const SECTIONS_BY_KIND: Record<ReportKind, { key: Section; label: string }[]> = {
  exec_summary: SECTION_ORDER.map(key => ({ key, label: SECTION_LABELS[key] })),
  ma_brief: [
    { key: "family", label: "Corporate family" },
    { key: "acquisitions", label: "Acquisitions" },
    { key: "domains", label: "Domains" },
    { key: "exposure", label: "Exposure" },
    { key: "priorities", label: "Priorities" },
    { key: "gaps", label: "What we still don't know" },
  ],
}

export const reportsApi = {
  list: (engagementId: string) =>
    api.get<ReportListItem[]>(`/reports?engagement_id=${encodeURIComponent(engagementId)}`),
  get: (id: string) => api.get<Report>(`/reports/${encodeURIComponent(id)}`),
  create: (engagementId: string, kind: ReportKind = "exec_summary") =>
    api.post<ReportListItem>("/reports", { engagement_id: engagementId, kind }),
  remove: (id: string) => api.delete<void>(`/reports/${encodeURIComponent(id)}`),
}

export function markdownHref(id: string): string {
  return `/reports/${encodeURIComponent(id)}/markdown`
}

/** Fetch the markdown with the bearer token (a plain link cannot send it) and
 *  save it as `report-<id>.md`. */
export async function downloadMarkdown(id: string): Promise<void> {
  const blob = await api.getBlob(markdownHref(id))
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = `report-${id}.md`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

/** Mirrors the backend gate for generating and deleting reports. */
export function canGenerateReports(role: string | undefined): boolean {
  return role === "admin" || role === "report_admin"
}

/** Where a citation chip links, or null for no link. Metric: the metric's own
 *  query in Explore. Finding: its record page, only if the id is a uuid. */
export function citationHref(
  c: Citation,
  report: Pick<Report, "facts">,
): string | null {
  if (c.kind === "metric") {
    const m = c.ref ? report.facts?.metrics?.[c.ref] : undefined
    return m ? exploreHref(m.query as QueryObject) : null
  }
  if (c.kind === "finding" && c.ref) {
    const href = `/findings/${c.ref}`
    return isInternalHref(href) ? href : null
  }
  if (c.kind === "entity" && c.ref) {
    const href = entityHref(c.ref)
    return isInternalHref(href) ? href : null
  }
  return null
}

/** `org_entities.relationship` in words (the stored enum is not a label). */
export const RELATIONSHIP_LABELS: Record<string, string> = { ours: "ours", ma_target: "M&A target" }

/** Display text of one fact-list row (plain text; the view never renders it as markup). */
export function listRowText(key: string, row: ListRow): string {
  const paren = (v: string | null | undefined) => (v ? ` (${v})` : "")
  switch (key) {
    case "family": return `${row.name ?? ""}${paren(row.relationship ? RELATIONSHIP_LABELS[row.relationship] ?? row.relationship : null)}`
    case "acquisitions": return `${row.acquirer ?? ""} acquired ${row.acquired ?? ""}${paren(row.event_date)}`
    case "former_names": return row.name ?? ""
    case "domains": return `${row.domain ?? ""} (${row.entity_name ?? ""})`
    default:
      return Object.values(row).filter((v): v is string => v != null && v !== "").join(" · ")
  }
}

export function formatCount(m: Pick<Metric, "count" | "capped">): string {
  return m.count.toLocaleString("en-US") + (m.capped ? "+" : "")
}
