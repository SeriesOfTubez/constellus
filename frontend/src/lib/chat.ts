/**
 * Chat assistant: types, API calls and the pure display rules (planning#228 slice 2).
 *
 * Nothing in the code is named after the assistant. Its display name is this
 * ONE constant, which mirrors `ASSISTANT_NAME` in backend `services/chat.py`.
 * Components read it from here and never spell it themselves.
 */
import { api, ApiError } from "@/lib/api"

export const ASSISTANT_NAME = "Perseus"

// ── wire types (backend services/chat.py message_out / list_conversations) ────

export type StopReason = "answered" | "round_limit" | "tool_call_limit" | "token_limit" | "spend_limit" | "error"

/** One tool call. `run_query` entries carry the query and its exact count;
 *  a failed call carries `error` instead. */
export interface ToolTraceEntry {
  tool: string
  error?: string
  query?: QueryObject
  count?: number
  count_capped?: boolean
  rows_shown?: number
}

export interface ChatMessage {
  id: string
  seq: number
  role: "user" | "assistant"
  content: string
  created_at: string
  // assistant messages only
  stop_reason?: StopReason
  model?: string | null
  tool_trace?: ToolTraceEntry[]
  queries?: QueryObject[]
  unverified_numbers?: number[]
  sanitised?: Record<string, number>
  tool_calls?: number
  cost_usd?: string
}

export interface ConversationSummary {
  id: string
  title: string
  created_at: string
  updated_at: string
}

export interface Conversation extends ConversationSummary {
  messages: ChatMessage[]
}

export interface AskResponse {
  conversation_id: string
  message: ChatMessage
}

// The typed query object (backend services/query_schema.py, version 1). Only
// what the summary reads is typed; the object itself is passed through as-is.
export type QueryNode =
  | { all: QueryNode[] }
  | { any: QueryNode[] }
  | { not: QueryNode }
  | { exists: { relation: string; where?: QueryNode } }
  | { field: string; op: string; value?: unknown }

export interface QueryObject {
  version?: number
  entity: string
  where?: QueryNode
  [key: string]: unknown
}

export interface QueryRowsResponse {
  entity: string
  columns: string[]
  rows: Record<string, unknown>[]
  row_count: number
  truncated: boolean
}

export interface QueryCountResponse {
  entity: string
  count: number
  capped: boolean
}

export const chatApi = {
  list: () => api.get<ConversationSummary[]>("/chat/conversations"),
  get: (id: string) => api.get<Conversation>(`/chat/conversations/${encodeURIComponent(id)}`),
  start: (question: string) => api.post<AskResponse>("/chat/conversations", { question }),
  ask: (id: string, question: string) =>
    api.post<AskResponse>(`/chat/conversations/${encodeURIComponent(id)}/messages`, { question }),
  remove: (id: string) => api.delete<void>(`/chat/conversations/${encodeURIComponent(id)}`),
}

export const MAX_QUESTION_CHARS = 2000  // backend chat.MAX_QUESTION_CHARS

// ── display rules ─────────────────────────────────────────────────────────────

/** The count shown next to a query. It always comes from `tool_trace`, never
 *  from the answer's prose. A capped count means "more than", so it reads
 *  "10,000+". */
export function formatCount(count: number, capped: boolean): string {
  return count.toLocaleString("en-US") + (capped ? "+" : "")
}

// Failed calls (invalid query, tool-call limit) have no count and are left out.
export interface CountedQuery {
  query: QueryObject
  count: number
  count_capped: boolean
  /** How many times this identical query ran in the answer. */
  times: number
}

/** The run_query calls that produced a count, in the order they first ran.
 *  An identical query run again (same object, same count) is one row with
 *  `times`, so a looping model doesn't bury the answer under copies. */
export function countedQueries(trace: ToolTraceEntry[] | undefined): CountedQuery[] {
  const out = new Map<string, CountedQuery>()
  for (const t of trace ?? []) {
    if (t.tool !== "run_query" || t.error || !t.query || typeof t.count !== "number") continue
    const capped = t.count_capped === true
    const key = JSON.stringify([t.query, t.count, capped])
    const seen = out.get(key)
    if (seen) seen.times += 1
    else out.set(key, { query: t.query, count: t.count, count_capped: capped, times: 1 })
  }
  return [...out.values()]
}

const OP_SYMBOL: Record<string, string> = {
  eq: "=", ne: "≠", gt: ">", gte: "≥", lt: "<", lte: "≤",
  in: "in", not_in: "not in", contains: "contains", starts_with: "starts with",
  has: "has", is_null: "is empty", is_empty: "is empty",
}

function valueText(v: unknown): string {
  if (Array.isArray(v)) return v.length <= 3 ? `[${v.map(valueText).join(", ")}]` : `[${v.slice(0, 2).map(valueText).join(", ")}, +${v.length - 2}]`
  if (typeof v === "string") return v
  return JSON.stringify(v)
}

function nodeText(n: QueryNode): string {
  if ("field" in n) {
    if (n.op === "is_null" || n.op === "is_empty") return `${n.field} ${n.value === false ? "is set" : "is empty"}`
    return `${n.field} ${OP_SYMBOL[n.op] ?? n.op} ${valueText(n.value)}`
  }
  if ("exists" in n) {
    const inner = n.exists.where ? conditions(n.exists.where) : []
    return inner.length ? `${n.exists.relation} where ${inner[0]}${inner.length > 1 ? ` +${inner.length - 1}` : ""}` : `has ${n.exists.relation}`
  }
  if ("not" in n) return `not (${nodeText(n.not)})`
  if ("any" in n) return n.any.length === 1 ? nodeText(n.any[0]) : `any of ${n.any.length}`
  return conditions(n).join(" and ")
}

function conditions(n: QueryNode): string[] {
  return "all" in n ? n.all.map(nodeText) : [nodeText(n)]
}

const ENTITY_PLURAL: Record<string, string> = { asset: "assets", finding: "findings" }

/** A one-line summary of a query object: entity, the first two conditions,
 *  then `+n` for the rest. It is a label only; the full object is in the
 *  tooltip and in Explore. */
export function summariseQuery(q: QueryObject): string {
  const entity = ENTITY_PLURAL[q.entity] ?? q.entity
  const conds = q.where ? conditions(q.where) : []
  if (!conds.length) return entity
  const shown = conds.slice(0, 2).join(", ")
  return `${entity} · ${shown}${conds.length > 2 ? ` +${conds.length - 2}` : ""}`
}

// ── links ─────────────────────────────────────────────────────────────────────

const INTERNAL_HREF = /^\/(assets|findings|entities)\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** The only links an answer may render: a record page by id. Everything else
 *  (external URLs, autolinks, `www.` literals, `javascript:`, anchors) is
 *  shown as plain text. This is the second layer behind the server sanitiser. */
export function isInternalHref(href: unknown): href is string {
  return typeof href === "string" && INTERNAL_HREF.test(href)
}

/** "Open in Explore": the query object rides in the URL. The link carries no
 *  data; Explore runs the query as whoever opens it. */
export function exploreHref(q: QueryObject): string {
  return `/explore?q=${encodeURIComponent(JSON.stringify(q))}`
}

/** Parse Explore's `q` parameter. Returns null when it is absent or is not a
 *  JSON object; the backend validator decides everything else. */
export function parseExploreParam(raw: string | null): QueryObject | null {
  if (!raw) return null
  try {
    const v: unknown = JSON.parse(raw)
    return v && typeof v === "object" && !Array.isArray(v) ? (v as QueryObject) : null
  } catch {
    return null
  }
}

// ── notices ───────────────────────────────────────────────────────────────────

/** One sentence per stop reason other than `answered`. */
export const STOP_NOTICES: Record<Exclude<StopReason, "answered">, string> = {
  round_limit: "Stopped early: reached the lookup limit for one question. The answer may be incomplete.",
  tool_call_limit: "Stopped early: reached the lookup limit for one question. The answer may be incomplete.",
  token_limit: "Stopped early: this question used up its token allowance. The answer may be incomplete.",
  spend_limit: "This conversation reached its spending limit. Start a new conversation to continue.",
  error: "The AI model failed partway through. The answer may be incomplete.",
}

export function stopNotice(reason: StopReason | undefined): string | null {
  if (!reason || reason === "answered") return null
  return STOP_NOTICES[reason] ?? "Stopped early. The answer may be incomplete."
}

/** Why a question was not answered, in plain language. */
export function askErrorReason(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.status) {
      case 404: return "This conversation no longer exists."
      case 409: return err.message || "This conversation reached its limit. Start a new one."
      case 422: return err.message || "The question is not valid."
      case 429: return "The AI budget or rate limit is reached. Try again later."
      case 502: return "The AI model failed. Try again."
      case 503: return "AI is not configured. An admin can set it up under Admin → AI models."
    }
    return err.message || "The request failed."
  }
  return "The request failed. Check your connection and try again."
}
