// planning#231 — web endpoint classification: types and pure helpers.
//
// The AI's classification of a web endpoint is APPLIED and shown as inferred;
// admins correct it. Nothing here treats the AI value as a proposal.

export type Kind =
  | "login_portal" | "admin_panel" | "default_install" | "parked"
  | "marketing_site" | "api" | "application" | "unknown"
export type Env = "production" | "non_production" | "unknown"

export interface Citation {
  source_field: string
  value: string
}

export interface AiRow {
  id: string
  port: number
  status: "queued" | "running" | "succeeded" | "failed"
  kind: Kind | null
  environment: Env | null
  product: string | null
  product_source_field: string | null
  evidence: Citation[]
  citations_dropped: number | null
  product_dropped: boolean | null
  downgraded: boolean | null
  model: string | null
  forced_strict: boolean | null
  error: string | null
  requested_by_id: string | null
  created_at: string
  finished_at: string | null
  cost_usd: number | null
}

export interface Override {
  kind: Kind
  environment: Env
  reason: string | null
  set_by: string | null
  set_at: string
  updated_at: string
  ai_classification_id: string | null
}

export interface WebEndpointState {
  port: number
  kind: Kind | null
  environment: Env | null
  product: string | null
  source: "ai" | "user" | "none"
  http_title: string | null
  http_status: number | null
  service: string | null
  ai: AiRow | null
  override: Override | null
  active: AiRow | null
  last_failure: AiRow | null
  ai_inputs_changed: boolean | null
  override_stale: boolean | null
  ai_suggests: { kind: Kind; environment: Env } | null
  // list endpoint only
  asset_id?: string
  asset_value?: string
  asset_type?: string
}

export const KIND_LABELS: Record<Kind, string> = {
  login_portal: "Login portal",
  admin_panel: "Admin panel",
  default_install: "Default install page",
  parked: "Parked domain",
  marketing_site: "Marketing site",
  api: "API",
  application: "Application",
  unknown: "Unknown",
}

export const ENV_LABELS: Record<Env, string> = {
  production: "Production",
  non_production: "Non-production",
  unknown: "Unknown environment",
}

export const KINDS: Kind[] = [
  "login_portal", "admin_panel", "default_install", "parked",
  "marketing_site", "api", "application", "unknown",
]
export const ENVS: Env[] = ["production", "non_production", "unknown"]

/** "none" is Unclassified, never "Unknown" (Unknown is a real AI/admin verdict). */
export function effectiveLabel(s: WebEndpointState): string {
  if (s.source === "none" || !s.kind) return "Unclassified"
  return KIND_LABELS[s.kind]
}

export function isInputBlocked(row: AiRow | null | undefined): boolean {
  return !!row?.error && row.error.includes("blocked this input")
}

export type EndpointFlag = { key: string; text: string; tone: "muted" | "warn" }

export function endpointFlags(s: WebEndpointState): EndpointFlag[] {
  const flags: EndpointFlag[] = []
  if (s.active) flags.push({ key: "running", text: "Classifying…", tone: "muted" })
  if (s.source === "user" && s.override_stale) {
    flags.push({ key: "stale", text: "Inputs changed since this was set", tone: "warn" })
  }
  if (s.ai_suggests) {
    flags.push({
      key: "suggests",
      text: `AI now suggests ${KIND_LABELS[s.ai_suggests.kind]} · ${ENV_LABELS[s.ai_suggests.environment]}`,
      tone: "warn",
    })
  }
  if (s.source === "ai" && s.ai_inputs_changed) {
    flags.push({ key: "changed", text: "Signals changed since the AI classified this", tone: "muted" })
  }
  if (s.source === "none" && s.ai?.downgraded) {
    flags.push({ key: "downgraded", text: "AI cited no evidence, so it is left unclassified", tone: "muted" })
  }
  const f = s.last_failure
  if (f) {
    const newer = !s.ai || new Date(f.created_at).getTime() > new Date(s.ai.created_at).getTime()
    if (newer) {
      if (isInputBlocked(f)) {
        flags.push({ key: "failure", text: `Not classified: ${f.error}`, tone: "muted" })
      } else {
        flags.push({ key: "failure", text: `Last classification failed: ${f.error ?? "unknown error"}`, tone: "warn" })
      }
    }
  }
  return flags
}

/** Stable id for list rows (useFlyout needs an `id`). */
export function endpointKey(s: WebEndpointState): string {
  return `${s.asset_id}:${s.port}`
}
