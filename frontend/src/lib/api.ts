import { useAuthStore } from "@/lib/auth"

const BASE = "/api"

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const { tokens, clearAuth } = useAuthStore.getState()

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string>),
  }
  if (tokens?.access_token) {
    headers["Authorization"] = `Bearer ${tokens.access_token}`
  }

  let res = await fetch(`${BASE}${path}`, { ...init, headers })

  if (res.status === 401 && tokens?.refresh_token) {
    const refreshed = await tryRefresh(tokens.refresh_token)
    if (refreshed) {
      headers["Authorization"] = `Bearer ${refreshed}`
      res = await fetch(`${BASE}${path}`, { ...init, headers })
    } else {
      clearAuth()
      window.location.href = "/login"
      throw new Error("Session expired")
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }))
    throw new ApiError(res.status, body.detail ?? "Request failed")
  }

  if (res.status === 204) return undefined as T
  return res.json()
}

async function tryRefresh(refreshToken: string): Promise<string | null> {
  try {
    const res = await fetch(`${BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
    if (!res.ok) return null
    const data = await res.json()
    const { setTokens } = useAuthStore.getState()
    setTokens(data)
    return data.access_token
  } catch {
    return null
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: JSON.stringify(body) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
}

// ── Typed API helpers ──────────────────────────────────────────────────────────

export type User = {
  id: string
  email: string
  full_name: string
  role: string
  is_active: boolean
  created_at: string
  last_login_at: string | null
}

export type TokenResponse = {
  access_token: string
  refresh_token: string
  token_type: string
}

export type ConnectorSummary = {
  id: string
  name: string
  description: string
  phase: string
  enabled: boolean
  configured: boolean
  schema: Record<string, { label: string; type: string; help?: string; default?: unknown; options?: string[] }>
}

export type ScanScope = {
  domains: string[]
  ip_ranges: string[]
}

export type ScanRun = {
  id: string
  name: string | null
  status: "pending" | "running" | "completed" | "failed" | "cancelled"
  scope: ScanScope
  connectors_used: string[] | null
  created_at: string
  started_at: string | null
  completed_at: string | null
  error: string | null
  asset_count: number
  finding_count: number
}

export type AvailableDomain = {
  domain: string
  connector_id: string
  connector_name: string
}

export type Asset = {
  id: string
  scan_run_id: string
  asset_type: string
  value: string
  parent_value: string | null
  asset_metadata: Record<string, unknown>
  discovered_at: string
  ignored: boolean
}

export type Target = {
  id: string
  type: "domain" | "ip" | "cidr"
  value: string
  verified: boolean
  verification_method: string | null
  connector_id: string | null
  token: string
  whois_org: string | null
  whois_asn: string | null
  verified_at: string | null
  created_at: string
  notes: string | null
}

export type Finding = {
  id: string
  scan_run_id: string
  discovered_at: string
  asset_value: string
  finding_type: string
  source: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  description: string | null
  detail: Record<string, unknown> | null
  state: "open" | "acknowledged" | "suppressed" | "resolved"
  acknowledged_at: string | null
  suppressed_until: string | null
  category: string | null
  cve_id: string | null
  cvss_score: number | null
  cvss_vector: string | null
  epss_score: number | null
  epss_percentile: number | null
  kev: boolean | null
  kev_date_added: string | null
  cwe: string | null
}

export type SamlConfig = {
  id: string
  enabled: boolean
  metadata_url: string
  metadata_fetched_at: string | null
  sp_entity_id: string
  sp_acs_url: string
  jit_provisioning: boolean
  allow_local_fallback: boolean
}

export type IdpMetadataPreview = {
  entity_id: string
  sso_url: string
  certificate_subject: string | null
  valid: boolean
  error: string | null
}

export type SystemStatus = {
  first_run: boolean
  version: string
}
