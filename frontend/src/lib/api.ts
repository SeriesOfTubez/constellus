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
  delete: <T>(path: string, body?: unknown) =>
    request<T>(path, body !== undefined ? { method: "DELETE", body: JSON.stringify(body) } : { method: "DELETE" }),
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
  config_schema: Record<string, { label: string; type: string; help?: string; default?: unknown; options?: string[] }>
  core: boolean
  disabled_at_current_tier: boolean
  current_tier: string | null
}

export type ScanScope = {
  domains: string[]
  ip_ranges: string[]
}

export type ScanKind = "monitoring" | "initial_discovery" | "recheck" | "manual"

export type ScanRun = {
  id: string
  name: string | null
  status: "pending" | "running" | "completed" | "failed" | "cancelled"
  kind: ScanKind
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

export type WhoisInfo = {
  ip: string
  org: string | null
  asn: string | null
  looked_up_at: string | null
  public: boolean
}

export type DomainWhoisInfo = {
  domain: string
  registrar: string | null
  registrant_org: string | null
  registrant_country: string | null
  creation_date: string | null
  expiration_date: string | null
  updated_date: string | null
  name_servers: string[]
  status: string[]
  dnssec: string | null
  looked_up_at: string | null
}

export type Asset = {
  id: string
  asset_type: string
  value: string
  parent_value: string | null
  asset_metadata: Record<string, unknown>
  first_seen_at: string
  last_seen_at: string
  ignored: boolean
  tags: string[]
  worst_severity: "critical" | "high" | "medium" | "low" | "info" | null
  // Worst-driven Risk Score rollup — the asset's single worst open finding.
  risk_score: number | null
  risk_band: "imminent_compromise" | "high" | "elevated" | "low" | "secure" | null
}

export type SecurityScore = {
  score: number
  band: "imminent_compromise" | "high" | "elevated" | "low" | "secure"
  worst_band_count: number
  worst_band_count_prev: number
  worst_band_new: number
  worst_band_resolved: number
  breakdown: {
    id: string
    title: string
    asset_value: string | null
    risk_score: number | null
    severity: "critical" | "high" | "medium" | "low" | "info"
    building_velocity: boolean | null
  }[]
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
  tags: string[]
  aggressiveness: AggressivenessTier | null
  effective_aggressiveness: AggressivenessTier
  last_scanned_at: string | null
  next_scan_at: string | null
}

// Shared-infra verification evidence bundle (migrations 0036/0037, epic#81
// Phases A/D). Shape mirrors services/shared_infra_verifier.py's
// verification_evidence — all fields optional since which ones are present
// depends on which verdict fired.
export type VerificationEvidence = {
  ip?: string
  reason?: string
  hostnames?: Record<string, { verdict: string; signals: string[] }>
  hosting_class?: { company_name: string | null; asn: number | null }
  corroboration?: {
    origin_serves_others: boolean
    corroborating_hostname: string | null
    evidence: "tls_san_match" | "http_2xx" | null
    hostnames_probed: string[]
  }
  tech_absence?: {
    cve_product: string
    checked_ports: string[]
    tech_observed: string[]
    expected_tech_absent: boolean
    state_affecting: boolean
  }
} | null

export type Finding = {
  id: string
  asset_value: string
  asset_parent_value: string | null
  asset_canonical_id: string
  finding_type: string
  source: string
  // Read-time CVE rollup (#66 D3, backend _rollup_cve_findings): every source
  // that contributed to this logical finding, the strongest confidence across
  // them, the version_match-supplied fixed version, and the constituent ids.
  sources?: string[]
  confidence?: "confirmed" | "potential"
  fixed_version?: string | null
  rolled_up_ids?: string[]
  fingerprint: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  title: string
  description: string | null
  detail: Record<string, unknown> | null
  state: "open" | "acknowledged" | "suppressed" | "resolved"
  acknowledged_at: string | null
  suppressed_until: string | null
  // Shared-infra verification (migrations 0036/0037, epic#81 Phases A/D).
  verification: "unverified" | "confirmed_ours" | "rejected_shared_infra" | "ownership_unverifiable" | null
  verification_evidence: VerificationEvidence
  verified_at: string | null
  category: string | null
  cve_id: string | null
  cvss_score: number | null
  cvss_vector: string | null
  cvss_version: string | null
  epss_score: number | null
  epss_percentile: number | null
  kev: boolean | null
  kev_date_added: string | null
  cwe: string | null
  // Constellus Risk Score
  risk_score: number | null
  risk_band: "imminent_compromise" | "high" | "elevated" | "low" | "secure" | null
  building_velocity: boolean | null
  impact_class: "rce" | "data_exposure" | "denial_of_service" | "tampering" | "other" | null
  exploit_types: string[]
  // SSVC (CISA Vulnrichment or derived CVSS-vector fallback; ssvc_source distinguishes)
  ssvc_exploitation: "none" | "poc" | "active" | null
  ssvc_automatable: boolean | null
  ssvc_technical_impact: "total" | "partial" | null
  ssvc_source: "vulnrichment" | "derived" | null
  ssvc_scored_at: string | null
  vulncheck_kev: boolean | null
  has_exploit: boolean | null
  exploit_count: number | null
  ransomware_use: boolean | null
  canary_detected: boolean | null
  is_template: boolean | null
  is_poc: boolean | null
  tags: string[]
  first_seen_at: string
  last_seen_at: string
  resolved_at: string | null
  // BOD-26-04 remediation SLA lens (compliance deadline, separate from Risk Score)
  bod_sla: {
    window: "3d" | "3d+triage" | "14d" | "60d" | "upgrade"
    forensic_triage: boolean
    due_date: string | null
    days_remaining: number | null
    overdue: boolean
  } | null
}

export type ScanTemplate = {
  id: string
  name: string
  scope: ScanScope
  options: Record<string, unknown>
  schedule_cron: string | null
  enabled: boolean
  tags: string[]
  created_at: string | null
  created_by_id: string | null
}

export type ZoneEntry = {
  name: string
  excluded: boolean
}

export type TagRule = {
  id: string
  name: string
  entity_type: "target" | "asset" | "finding"
  condition: Record<string, unknown>
  tag: string
  enabled: boolean
  created_at: string
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

// ── Edges (Connected Entities panel) ─────────────────────────────────────────

export type EdgeNodeType = "asset_canonical" | "finding_canonical" | "target" | "whois_org"

export type EdgeNode = {
  node_type: EdgeNodeType
  node_id: string
  value: string
  label: string
  edge_metadata: Record<string, unknown>
  // asset_canonical
  asset_type?: string
  ignored?: boolean
  metadata?: Record<string, unknown>
  // finding_canonical
  severity?: "critical" | "high" | "medium" | "low" | "info"
  state?: "open" | "acknowledged" | "suppressed" | "resolved"
  category?: string | null
  cve_id?: string | null
  kev?: boolean | null
  // target
  target_type?: "domain" | "ip" | "cidr"
  verified?: boolean
}

export type EdgeGroup = {
  edge_type: string
  direction: "in" | "out" | "lateral"
  verb: string
  total: number
  items: EdgeNode[]
}

export type EdgesResponse = {
  groups: EdgeGroup[]
}

export type AggressivenessTier = "stealth" | "polite" | "standard" | "aggressive"

export type AppSettings = {
  scan_authorisation_mode: "strict" | "acknowledge" | "disabled"
  aggressiveness: AggressivenessTier
  org_name: string
  org_logo_url: string | null
  org_brand_accent: string
  org_name_color: string | null
}

export type EpssHistoryPoint = {
  week_start: string
  epss_score: number
  epss_percentile: number
}

export type EpssHistoryData = {
  cve_id: string
  current_score: number | null
  current_percentile: number | null
  delta: number | null
  score_changed_date: string | null
  history: EpssHistoryPoint[]
}
