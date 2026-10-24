import type { ConnectorInstanceSummary, ConnectorTypeSummary } from "@/lib/api"

export const inst = (over: Partial<ConnectorInstanceSummary> = {}): ConnectorInstanceSummary => ({
  id: "i1", type: "cloudflare", name: "Example Holdings A", enabled: true, configured: true,
  bound_entity_id: "o1", bound_entity_name: "Example Holdings A", binding_ok: true,
  created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", ...over,
})
export const typ = (over: Partial<ConnectorTypeSummary> = {}): ConnectorTypeSummary => ({
  id: "cloudflare", name: "Cloudflare", description: "DNS zones", phase: "discovery", config_schema: {},
  core: false, disabled_at_current_tier: false, current_tier: null, account_scoped: true, multi_instance: true, supports_zones: true,
  instances: [], ...over,
})
