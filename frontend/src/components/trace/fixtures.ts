// Synthetic, typed fixtures for the trace tests. Invented names only.
import type {
  Attribution, AttributionChain, AttributionHop, ClaimEvidence, ExposureHop, ExposureHopCandidate,
  ExposurePath, RelationEvidence, SignalEvidence, TimelineEvent,
} from "@/lib/api"

const base = () => ({ reason: null, evidence: [], evidence_truncated: false, tier: null, first_seen_at: null, last_seen_at: null })

export const signal = (over: Partial<SignalEvidence> = {}): SignalEvidence => ({
  kind: "signal", signal_id: "sig-1", signal_type: "registrant_match", label: "Registrant match",
  source: "rdap", tier: "supporting", evidence_id: "doc-1", first_seen_at: null, last_seen_at: null, ...over,
})
export const relation = (over: Partial<RelationEvidence> = {}): RelationEvidence => ({
  kind: "relation", relation_id: "rel-1", relation: "acquired", source: "sec_filing", tier: "strong",
  event_date: null, event_date_precision: "unknown", evidence_id: "doc-2", confirmed_by: null, confirmed_at: null, ...over,
})
export const claim = (over: Partial<ClaimEvidence> = {}): ClaimEvidence => ({
  kind: "claim", claim_id: "clm-1", claim_type: "observation", source: "scanner", source_trust: "observed",
  tier: null, outcome: null, first_seen_at: null, last_seen_at: null, ...over,
})

export const orgHop = (over: Record<string, unknown> = {}): AttributionHop => ({
  ...base(), status: "observed", kind: "organization", entity_id: "ent-1", name: "Halvard Rhys Freight",
  relationship: "ours", marked_at: null, marked_by_id: null, marked_by_name: null, ...over,
}) as AttributionHop
export const scopeHop = (over: Record<string, unknown> = {}): AttributionHop => ({
  ...base(), status: "observed", kind: "scope", target_id: "tgt-1", target_type: "domain",
  value: "brightwatercold.example", candidate_id: null, claimed_at: null, claimed_by_id: null, claimed_by_name: null, ...over,
}) as AttributionHop
export const hostHop = (over: Record<string, unknown> = {}): AttributionHop => ({
  ...base(), status: "observed", kind: "host", asset_id: "ast-1", hostname: "dock.brightwatercold.example",
  candidates: [], candidates_truncated: false, ...over,
}) as AttributionHop
export const addrHop = (over: Record<string, unknown> = {}): AttributionHop => ({
  ...base(), status: "observed", kind: "address", asset_id: "ast-2", address: "203.0.113.47", ...over,
}) as AttributionHop

export const chain = (hops: AttributionHop[] = [orgHop(), scopeHop(), hostHop()]): AttributionChain => ({ target_id: "tgt-1", hops })

export const attribution = (over: Partial<Attribution> = {}): Attribution => ({
  ownership: { surface: "proven_ours", reason: null, evidence: [], tier: null },
  chains: [chain()], chains_truncated: false, ...over,
})

export const candidate = (over: Partial<ExposureHopCandidate> = {}): ExposureHopCandidate => ({
  asset_id: "cand-1", asset_type: "dns_record", value: "gate.brightwatercold.example", record_type: "A",
  distance: 1, link_first_seen_at: null, link_last_seen_at: null, ...over,
})

const xb = () => ({ reason: null, sources: [] as string[], first_seen_at: null, last_seen_at: null, status: "observed" })
export const exposureHops = (over: Partial<Record<ExposureHop["kind"], Record<string, unknown>>> = {}): ExposureHop[] => [
  { ...xb(), kind: "internet", ...over.internet },
  { ...xb(), kind: "host", asset_id: "ast-1", hostname: "dock.brightwatercold.example", candidates: [], candidates_truncated: false, ...over.host },
  { ...xb(), kind: "address", asset_id: "ast-2", address: "203.0.113.47", candidates: [], candidates_truncated: false, ...over.address },
  { ...xb(), kind: "port", port: 443, protocol: "tcp", ...over.port },
  { ...xb(), kind: "service", asset_id: null, service: "nginx", version: "1.24.0", protocol: null, ...over.service },
  { ...xb(), kind: "finding", finding_id: "fnd-1", finding_type: "exposed_panel", ...over.finding },
] as ExposureHop[]

export const path = (over: Partial<ExposurePath> = {}): ExposurePath => ({
  endpoint_id: "ep-1", observation: "current", first_seen_at: null, last_seen_at: null, hops: exposureHops(), ...over,
})

export const timelineEvent = (over: Partial<TimelineEvent> = {}): TimelineEvent => ({
  kind: "first_seen",
  date: "2026-11-09",
  precision: "day",
  at: null,
  source: null,
  entity_id: null,
  entity_name: null,
  acquirer_id: null,
  target_id: null,
  target_value: null,
  other_dates: [],
  ...over,
})
