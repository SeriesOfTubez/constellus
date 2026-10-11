import { describe, expect, it } from "vitest"
import {
  effectiveLabel, endpointFlags, endpointKey, isInputBlocked,
  type AiRow, type WebEndpointState,
} from "@/lib/webClassification"

function ai(over: Partial<AiRow> = {}): AiRow {
  return {
    id: "a1", port: 443, status: "succeeded", kind: "login_portal", environment: "production",
    product: null, product_source_field: null, evidence: [], citations_dropped: null,
    product_dropped: null, downgraded: null, model: "m", forced_strict: null, error: null,
    requested_by_id: null, created_at: "2026-01-02T00:00:00Z", finished_at: null, cost_usd: null,
    ...over,
  }
}

function state(over: Partial<WebEndpointState> = {}): WebEndpointState {
  return {
    port: 443, kind: "login_portal", environment: "production", product: null, source: "ai",
    http_title: null, http_status: null, service: null, ai: ai(), override: null, active: null,
    last_failure: null, ai_inputs_changed: null, override_stale: null, ai_suggests: null,
    ...over,
  }
}

describe("effectiveLabel", () => {
  it("reads none as Unclassified even when kind is unknown", () => {
    expect(effectiveLabel(state({ source: "none", kind: "unknown" }))).toBe("Unclassified")
    expect(effectiveLabel(state({ source: "none", kind: null }))).toBe("Unclassified")
  })
  it("keeps Unknown for a real unknown verdict", () => {
    expect(effectiveLabel(state({ source: "ai", kind: "unknown" }))).toBe("Unknown")
  })
  it("labels the kind", () => {
    expect(effectiveLabel(state({ kind: "default_install" }))).toBe("Default install page")
  })
})

describe("isInputBlocked", () => {
  it("matches only the blocked-input error", () => {
    expect(isInputBlocked(ai({ error: "The guard blocked this input" }))).toBe(true)
    expect(isInputBlocked(ai({ error: "timeout" }))).toBe(false)
    expect(isInputBlocked(null)).toBe(false)
  })
})

describe("endpointFlags", () => {
  it("is empty for a clean AI classification", () => {
    expect(endpointFlags(state())).toEqual([])
  })
  it("flags a running classification", () => {
    expect(endpointFlags(state({ active: ai({ status: "running" }) })))
      .toEqual([{ key: "running", text: "Classifying…", tone: "muted" }])
  })
  it("flags a stale override only for source user", () => {
    expect(endpointFlags(state({ source: "user", override_stale: true })).map(f => f.text))
      .toEqual(["Inputs changed since this was set"])
    expect(endpointFlags(state({ source: "ai", override_stale: true }))).toEqual([])
  })
  it("renders what the AI now suggests as a warning", () => {
    const f = endpointFlags(state({ source: "user", ai_suggests: { kind: "admin_panel", environment: "non_production" } }))
    expect(f).toEqual([{ key: "suggests", text: "AI now suggests Admin panel · Non-production", tone: "warn" }])
  })
  it("flags changed signals only for source ai", () => {
    expect(endpointFlags(state({ source: "ai", ai_inputs_changed: true })).map(f => f.text))
      .toEqual(["Signals changed since the AI classified this"])
    expect(endpointFlags(state({ source: "user", ai_inputs_changed: true }))).toEqual([])
  })
  it("flags a downgrade only when unclassified", () => {
    expect(endpointFlags(state({ source: "none", kind: null, ai: ai({ downgraded: true }) })).map(f => f.text))
      .toEqual(["AI cited no evidence, so it is left unclassified"])
    expect(endpointFlags(state({ source: "ai", ai: ai({ downgraded: true }) }))).toEqual([])
  })
  it("renders an InputBlocked failure as a muted note", () => {
    const f = endpointFlags(state({
      source: "none", ai: null,
      last_failure: ai({ status: "failed", error: "Guard blocked this input" }),
    }))
    expect(f).toEqual([{ key: "failure", text: "Not classified: Guard blocked this input", tone: "muted" }])
  })
  it("renders another failure as an amber warning", () => {
    const f = endpointFlags(state({
      source: "none", ai: null,
      last_failure: ai({ status: "failed", error: "provider timeout" }),
    }))
    expect(f).toEqual([{ key: "failure", text: "Last classification failed: provider timeout", tone: "warn" }])
  })
  it("hides a failure older than the AI row", () => {
    const f = endpointFlags(state({
      ai: ai({ created_at: "2026-01-05T00:00:00Z" }),
      last_failure: ai({ status: "failed", error: "provider timeout", created_at: "2026-01-01T00:00:00Z" }),
    }))
    expect(f).toEqual([])
  })
  it("shows a failure newer than the AI row", () => {
    const f = endpointFlags(state({
      ai: ai({ created_at: "2026-01-01T00:00:00Z" }),
      last_failure: ai({ status: "failed", error: "provider timeout", created_at: "2026-01-05T00:00:00Z" }),
    }))
    expect(f.map(x => x.key)).toEqual(["failure"])
  })
})

describe("endpointKey", () => {
  it("joins asset and port", () => {
    expect(endpointKey(state({ asset_id: "abc" }))).toBe("abc:443")
  })
})
