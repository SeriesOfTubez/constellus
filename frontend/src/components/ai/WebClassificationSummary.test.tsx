import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { TooltipProvider } from "@/components/ui/tooltip"
import { WebClassificationSummary } from "@/components/ai/WebClassificationSummary"
import type { AiRow, WebEndpointState } from "@/lib/webClassification"

const XSS = "<img src=x onerror=alert(1)>"

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

const render = (s: WebEndpointState, compact = false) =>
  renderToStaticMarkup(<TooltipProvider><WebClassificationSummary state={s} compact={compact} /></TooltipProvider>)

const cite = (n: number) => Array.from({ length: n }, (_, i) => ({ source_field: `field${i}`, value: `val${i}` }))

describe("WebClassificationSummary", () => {
  it("renders model and page text escaped, never as markup", () => {
    const html = render(state({
      http_title: XSS,
      product: XSS,
      ai: ai({ evidence: [{ source_field: "http_title", value: XSS }], error: XSS }),
      last_failure: ai({ status: "failed", error: XSS, created_at: "2026-02-01T00:00:00Z" }),
    }))
    expect(html).toContain("&lt;img")
    expect(html).not.toContain("<img")
  })

  it("escapes the override reason", () => {
    const html = render(state({
      source: "user",
      override: {
        kind: "login_portal", environment: "production", reason: XSS, set_by: "Ada",
        set_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", ai_classification_id: null,
      },
    }))
    expect(html).toContain("Reason: ")
    expect(html).toContain("&lt;img")
    expect(html).not.toContain("<img")
  })

  it("shows citations for an AI classification", () => {
    const html = render(state({ ai: ai({ evidence: cite(1) }) }))
    expect(html).toContain("field0")
    expect(html).toContain("val0")
    expect(html).toContain("Inferred by AI")
  })

  it("collapses to +n in compact mode with 3+ citations", () => {
    const html = render(state({ ai: ai({ evidence: cite(4) }) }), true)
    expect(html).toContain("field0")
    expect(html).toContain("field1")
    expect(html).not.toContain("field2")
    expect(html).toContain("+2")
  })

  it("shows every citation when not compact", () => {
    const html = render(state({ ai: ai({ evidence: cite(4) }) }))
    expect(html).toContain("field3")
    expect(html).not.toContain("+2")
  })

  it("shows the product line only when product is non-null", () => {
    expect(render(state({ product: "Acme Gateway" }))).toContain("Product (AI guess): Acme Gateway")
    expect(render(state({ product: null }))).not.toContain("Product (AI guess)")
  })

  it("reads none as Unclassified with no badge", () => {
    const html = render(state({ source: "none", kind: null, environment: null, ai: null }))
    expect(html).toContain("Unclassified")
    expect(html).not.toContain("Inferred by AI")
    expect(html).not.toContain("Set by")
    expect(html).not.toContain("Unknown")
  })

  it("omits an unknown environment", () => {
    const html = render(state({ environment: "unknown" }))
    expect(html).not.toContain("Unknown environment")
  })
})
