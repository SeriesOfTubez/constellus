import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import type { ClusterWriteup, ClusterWriteupState } from "@/lib/api"
import { clusterWriteupPath } from "@/lib/api"
import { ClusterWriteupBody } from "@/components/ClusterWriteupPanel"
import { ClusterWriteupsCard } from "@/pages/admin/AiModels"
import { DigestBodyView } from "@/components/DigestHistoryList"

function wu(over: Partial<ClusterWriteup> = {}): ClusterWriteup {
  return {
    id: "w1", created_at: "2026-10-01T00:00:00Z", finished_at: "2026-10-01T00:00:05Z",
    model: "vendor/model-a", summary: "Three hosts expose the same admin panel.",
    context: [{ statement: "Panel is reachable from the internet.", source_field: "findings.evidence.url", value: "https://app.fabrikam.com/admin" }],
    fix_steps: ["Restrict the panel to a VPN."], priority_note: "Fix the 203.0.113.10 host first.",
    statements_returned: 3, statements_dropped: 1, summary_dropped: false, priority_note_dropped: false,
    forced_strict: false, cost_usd: 0.0123, finding_count: 4, asset_count: 3, max_severity: "high", auto: false, ...over,
  }
}
function state(over: Partial<ClusterWriteupState> = {}): ClusterWriteupState {
  return {
    eligible: true, ineligible_reason: null, mode: "on_demand", writeup: null, hidden: false,
    inputs_changed: null, pending: null, last_failure: null, ...over,
  }
}
const noop = () => {}
const body = (d: ClusterWriteupState, canGenerate = true) => renderToStaticMarkup(
  <ClusterWriteupBody data={d} canGenerate={canGenerate} busy={false} onGenerate={noop} assetCount={3} />,
)
const GEN = "Write up this issue with AI"

describe("ClusterWriteupBody", () => {
  it("eligible, no write-up: admin sees the button and the coverage note", () => {
    const html = body(state())
    expect(html).toContain(GEN)
    expect(html).toContain("all 3 assets")
  })
  it("non-admin sees no button", () => {
    const html = body(state(), false)
    expect(html).not.toContain(GEN)
    expect(html).toContain("An admin can generate")
  })
  it("pending shows progress and no generate button", () => {
    const html = body(state({ pending: { id: "p", status: "running", created_at: "2026-10-01T00:00:00Z" } }))
    expect(html).toContain("Generating")
    expect(html).not.toContain(GEN)
  })
  it("failure shows the error and Retry", () => {
    const html = body(state({ last_failure: { error: "model timed out", finished_at: null } }))
    expect(html).toContain("model timed out")
    expect(html).toContain("Retry")
  })
  it("write-up renders summary, context with source, guidance, priority, meta", () => {
    const html = body(state({ writeup: wu() }))
    expect(html).toContain("AI-generated")
    expect(html).toContain("Three hosts expose the same admin panel.")
    expect(html).toContain("source: findings.evidence.url")
    expect(html).toContain("General guidance")
    expect(html).toContain("Restrict the panel to a VPN.")
    expect(html).toContain("Fix the 203.0.113.10 host first.")
    expect(html).toContain("Generated on demand")
    expect(html).toContain("vendor/model-a")
    expect(html).toContain("covers 3 assets, 4 findings")
    expect(html).toContain("$0.0123")
    expect(html).toContain("1 of 3 statements dropped")
    expect(html).not.toContain("Strict data policy")
    expect(html).not.toContain(GEN)
    expect(html).not.toContain("Regenerate")
  })
  it("auto and forced_strict are labelled", () => {
    const html = body(state({ writeup: wu({ auto: true, forced_strict: true }) }))
    expect(html).toContain("Generated automatically")
    expect(html).toContain("Strict data policy")
  })
  it("summary withheld note", () => {
    const html = body(state({ writeup: wu({ summary: null, summary_dropped: true }) }))
    expect(html).toContain("Summary withheld: it named an asset outside this issue")
  })
  it("model text is escaped, not rendered", () => {
    const html = body(state({ writeup: wu({ summary: "<img src=x onerror=alert(1)> [x](http://evil)" }) }))
    expect(html).not.toContain("<img")
    expect(html).not.toContain("<a ")
  })
  it("inputs_changed shows amber notice and Regenerate for admin only", () => {
    const d = state({ writeup: wu(), inputs_changed: true })
    expect(body(d)).toContain("Membership changed since this write-up")
    expect(body(d)).toContain("Regenerate")
    expect(body(d, false)).toContain("Membership changed since this write-up")
    expect(body(d, false)).not.toContain("Regenerate")
  })
  it("hidden shows the message and no button", () => {
    const html = body(state({ hidden: true, writeup: null }))
    expect(html).toContain("A write-up exists but covers findings you can&#x27;t view.")
    expect(html).not.toContain(GEN)
  })
  it("ineligible shows the reason", () => {
    const html = body(state({ eligible: false, ineligible_reason: "Only High and Critical issues." }))
    expect(html).toContain("Only High and Critical issues.")
    expect(html).not.toContain(GEN)
  })
})

describe("clusterWriteupPath", () => {
  it("encodes a fingerprint with &, # and spaces", () => {
    const fp = "a&b#c d=e"
    const path = clusterWriteupPath({ finding_type: "exposure", source: "nuclei", fingerprint: fp })
    expect(path).not.toContain("#")
    expect(path).not.toContain(" ")
    const q = new URLSearchParams(path.split("?")[1])
    expect(q.get("fingerprint")).toBe(fp)
    expect([...q.keys()]).toEqual(["finding_type", "source", "fingerprint"])
  })
  it("adds force only when given", () => {
    const k = { finding_type: "t", source: "s", fingerprint: "f" }
    expect(clusterWriteupPath(k)).not.toContain("force")
    expect(clusterWriteupPath(k, true)).toContain("force=true")
    expect(clusterWriteupPath(k, false)).toContain("force=false")
  })
})

const wrap = (ui: React.ReactNode) => renderToStaticMarkup(
  <QueryClientProvider client={new QueryClient()}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>,
)

describe("ClusterWriteupsCard", () => {
  it("renders the three mode labels and today / cap", () => {
    const html = wrap(<ClusterWriteupsCard cw={{ mode: "auto_high", daily_cap: 25, today: 4 }} />)
    expect(html).toContain("AI cluster write-ups")
    expect(html).toContain("On demand only")
    expect(html).toContain("Automatic for High and Critical")
    expect(html).toContain("Automatic, and included in digests")
    expect(html).toContain("4 / 25")
  })
  it("on_demand notes the cap is unused", () => {
    // Initial state is on_demand until the effect syncs, which does not run in static render.
    expect(wrap(<ClusterWriteupsCard cw={{ mode: "on_demand", daily_cap: 0, today: 0 }} />))
      .toContain("only used in automatic modes")
  })
  it("shows a skeleton before status loads", () => {
    expect(wrap(<ClusterWriteupsCard cw={undefined} />)).not.toContain("AI cluster write-ups")
  })
})

describe("DigestBodyView cluster write-up line", () => {
  const detail = (writeup?: object) => ({
    id: "g1", rule_id: "r1", rule_name: "Fabrikam daily",
    period_start: "2026-01-01T00:00:00Z", period_end: "2026-01-02T00:00:00Z",
    event_count: 1, finding_count: 2, outcome: "sent", narrative_status: null, narrative_reason: null,
    deliveries: [], created_at: "2026-01-02T00:00:00Z", sent_at: null,
    body: {
      rule: { id: "r1", name: "x", severity_threshold: "high" },
      period: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" },
      totals: { events: 1, findings: 2, assets: 2, new: 1, promotions: 0, by_severity: { critical: 0, high: 2, medium: 0, low: 0, info: 0 } },
      groups: [{ kind: "cluster", label: "Exposed panel", finding_count: 2, asset_count: 2, max_severity: "high", key: "k", items: [], ...(writeup ? { writeup } : {}) }],
      listed_findings: 0, omitted_findings: 0,
    },
    narrative: null,
  }) as unknown as Parameters<typeof DigestBodyView>[0]["detail"]

  it("renders the line, with inputs-changed marker", () => {
    const w = { id: "w", summary: "Same panel on two hosts.", written_at: "2026-01-01T12:00:00Z", asset_count: 2, finding_count: 2, inputs_changed: true }
    const html = wrap(<DigestBodyView detail={detail(w)} />)
    expect(html).toContain("AI write-up of this issue across 2 assets")
    expect(html).toContain("inputs changed since")
    expect(html).toContain("Same panel on two hosts.")
    expect(wrap(<DigestBodyView detail={detail({ ...w, inputs_changed: false })} />)).not.toContain("inputs changed since")
  })
  it("omits it when absent", () => {
    expect(wrap(<DigestBodyView detail={detail()} />)).not.toContain("AI write-up of this issue")
  })
})
