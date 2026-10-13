import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import type { DigestDetail, DigestOutcome, DigestSummary } from "@/lib/api"
import { DigestBodyView, DigestHistoryList } from "@/components/DigestHistoryList"

function summary(over: Partial<DigestSummary> = {}): DigestSummary {
  return {
    id: "g1", rule_id: "r1", rule_name: "Fabrikam daily",
    period_start: "2026-01-01T00:00:00Z", period_end: "2026-01-02T00:00:00Z",
    event_count: 4, finding_count: 3, outcome: "sent",
    narrative_status: null, narrative_reason: null, deliveries: [],
    created_at: "2026-01-02T00:00:00Z", sent_at: "2026-01-02T00:01:00Z", ...over,
  }
}

function detail(over: Partial<DigestDetail> = {}): DigestDetail {
  return {
    ...summary({ narrative_status: "succeeded" }),
    body: {
      rule: { id: "r1", name: "Fabrikam daily", severity_threshold: "high" },
      period: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" },
      totals: { events: 4, findings: 3, assets: 2, new: 2, promotions: 1,
        by_severity: { critical: 1, high: 2, medium: 0, low: 0, info: 0 } },
      groups: [{
        kind: "cluster", label: "Exposed admin panel", finding_count: 2, asset_count: 2,
        max_severity: "critical", key: "k1",
        items: [
          { finding_id: "f-1", asset_id: "a-1", asset: "app.example.com", title: "Admin panel exposed",
            severity: "critical", cve_id: "CVE-2024-90001", kinds: ["new"],
            band_change: null, state_now: "resolved", excluded_now: false, path: "/findings?id=f-1" },
          { finding_id: "f-2", asset_id: "a-2", asset: "203.0.113.7", title: "Admin panel exposed",
            severity: "high", cve_id: null, kinds: ["promotion"],
            band_change: { from: "Monitor", to: "Act" }, state_now: "open", excluded_now: true, path: "/findings?id=f-2" },
        ],
      }],
      listed_findings: 2, omitted_findings: 5,
    },
    narrative: { statements: [{ text: "One critical admin panel appeared.", cites: [] }], returned: 1, dropped: 0 },
    ...over,
  }
}

const wrap = (ui: React.ReactNode) => renderToStaticMarkup(
  <QueryClientProvider client={new QueryClient()}><MemoryRouter>{ui}</MemoryRouter></QueryClientProvider>,
)
const renderList = (d: DigestSummary[]) => wrap(<DigestHistoryList digests={d} />)

describe("DigestHistoryList", () => {
  it("shows every outcome label", () => {
    const labels: Record<DigestOutcome, string> = {
      empty: "Nothing new · not sent", pending: "Sending…", sent: "Sent", partial: "Partly sent",
      failed: "Send failed", no_channel: "Not sent · no notification channel",
      no_recipients: "Not sent · no recipients", abandoned: "Not sent · gave up after retries",
    }
    for (const [o, label] of Object.entries(labels)) {
      expect(renderList([summary({ outcome: o as DigestOutcome })])).toContain(label)
    }
  })

  it("shows rule name and finding count, or Nothing new", () => {
    const html = renderList([summary()])
    expect(html).toContain("Fabrikam daily")
    expect(html).toContain("3 findings")
    expect(renderList([summary({ finding_count: 0, outcome: "empty" })])).toContain("Nothing new")
  })

  it("AI label: succeeded, and skipped/failed carry the reason as a tooltip", () => {
    expect(renderList([summary({ narrative_status: "succeeded" })])).toContain("AI summary")
    const html = renderList([summary({ narrative_status: "skipped", narrative_reason: "daily cap reached" })])
    expect(html).toContain("No AI summary")
    expect(html).toContain('title="daily cap reached"')
    expect(renderList([summary({ narrative_status: "failed", narrative_reason: "model error" })]))
      .toContain('title="model error"')
    const none = renderList([summary({ narrative_status: null })])
    expect(none).not.toContain("AI summary")
  })

  it("shows the empty state", () => {
    expect(renderList([])).toContain("No digests yet.")
  })

  it("does not render the detail until expanded", () => {
    expect(renderList([summary()])).not.toContain("tied to the records below")
  })
})

describe("DigestBodyView", () => {
  it("renders statements, groups, omitted count, annotations and link", () => {
    const html = wrap(<DigestBodyView detail={detail()} />)
    expect(html).toContain("AI summary (each statement is tied to the records below)")
    expect(html).toContain("One critical admin panel appeared.")
    expect(html).toContain("Exposed admin panel")
    expect(html).toContain("2 findings")
    expect(html).toContain("CVE-2024-90001")
    expect(html).toContain("Monitor")
    expect(html).toContain("Act")
    expect(html).toContain("(now resolved)")
    // f-2 is still open: an open finding carries no "now" annotation.
    expect(html).not.toContain("(now open)")
    expect(html).toContain("(now excluded)")
    expect(html).toContain("… and 5 more")
    expect(html).toContain('href="/findings?id=f-1"')
    expect(html).toContain("app.example.com")
  })

  it("omits the omitted line when nothing was omitted", () => {
    const d = detail()
    d.body.omitted_findings = 0
    expect(wrap(<DigestBodyView detail={d} />)).not.toContain("more")
  })

  it("shows the unavailable reason when there is no narrative", () => {
    const html = wrap(<DigestBodyView detail={detail({
      narrative: null, narrative_status: "skipped", narrative_reason: "daily cap reached",
    })} />)
    expect(html).toContain("AI summary unavailable: daily cap reached")
    expect(html).not.toContain("tied to the records below")
  })

  it("escapes a script tag in a title", () => {
    const d = detail()
    d.body.groups[0].items[0].title = "<script>alert(1)</script>"
    const html = wrap(<DigestBodyView detail={d} />)
    expect(html).not.toContain("<script>")
    expect(html).toContain("&lt;script&gt;")
  })
})
