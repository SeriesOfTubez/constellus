import { describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { TooltipProvider } from "@/components/ui/tooltip"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

vi.mock("@/lib/evidence", () => ({ openEvidence: vi.fn() }))

import FindingDetail from "@/pages/FindingDetail"
import type { Finding } from "@/lib/api"
import { attribution, path } from "@/components/trace/fixtures"

const FINDING = {
  id: "fnd-1", asset_value: "dock.brightwatercold.example", asset_parent_value: null, asset_canonical_id: "ast-1",
  finding_type: "exposed_panel", source: "nuclei", fingerprint: "fp-1", severity: "high",
  title: "Admin panel reachable without login", description: null,
  detail: { cve_intel: { references: [{ url: "https://advisories.brightwatercold.example/a1", tags: [] }] } },
  state: "open", acknowledged_at: null, suppressed_until: null, verification: null, verification_evidence: null,
  verified_at: null, category: null, cve_id: null, cvss_score: null, cvss_vector: null, cvss_version: null,
  epss_score: null, epss_percentile: null, kev: null, kev_date_added: null, cwe: null, risk_score: null,
  risk_band: null, building_velocity: null, impact_class: null, exploit_types: [], ssvc_exploitation: null,
  ssvc_automatable: null, ssvc_technical_impact: null, ssvc_source: null, ssvc_scored_at: null,
  vulncheck_kev: null, has_exploit: null, exploit_count: null, ransomware_use: null, canary_detected: null,
  is_template: null, is_poc: null, tags: [], first_seen_at: "2026-03-01T00:00:00Z", last_seen_at: "2026-03-02T00:00:00Z",
  resolved_at: null, bod_sla: null, attribution: attribution(), exposure_paths: [path()],
} as Finding

function render() {
  const qc = new QueryClient()
  qc.setQueryData(["finding-detail", "fnd-1"], FINDING)
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <TooltipProvider>
        <MemoryRouter initialEntries={["/findings/fnd-1"]}>
          <Routes><Route path="/findings/:id" element={<FindingDetail />} /></Routes>
        </MemoryRouter>
      </TooltipProvider>
    </QueryClientProvider>,
  )
}

describe("FindingDetail trace mount", () => {
  it("shows both questions on Overview and keeps the other tabs", () => {
    const html = render()
    expect(html).toContain("Is it yours?")
    expect(html).toContain("Can it be reached?")
    expect(html).toContain(">Timeline<")
    expect(html).toContain(">Raw<")
    expect(html).toContain(">Intel<")
  })

  it("shows the verdict band above the first question", () => {
    const html = render()
    expect(html).toContain("Check matched")
    expect(html).toContain("What we did not do")
    expect(html.indexOf("Check matched")).toBeLessThan(html.indexOf("Is it yours?"))
    expect(html).toContain(">Timeline<")
    expect(html).toContain(">Raw<")
    expect(html).toContain(">Intel<")
  })
})
