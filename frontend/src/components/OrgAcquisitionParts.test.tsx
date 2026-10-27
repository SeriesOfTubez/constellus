import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import type { AcquisitionRow } from "@/lib/organizations"
import { AcquisitionsTable } from "@/components/OrgAcquisitionParts"

const row = (over: Partial<AcquisitionRow> = {}): AcquisitionRow => ({
  entity_id: "e1", name: "Fabrikam Labs", organic: false, closed: "2021-03-12", closed_precision: "day",
  postures: ["day_0"], domains_claimed: 2, domains_to_review: 0, asns_claimed: 1, cidrs_claimed: 2, ip_to_review: 0,
  assets: 7, open_findings: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 }, worst_severity: "critical",
  kev: 0, risk_score_sum: 10, risk_share: 0.25, ...over,
})
const html = (rows: AcquisitionRow[], open?: (id: string | null) => void) =>
  renderToStaticMarkup(<MemoryRouter><AcquisitionsTable rows={rows} onOpenCompany={open} /></MemoryRouter>)

describe("AcquisitionsTable", () => {
  const rows = [
    row({ domains_to_review: 3 }),
    row({ entity_id: "e2", name: "Example Holdings B", ip_to_review: 0 }),
    row({ entity_id: null, name: "Example Holdings A", organic: true, closed: null, closed_precision: null, postures: [] }),
  ]
  it("keeps order, suffixes the organic row, and shows +N cand only when > 0", () => {
    const h = html(rows)
    expect(h.indexOf("Fabrikam Labs")).toBeLessThan(h.indexOf("Example Holdings B"))
    expect(h.indexOf("Example Holdings B")).toBeLessThan(h.indexOf("Example Holdings A (organic)"))
    expect(h).toContain("+3 cand")
    expect(h.match(/cand</g)?.length).toBe(1)
  })
  it("renders — for a null share", () => {
    expect(html([row({ risk_share: null })])).toContain(">—<")
  })
  it("renders — for IP space when both counts are zero", () => {
    const h = html([row({ asns_claimed: 0, cidrs_claimed: 0 })])
    expect(h).toContain(">—<")
    expect(h).not.toContain("prefix")
  })
  it("has no Trend header", () => {
    expect(html(rows)).not.toMatch(/trend/i)
  })
  it("shows the open button only when onOpenCompany is given", () => {
    expect(html(rows)).not.toContain("Open in Companies")
    expect(html(rows, () => undefined)).toContain("Open in Companies &amp; filings")
  })
})
