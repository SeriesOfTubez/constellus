import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import type { AcquisitionRow } from "@/lib/organizations"
import { AcquisitionTimeline, AcquisitionsTable } from "@/components/OrgAcquisitionParts"

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

describe("AcquisitionTimeline", () => {
  const tl = (rows: AcquisitionRow[], selected: string | null = null) =>
    renderToStaticMarkup(<AcquisitionTimeline rows={rows} selected={selected} onSelect={() => undefined} />)
  const organic = row({ entity_id: null, name: "Example Holdings A", organic: true })
  const none = { domains_claimed: 0, asns_claimed: 0, cidrs_claimed: 0, assets: 0 }

  it("renders nothing when there are no deal rows", () => {
    expect(tl([])).toBe("")
    expect(tl([organic])).toBe("")
  })
  it("never draws the organic row but does draw the deal", () => {
    const h = tl([row(), organic])
    expect(h).toContain('aria-label="Fabrikam Labs')
    expect(h).not.toContain("Example Holdings A")
  })
  it("puts an undated deal under Date unknown, not on the axis", () => {
    const h = tl([row(), row({ entity_id: "e2", name: "Example Holdings B", closed: null, closed_precision: null })])
    expect(h).toContain("Date unknown")
    // the dated dot is an absolutely positioned axis button; the chip is not
    expect(h.match(/class="absolute h-3 w-3/g)?.length).toBe(1)
    expect(h).toContain("Example Holdings B")
    expect(h.indexOf("Date unknown")).toBeLessThan(h.indexOf("Example Holdings B"))
  })
  it("omits the Date unknown group when every deal is dated", () => {
    expect(tl([row()])).not.toContain("Date unknown")
  })
  it("marks only the selected deal aria-pressed", () => {
    const h = tl([row(), row({ entity_id: "e2", name: "Example Holdings B", closed: "2022-01-01" })], "e2")
    expect(h.match(/aria-pressed="true"/g)?.length).toBe(1)
    expect(h.match(/aria-pressed="false"/g)?.length).toBe(1)
    expect(h.indexOf('aria-pressed="true"')).toBeGreaterThan(h.indexOf("Example Holdings B"))
  })
  it("styles severity, clean and hollow dots from the locked palette vars", () => {
    const h = tl([
      row({ worst_severity: "critical" }),
      row({ entity_id: "e2", name: "Example Holdings B", closed: "2022-01-01", worst_severity: null, asns_claimed: 1 }),
      row({ entity_id: "e3", name: "Example Holdings C", closed: "2023-01-01", worst_severity: null, ...none }),
    ])
    expect(h).toContain("background-color:var(--sev-critical)")
    expect(h).toContain("background-color:var(--sev-clean)")
    expect(h).toMatch(/border:2px solid var\(--sev-unknown\)/)
    expect(h).toContain("no claimed scope")
    expect(h).toContain("no open findings")
  })
})
