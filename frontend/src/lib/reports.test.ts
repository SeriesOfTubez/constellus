import { describe, expect, it } from "vitest"
import { canGenerateReports, citationHref, formatCount, listRowText, SECTION_LABELS, type Citation } from "@/lib/reports"

const ID = "3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e"
const query = { version: 1, entity: "finding", where: { field: "severity", op: "eq", value: "critical" } }
const report = {
  facts: {
    as_of: "2026-01-01T00:00:00Z",
    engagement: { id: "e", posture: "passive" },
    metrics: { crit: { label: "Critical", query, count: 3, capped: false } },
    top_findings: [],
    top_findings_query: {},
  },
}

const cite = (kind: Citation["kind"], ref: string | null): Citation => ({ path: "p", value: "v", kind, ref })

describe("canGenerateReports", () => {
  it.each([["admin", true], ["report_admin", true], ["viewer", false], ["integration_admin", false], [undefined, false]])(
    "%s -> %s", (role, expected) => {
      expect(canGenerateReports(role)).toBe(expected)
    })
})

describe("citationHref", () => {
  it("links a metric citation to Explore with the metric's own query", () => {
    const href = citationHref(cite("metric", "crit"), report)
    expect(href).toMatch(/^\/explore\?q=/)
    expect(decodeURIComponent(href!.slice("/explore?q=".length))).toBe(JSON.stringify(query))
  })
  it("gives no link for an unknown metric ref", () => {
    expect(citationHref(cite("metric", "nope"), report)).toBeNull()
  })
  it("links a finding citation with a uuid", () => {
    expect(citationHref(cite("finding", ID), report)).toBe(`/findings/${ID}`)
  })
  it.each(["not-a-uuid", `${ID}/../x`, `${ID}?next=https://evil.example`, ""])("gives no link for finding ref %j", ref => {
    expect(citationHref(cite("finding", ref), report)).toBeNull()
  })
  it("gives no link for a fact citation or a null ref", () => {
    expect(citationHref(cite("fact", "x"), report)).toBeNull()
    expect(citationHref(cite("finding", null), report)).toBeNull()
  })
})

describe("formatCount", () => {
  it("adds + when capped and groups digits", () => {
    expect(formatCount({ count: 10000, capped: true })).toBe("10,000+")
    expect(formatCount({ count: 1234, capped: false })).toBe("1,234")
  })
})

describe("SECTION_LABELS", () => {
  it("names the gaps section plainly", () => {
    expect(SECTION_LABELS.gaps).toBe("What we don't know")
  })
})

describe("citationHref entity", () => {
  it("links a uuid entity ref and refuses a non-uuid", () => {
    expect(citationHref(cite("entity", ID), report)).toBe(`/organizations/entity/${ID}`)
    expect(citationHref(cite("entity", "x/../y"), report)).toBeNull()
    expect(citationHref(cite("entity", null), report)).toBeNull()
  })
})

describe("listRowText", () => {
  it("formats each list key", () => {
    expect(listRowText("family", { name: "Example Holdings B", relationship: "subsidiary" })).toBe("Example Holdings B (subsidiary)")
    expect(listRowText("family", { name: "Example Holdings B", relationship: null })).toBe("Example Holdings B")
    // the stored enum is not a label
    expect(listRowText("family", { name: "Example Holdings B", relationship: "ma_target" })).toBe("Example Holdings B (M&A target)")
    expect(listRowText("acquisitions", { acquirer: "A", acquired: "B", event_date: "2020-01-01" })).toBe("A acquired B (2020-01-01)")
    expect(listRowText("acquisitions", { acquirer: "A", acquired: "B", event_date: null })).toBe("A acquired B")
    expect(listRowText("former_names", { name: "Old Name" })).toBe("Old Name")
    expect(listRowText("domains", { domain: "fabrikam.com", entity_name: "Example Holdings B" })).toBe("fabrikam.com (Example Holdings B)")
  })
  it("falls back to the row values for an unknown key", () => {
    expect(listRowText("other", { a: "x", b: null, c: "y" })).toBe("x · y")
  })
})
