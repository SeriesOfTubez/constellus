import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { ReportView } from "@/components/reports/ReportView"
import { GenerateControl } from "@/components/reports/GenerateControl"
import type { Report, Statement } from "@/lib/reports"

const ID = "3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e"
const query = { version: 1, entity: "finding", where: { field: "severity", op: "eq", value: "critical" } }

function make(over: Partial<Report> = {}, statements: Statement[] = []): Report {
  return {
    id: "r1", kind: "exec_summary", status: "done",
    as_of: "2026-01-01T00:00:00Z", created_at: "2026-01-01T00:00:00Z", finished_at: "2026-01-01T00:01:00Z",
    statements_returned: statements.length, statements_dropped: 0, cost_usd: 0.0123,
    engagement_id: "e1", model: "test-model", forced_strict: false, error: null, drop_reasons: {},
    facts: {
      as_of: "2026-01-01T00:00:00Z",
      engagement: { id: "e1", posture: "passive" },
      metrics: {
        crit: { label: "Critical findings", query, count: 3, capped: false },
        assets: { label: "Assets", query: { version: 1, entity: "asset" }, count: 10000, capped: true },
      },
      top_findings: [],
      top_findings_query: {},
    },
    payload: { statements },
    ...over,
  }
}

function render(report: Report, props: { onDelete?: () => void; onDownload?: () => void } = {}): string {
  return renderToStaticMarkup(
    <MemoryRouter><ReportView report={report} engagementName="Example Engagement" {...props} /></MemoryRouter>,
  )
}

const stmt = (text: string, citations: Statement["citations"] = []): Statement => ({ section: "posture", text, citations })

describe("ReportView order and numbering", () => {
  it("shows metrics in metric_order, not object key order", () => {
    const base = make()
    const html = render({ ...base, facts: { ...base.facts!, metric_order: ["assets", "crit"] } })
    expect(html.indexOf("Assets")).toBeGreaterThan(-1)
    expect(html.indexOf("Assets")).toBeLessThan(html.indexOf("Critical findings"))
    const html2 = render({ ...base, facts: { ...base.facts!, metric_order: ["crit", "assets"] } })
    expect(html2.indexOf("Critical findings")).toBeLessThan(html2.indexOf("Assets"))
  })

  it("numbers citations across the whole report, as the markdown export does", () => {
    const c = (ref: string) => ({ path: `metrics.${ref}.count`, value: "3", kind: "metric" as const, ref })
    const html = render(make({}, [
      stmt("first", [c("crit"), c("crit")]),
      { section: "gaps", text: "second", citations: [c("crit")] },
    ]))
    expect(html).toContain("[1]")
    expect(html).toContain("[2]")
    expect(html).toContain("[3]")
    expect(html.indexOf("second")).toBeLessThan(html.indexOf("[3]"))
  })
})

describe("ReportView narrative", () => {
  it("renders statement text as literal text (no links, no elements)", () => {
    const html = render(make({}, [stmt("see [x](https://evil.example) and <b>hi</b>")]))
    expect(html).toContain("see [x](https://evil.example) and &lt;b&gt;hi&lt;/b&gt;")  // reached, escaped
    expect(html).not.toContain('<a href="https://evil')
    expect(html).not.toContain("<b>")
    expect(html).not.toMatch(/href="https?:/)
  })

  it("links a metric citation to Explore and a uuid finding citation to its page", () => {
    const html = render(make({}, [stmt("a", [
      { path: "metrics.crit.count", value: "3", kind: "metric", ref: "crit" },
      { path: "top_findings[0]", value: "t", kind: "finding", ref: ID },
    ])]))
    expect(html).toMatch(/<a [^>]*href="\/explore\?q=/)
    expect(html).toContain(`href="/findings/${ID}"`)
  })

  it("gives no anchor for a non-uuid finding ref or a fact citation, but still shows the chip", () => {
    const html = render(make({}, [stmt("a", [
      { path: "p1", value: "v1", kind: "finding", ref: "not-a-uuid" },
      { path: "p2", value: "v2", kind: "fact", ref: null },
    ])]), {})
    expect(html).toContain('title="p1 = v1"')
    expect(html).toContain('title="p2 = v2"')
    expect(html).not.toContain("/findings/")
    expect(html).not.toMatch(/<sup[^>]*><a /)
  })

  it("groups by section in order", () => {
    const html = render(make({}, [
      { section: "gaps", text: "G", citations: [] },
      { section: "posture", text: "P", citations: [] },
    ]))
    expect(html.indexOf("Posture")).toBeLessThan(html.indexOf("What we don&#x27;t know"))
  })

  it("says so when no statement survived, and shows the dropped footer only when dropped > 0", () => {
    const none = render(make({ statements_dropped: 0 }, []))
    expect(none).toContain("No statement could be tied to the data, so none is shown.")
    expect(none).not.toContain("dropped because")
    const one = render(make({ statements_dropped: 1 }, []))
    expect(one).toContain("1 statement was dropped because it could not be tied to the data.")
    const dropped = render(make({ statements_dropped: 2 }, []))
    expect(dropped).toContain("2 statements were dropped because they could not be tied to the data.")
  })
})

describe("ReportView numbers", () => {
  it("shows counts from facts.metrics only, with + when capped", () => {
    const html = render(make({}, [stmt("There are 999 critical findings and 5 assets.")]))
    expect(html).toContain(">3<")
    expect(html).toContain("10,000+")
    expect(html).toMatch(/Open Critical findings in Explore/)
  })
})

describe("ReportView findings and status", () => {
  it("states the empty top-findings case about the record", () => {
    expect(render(make())).toContain("No open findings recorded for this engagement.")
  })

  it("lists top findings with a guarded link and KEV badge", () => {
    const r = make()
    r.facts!.top_findings = [{
      id: ID, title: "Example finding", severity: "critical", risk_score: 9.1, risk_band: "critical",
      kev: true, cve_id: null, asset_id: "a1", asset_value: "host.example.com",
    }]
    const html = render(r)
    expect(html).toContain(`href="/findings/${ID}"`)
    expect(html).toContain("KEV")
  })

  it("failed: shows the error and the computed numbers, no narrative", () => {
    const html = render(make({ status: "failed", error: "model unavailable", payload: null }))
    expect(html).toContain("model unavailable")
    expect(html).toContain("The numbers below were computed; the narrative could not be generated.")
    expect(html).toContain("Critical findings")
  })

  it("running: shows progress and no delete button", () => {
    const html = render(make({ status: "running", facts: null, payload: null }), { onDelete: () => {} })
    expect(html).toContain("Generating")
    expect(html).not.toContain("Delete")
  })

  it("offers delete only when a handler is passed", () => {
    expect(render(make())).not.toContain("Delete")
    expect(render(make(), { onDelete: () => {} })).toContain("Delete")
  })
})

describe("GenerateControl", () => {
  const html = (role: string | undefined, busy = false) =>
    renderToStaticMarkup(<GenerateControl role={role} busy={busy} onClick={() => {}} />)

  it("is hidden for viewer and integration_admin, shown for admin and report_admin", () => {
    expect(html("viewer")).toBe("")
    expect(html("integration_admin")).toBe("")
    expect(html("admin")).toContain("Generate executive summary")
    expect(html("report_admin")).toContain("Generate executive summary")
  })

  it("is disabled while busy", () => {
    expect(html("admin", true)).toContain(" disabled=\"\"")
    expect(html("admin", false)).not.toContain(" disabled=\"\"")
  })
})

describe("ReportView ma_brief", () => {
  const EID = "7a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d"
  const SID = "11111111-2222-4333-8444-555555555555"
  const EXPLORE = { version: 1, entity: "entity" }
  const hostile = "Evil [x](https://evil.example) <b>Ltd</b>"

  function makeMa(entityId: string | null = EID, name = "Example Holdings B"): Report {
    const base = make({ kind: "ma_brief" }, [
      { section: "gaps", text: "gap text", citations: [] },
      { section: "family", text: "family text", citations: [
        { path: "lists.family.rows[0]", value: name, kind: "entity", ref: EID },
      ] },
      { section: "domains", text: "domain text", citations: [] },
    ])
    base.facts = {
      ...base.facts!,
      subject: { id: SID, name: "Example Holdings A" },
      list_order: ["family", "acquisitions", "former_names", "domains"],
      lists: {
        family: { label: "Corporate family", query: EXPLORE, truncated: true,
          rows: [{ entity_id: entityId, name, relationship: "subsidiary" }] },
        acquisitions: { label: "Acquisitions", query: EXPLORE, truncated: false,
          rows: [{ entity_id: EID, acquirer: "Example Holdings A", acquired: "Example Holdings B", event_date: "2020-01-01" }] },
        former_names: { label: "Former names", query: EXPLORE, truncated: false, rows: [] },
        domains: { label: "Domains", query: EXPLORE, truncated: false,
          rows: [{ entity_id: EID, domain: "fabrikam.com", entity_name: "Example Holdings B" }] },
      },
    }
    return base
  }

  it("renders title, subject link, sections in order, list rows, entity citation and truncation note", () => {
    const html = render(makeMa())
    expect(html).toContain("M&amp;A due-diligence brief")
    expect(html).toContain(`Subject:`)
    expect(html).toContain(`href="/organizations/entity/${SID}"`)
    const i = ["Corporate family", "Domains", "What we still don&#x27;t know"].map(h => html.indexOf(`>${h}<`))
    expect(i.every(n => n > -1)).toBe(true)
    expect(i[0]).toBeLessThan(i[1])
    expect(i[1]).toBeLessThan(i[2])
    expect(html).not.toContain(">Acquisitions</h3><ul class=\"list-disc pl-5 space-y-1.5\"")  // no statements for it
    expect(html).toContain("Example Holdings B (subsidiary)")
    expect(html).toContain("Example Holdings A acquired Example Holdings B (2020-01-01)")
    expect(html).toContain("fabrikam.com (Example Holdings B)")
    expect(html).toContain(`href="/organizations/entity/${EID}"`)
    expect(html).toMatch(/<sup[^>]*><a [^>]*href="\/organizations\/entity\/7a1b2c3d/)
    expect(html).toContain("Showing the first 1; more exist.")
    expect(html).toContain("None recorded.")
    expect(html).toMatch(/aria-label="Open Corporate family in Explore"/)
  })

  it("renders a hostile entity name as literal text", () => {
    const html = render(makeMa(EID, hostile))
    expect(html).toContain("Evil [x](https://evil.example) &lt;b&gt;Ltd&lt;/b&gt;")
    expect(html).not.toMatch(/<a [^>]*href="https?:/)
    expect(html).not.toContain("<b>")
  })

  it("gives a non-uuid entity_id no anchor", () => {
    const html = render(makeMa("not-a-uuid"))
    expect(html).toContain("Example Holdings B (subsidiary)")
    expect(html).not.toContain("not-a-uuid")
  })

  it("leaves the exec_summary title unchanged", () => {
    expect(render(make())).toContain("Executive summary")
  })
})

describe("GenerateControl M&A", () => {
  const html = (role: string | undefined, noSubject: boolean, busy = false) =>
    renderToStaticMarkup(<GenerateControl role={role} busy={busy} noSubject={noSubject} onClick={() => {}} onGenerateMa={() => {}} />)
  const maButton = (h: string) => /<button[^>]*>Generate M&amp;A brief<\/button>/.exec(h)![0]

  it("disables the M&A action without a subject, with the reason as title", () => {
    const b = maButton(html("admin", true))
    expect(b).toContain(' disabled=""')
    expect(b).toContain('title="This engagement has no subject entity"')
  })

  it("enables it with a subject, and disables it while busy", () => {
    expect(maButton(html("admin", false))).not.toContain(" disabled=\"\"")
    expect(maButton(html("report_admin", false, true))).toContain(' disabled=""')
  })

  it("shows no generate actions to a viewer", () => {
    expect(html("viewer", false)).toBe("")
  })
})
