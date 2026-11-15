/// <reference types="node" />
import { describe, expect, it, vi } from "vitest"
import fs from "node:fs"
import nodePath from "node:path"
import type { ReactElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"

vi.mock("@/lib/evidence", () => ({ openEvidence: vi.fn() }))

import type { Finding } from "@/lib/api"
import { AttributionQuestion } from "./AttributionQuestion"
import { ExposureQuestion } from "./ExposureQuestion"
import { EvidenceList } from "./EvidenceList"
import { CandidateList } from "./CandidateList"
import { TraceChains } from "./TraceChains"
import {
  addrHop, attribution, candidate, chain, claim, exposureHops, hostHop, orgHop, path, relation, scopeHop, signal,
} from "./fixtures"

const render = (el: ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>)
const count = (s: string, needle: string) => s.split(needle).length - 1
const text = (html: string) => html.replace(/<[^>]*>/g, " ")
const TITLE = "Admin panel reachable without login"

describe("Is it yours?", () => {
  it("S1: not_ours still shows its chain", () => {
    const a = attribution({ ownership: { surface: "not_ours", reason: "A registry names another holder.", evidence: [], tier: null } })
    expect(a.chains).toHaveLength(1)
    const html = render(<AttributionQuestion attribution={a} />)
    expect(html).toContain("No. The record says this is not yours.")
    expect(html).toContain("Halvard Rhys Freight")
    expect(html).toContain("A registry names another holder.")
    // The chain is not the answer, and the page says so.
    expect(html).toContain("They do not make it yours.")
  })

  it("S1: claimed_ours with an unknown organization hop is not downgraded", () => {
    const org = orgHop({ status: "unknown", name: null, entity_id: null, relationship: null, reason: "No organization claims this target." })
    const a = attribution({ ownership: { surface: "claimed_ours", reason: null, evidence: [], tier: null }, chains: [chain([org, scopeHop()])] })
    const html = render(<AttributionQuestion attribution={a} />)
    expect(html).toContain("Claimed as yours, not proven.")
    expect(html).not.toContain("No. The record says")
    expect(html).not.toContain("Not checked.")
    expect(html).not.toContain("They do not make it yours.")
  })

  it("S2: tier null prints no chip; a supporting tier prints one", () => {
    const withEvidence = (tier: "supporting" | null) =>
      attribution({ chains: [chain([orgHop(), scopeHop({ evidence: [signal({ tier })], tier }), hostHop()])] })
    const none = render(<AttributionQuestion attribution={withEvidence(null)} />)
    expect(none).toContain("1 record")
    for (const t of [">Strong<", ">Supporting<", ">Context<"]) expect(none).not.toContain(t)
    expect(render(<AttributionQuestion attribution={withEvidence("supporting")} />)).toContain(">Supporting<")
  })

  it("S2: no chip when ownership tier and claim row tier are null", () => {
    const a = attribution({
      ownership: { surface: "not_ours", reason: null, evidence: [claim({ tier: null })], tier: null },
      chains: [chain([orgHop(), scopeHop(), hostHop()])],
    })
    const html = render(<AttributionQuestion attribution={a} />)
    expect(html).toContain("1 ownership record")
    for (const t of [">Strong<", ">Supporting<", ">Context<"]) expect(html).not.toContain(t)
  })

  it("S3: unknown hop is a dashed gap with its reason, and later hops remain", () => {
    const reason = "No target on record covers this asset."
    const a = attribution({ chains: [chain([orgHop(), scopeHop({ status: "unknown", target_id: null, value: null, reason }), hostHop()])] })
    const html = render(<AttributionQuestion attribution={a} />)
    expect(html).toContain('data-status="unknown"')
    expect(html).toContain("border-dashed")
    expect(html).toContain(reason)
    expect(html).toContain("Halvard Rhys Freight")
    expect(html).toContain("dock.brightwatercold.example")
    expect(html).toContain("No target on record")
  })

  it("S4: a derived host with one candidate lists it and promotes none", () => {
    const host = hostHop({ status: "derived", hostname: null, asset_id: null, candidates: [candidate()] })
    const a = attribution({ chains: [chain([orgHop(), scopeHop(), host])] })
    const html = render(<AttributionQuestion attribution={a} />)
    expect(html).toContain("1 hostname points here")
    expect(count(html, "gate.brightwatercold.example")).toBe(1)
    expect(html).toContain('href="/assets/cand-1"')
  })

  it("S5: three chains, one expanded, none labelled as the main one", () => {
    const mk = (name: string, reason: string) => chain([orgHop({ name }), scopeHop({ reason }), hostHop()])
    const a = attribution({ chains: [mk("Halvard Rhys Freight", "detail one"), mk("Orsolya Vane Cold Storage", "detail two"), mk("Pelham Quay Logistics", "detail three")] })
    expect(a.chains).toHaveLength(3)
    const html = render(<AttributionQuestion attribution={a} />)
    expect(count(html, "aria-expanded")).toBe(3)
    expect(count(html, 'aria-expanded="true"')).toBe(1)
    expect(html).toContain("detail one")
    expect(html).not.toContain("detail two")
    expect(html).toContain("Orsolya Vane Cold Storage")
    const t = text(html).replace("None is the main one.", "")
    expect(t).not.toMatch(/main|primary|best match|default/i)
    expect(t).toContain("3 chains on record")
  })

  it("S6: an address without an asset id is text, with one it links", () => {
    const mk = (assetId: string | null) => attribution({ chains: [chain([orgHop(), scopeHop(), addrHop({ asset_id: assetId })])] })
    const bare = render(<AttributionQuestion attribution={mk(null)} />)
    expect(bare).toContain("203.0.113.47")
    expect(bare).not.toContain('href="/assets/')
    expect(render(<AttributionQuestion attribution={mk("ast-9")} />)).toContain('href="/assets/ast-9"')
  })

  it("S9: truncated chains say so", () => {
    const html = render(<AttributionQuestion attribution={attribution({ chains_truncated: true })} />)
    expect(html).toContain("More chains exist than are shown.")
  })

  it("null attribution prints the fixed line; undefined prints nothing", () => {
    expect(render(<AttributionQuestion attribution={null} />)).toContain(
      "This finding has no asset on record, so there is nothing to attribute.",
    )
    expect(render(<AttributionQuestion attribution={undefined} />)).toBe("")
  })

  it("evidence lists start collapsed", () => {
    const a = attribution({ chains: [chain([orgHop(), scopeHop({ evidence: [signal(), signal({ signal_id: "sig-2", label: "Shared mail server" })] }), hostHop()])] })
    const html = render(<AttributionQuestion attribution={a} />)
    expect(html).toContain("2 records")
    expect(html).toContain("linked by 2 signals")
    expect(html).not.toContain("Shared mail server")
    expect(html).not.toContain("Registrant match")
    expect(html).toContain('aria-expanded="false"')
  })
})

describe("EvidenceList and CandidateList", () => {
  const rows = [
    relation(),
    signal({ evidence_id: "doc-3" }),
    signal({ evidence_id: null, label: "Seeded by an admin" }),
    claim({ tier: "context" }),
  ]

  it("S7: the open control appears only on rows with a document", () => {
    const html = render(<EvidenceList rows={rows} truncated={false} />)
    expect(count(html, "<li")).toBe(4)
    expect(count(html, 'aria-label="Open source document"')).toBe(2)
    expect(html).toContain(">Context<")
  })

  it("S9: truncated evidence says so, and only then", () => {
    expect(render(<EvidenceList rows={rows} truncated />)).toContain("More exist than are listed.")
    expect(render(<EvidenceList rows={rows} truncated={false} />)).not.toContain("More exist than are listed.")
  })

  it("S9: truncated candidates say so; more than five are folded behind a button", () => {
    const many = Array.from({ length: 7 }, (_, i) => candidate({ asset_id: `c${i}`, value: `h${i}.brightwatercold.example` }))
    const html = render(<CandidateList candidates={many} truncated />)
    // Folded: the note waits until every listed candidate is on screen.
    expect(html).not.toContain("More exist than are listed.")
    expect(html).toContain("Show all 7")
    const few = render(<CandidateList candidates={many.slice(0, 3)} truncated />)
    expect(few).toContain("More exist than are listed.")
    expect(few).not.toContain("Show all")
    expect(html).toContain("h4.brightwatercold.example")
    expect(html).not.toContain("h5.brightwatercold.example")
    expect(render(<CandidateList candidates={many.slice(0, 2)} truncated={false} />)).not.toContain("Show all")
  })
})

describe("Can it be reached?", () => {
  it("a port without a protocol shows :443 and never tcp", () => {
    const p = path({ hops: exposureHops({ port: { protocol: null } }) })
    const html = render(<ExposureQuestion paths={[p]} findingTitle={TITLE} />)
    expect(html).toContain(":443")
    expect(html).not.toContain("tcp")
  })

  it("not_reobserved uses the observation label and never says closed or resolved", () => {
    const p = path({ observation: "not_reobserved", last_seen_at: "2026-03-04T10:00:00Z" })
    const html = render(<ExposureQuestion paths={[p]} findingTitle={TITLE} />)
    expect(html).toContain("Not seen again since 4 Mar 2026")
    expect(text(html)).not.toMatch(/closed|resolved/i)
  })

  it("a not_applicable hop is in the expanded detail but not in the summary", () => {
    const p = path({ hops: exposureHops({ service: { status: "not_applicable" } }) })
    const html = render(<ExposureQuestion paths={[p]} findingTitle={TITLE} />)
    expect(count(html, "Does not apply")).toBe(1) // the title says it; no second status word
    const header = html.slice(html.indexOf("<button"), html.indexOf("</button>"))
    expect(header).not.toContain("Does not apply")
    expect(header).toContain("dock.brightwatercold.example")
    expect(html).toContain("<h2")
  })

  it("the finding hop is drawn as a diamond, the title coming from the finding", () => {
    const html = render(<ExposureQuestion paths={[path()]} findingTitle={TITLE} />)
    expect(html).toContain("rotate-45")
    expect(html).toContain(TITLE)
  })

  it("every path is listed, the first open, with the legend once", () => {
    const html = render(<ExposureQuestion paths={[path(), path({ endpoint_id: "ep-2" })]} findingTitle={TITLE} />)
    expect(count(html, 'aria-expanded="true"')).toBe(1)
    expect(count(html, 'aria-expanded="false"')).toBe(1)
    expect(count(html, "Evidence tier")).toBe(1)
    expect(html).toContain(">Strong<")
  })

  it("an empty list prints the sentence and no chain button", () => {
    const html = render(<ExposureQuestion paths={[]} findingTitle={TITLE} />)
    expect(html).toContain("No place is recorded for this finding.")
    expect(html).not.toContain("aria-expanded")
  })

  it("S9: truncated candidates on an exposure host hop say so", () => {
    const host = { status: "derived", hostname: null, asset_id: null, candidates: [candidate()], candidates_truncated: true }
    const html = render(<ExposureQuestion paths={[path({ hops: exposureHops({ host }) })]} findingTitle={TITLE} />)
    expect(html).toContain("More than 1 hostnames point here")
    expect(html).toContain("More exist than are listed.")
  })
})

describe("TraceChains", () => {
  it("renders an empty string when the finding carries neither key", () => {
    expect(render(<TraceChains finding={{} as Finding} />)).toBe("")
  })
  it("renders both questions when it does", () => {
    const html = render(<TraceChains finding={{ title: TITLE, attribution: attribution(), exposure_paths: [path()] } as Finding} />)
    expect(html).toContain("Is it yours?")
    expect(html).toContain("Can it be reached?")
    expect(html).toContain('aria-label="Trace"')
  })
})

describe("components fetch nothing (S8)", () => {
  it("no non-test file in components/trace uses a query hook or the network", () => {
    const files = fs.readdirSync(__dirname).filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f))
    expect(files.length).toBeGreaterThanOrEqual(10)
    for (const f of files) {
      const src = fs.readFileSync(nodePath.join(__dirname, f), "utf8")
      for (const banned of ["useQuery", "api.get", "api.post", "fetch("]) expect(src, `${f}: ${banned}`).not.toContain(banned)
    }
  })
})
