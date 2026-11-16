/// <reference types="node" />
import { describe, expect, it, vi } from "vitest"
import fs from "node:fs"
import nodePath from "node:path"
import type { ReactElement } from "react"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"

vi.mock("@/lib/evidence", () => ({ openEvidence: vi.fn() }))

import type { Attribution, ExposurePath, Finding } from "@/lib/api"
import { AttributionChainHops, AttributionQuestion } from "./AttributionQuestion"
import { ExposurePathHops, ExposureQuestion } from "./ExposureQuestion"
import { EvidenceList } from "./EvidenceList"
import { CandidateList } from "./CandidateList"
import { TraceChains } from "./TraceChains"
import { VerdictBand } from "./VerdictBand"
import { VERDICTS, verdictFor, verdictVariant, type VerdictVariant } from "@/lib/trace"
import {
  addrHop, attribution, candidate, chain, claim, exposureHops, hostHop, orgHop, path, relation, scopeHop, signal,
} from "./fixtures"

const render = (el: ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>)
const count = (s: string, needle: string) => s.split(needle).length - 1
const text = (html: string) => html.replace(/<[^>]*>/g, " ")
const TITLE = "Admin panel reachable without login"

// Rows start closed and static markup cannot click, so the detail of a row is rendered
// on its own: `question*` is what loads, `hops*` is what one opened row shows.
const questionA = (a: Attribution) => render(<AttributionQuestion attribution={a} />)
const hopsA = (a: Attribution, i = 0) => render(<AttributionChainHops chain={a.chains[i]} />)
const bothA = (a: Attribution) => questionA(a) + a.chains.map((_, i) => hopsA(a, i)).join("")
const questionP = (paths: ExposurePath[]) => render(<ExposureQuestion paths={paths} findingTitle={TITLE} />)
const hopsP = (p: ExposurePath) => render(<ExposurePathHops path={p} findingTitle={TITLE} />)
const bothP = (paths: ExposurePath[]) => questionP(paths) + paths.map(hopsP).join("")

describe("Is it yours?", () => {
  it("S1: not_ours still shows its chain", () => {
    const a = attribution({ ownership: { surface: "not_ours", reason: "A registry names another holder.", evidence: [], tier: null } })
    expect(a.chains).toHaveLength(1)
    const html = bothA(a)
    expect(html).toContain("No. The record says this is not yours.")
    expect(html).toContain("Halvard Rhys Freight")
    expect(html).toContain("A registry names another holder.")
    // The chain is not the answer, and the page says so.
    expect(html).toContain("They do not make it yours.")
  })

  it("S1: claimed_ours with an unknown organization hop is not downgraded", () => {
    const org = orgHop({ status: "unknown", name: null, entity_id: null, relationship: null, reason: "No organization claims this target." })
    const a = attribution({ ownership: { surface: "claimed_ours", reason: null, evidence: [], tier: null }, chains: [chain([org, scopeHop()])] })
    const html = bothA(a)
    expect(html).toContain("Claimed as yours, not proven.")
    expect(html).not.toContain("No. The record says")
    expect(html).not.toContain("Not checked.")
    expect(html).not.toContain("They do not make it yours.")
  })

  it("S2: tier null prints no chip; a supporting tier prints one", () => {
    const withEvidence = (tier: "supporting" | null) =>
      attribution({ chains: [chain([orgHop(), scopeHop({ evidence: [signal({ tier })], tier }), hostHop()])] })
    const none = bothA(withEvidence(null))
    expect(none).toContain("1 record")
    for (const t of [">Strong<", ">Supporting<", ">Context<"]) expect(none).not.toContain(t)
    expect(hopsA(withEvidence("supporting"))).toContain(">Supporting<")
  })

  it("S2: no chip when ownership tier and claim row tier are null", () => {
    const a = attribution({
      ownership: { surface: "not_ours", reason: null, evidence: [claim({ tier: null })], tier: null },
      chains: [chain([orgHop(), scopeHop(), hostHop()])],
    })
    const html = bothA(a)
    expect(html).toContain("1 ownership record")
    for (const t of [">Strong<", ">Supporting<", ">Context<"]) expect(html).not.toContain(t)
  })

  it("S3: unknown hop is a dashed gap with its reason, and later hops remain", () => {
    const reason = "No target on record covers this asset."
    const a = attribution({ chains: [chain([orgHop(), scopeHop({ status: "unknown", target_id: null, value: null, reason }), hostHop()])] })
    const html = bothA(a)
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
    const html = bothA(a)
    expect(html).toContain("1 hostname points here")
    expect(count(html, "gate.brightwatercold.example")).toBe(1)
    expect(html).toContain('href="/assets/cand-1"')
  })

  it("S5: three chains, all closed on load, none labelled as the main one", () => {
    const mk = (name: string, reason: string) => chain([orgHop({ name }), scopeHop({ reason }), hostHop()])
    const a = attribution({ chains: [mk("Halvard Rhys Freight", "detail one"), mk("Orsolya Vane Cold Storage", "detail two"), mk("Pelham Quay Logistics", "detail three")] })
    expect(a.chains).toHaveLength(3)
    const html = questionA(a)
    expect(count(html, "aria-expanded")).toBe(3)
    expect(count(html, 'aria-expanded="false"')).toBe(3)
    // Every chain is summarised; no hop detail is on the page until a row is opened.
    for (const name of ["Halvard Rhys Freight", "Orsolya Vane Cold Storage", "Pelham Quay Logistics"]) expect(html).toContain(name)
    for (const detail of ["detail one", "detail two", "detail three"]) expect(html).not.toContain(detail)
    expect(html).not.toContain("data-status=")
    // An opened row shows its own chain's hops and no other's.
    expect(hopsA(a, 1)).toContain("detail two")
    expect(hopsA(a, 1)).not.toContain("detail one")
    const t = text(html).replace("None is the main one.", "")
    expect(t).not.toMatch(/main|primary|best match|default/i)
    expect(t).toContain("3 chains on record")
  })

  it("S6: an address without an asset id is text, with one it links", () => {
    const mk = (assetId: string | null) => attribution({ chains: [chain([orgHop(), scopeHop(), addrHop({ asset_id: assetId })])] })
    const bare = bothA(mk(null))
    expect(bare).toContain("203.0.113.47")
    expect(bare).not.toContain('href="/assets/')
    expect(hopsA(mk("ast-9"))).toContain('href="/assets/ast-9"')
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
    const html = hopsA(a)
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
    const html = bothP([p])
    expect(html).toContain(":443")
    expect(html).not.toContain("tcp")
  })

  it("not_reobserved uses the observation label and never says closed or resolved", () => {
    const p = path({ observation: "not_reobserved", last_seen_at: "2026-03-04T10:00:00Z" })
    const html = bothP([p])
    expect(html).toContain("Not seen again since 4 Mar 2026")
    expect(text(html)).not.toMatch(/closed|resolved/i)
  })

  it("a not_applicable hop is in the expanded detail but not in the summary", () => {
    const p = path({ hops: exposureHops({ service: { status: "not_applicable" } }) })
    expect(count(hopsP(p), "Does not apply")).toBe(1) // the title says it; no second status word
    const html = questionP([p])
    expect(html).not.toContain("Does not apply")
    const header = html.slice(html.indexOf("<button"), html.indexOf("</button>"))
    expect(header).not.toContain("Does not apply")
    expect(header).toContain("dock.brightwatercold.example")
    expect(html).toContain("<h2")
  })

  it("the finding hop is drawn as a diamond, the title coming from the finding", () => {
    const html = hopsP(path())
    expect(html).toContain("rotate-45")
    expect(html).toContain(TITLE)
  })

  it("every path is listed, all closed on load, with the legend once", () => {
    const html = questionP([path(), path({ endpoint_id: "ep-2" })])
    expect(count(html, "aria-expanded")).toBe(2)
    expect(count(html, 'aria-expanded="false"')).toBe(2)
    // No hop detail on load: the finding hop's diamond is only in an opened row.
    expect(html).not.toContain("rotate-45")
    expect(hopsP(path())).toContain("rotate-45")
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
    const html = bothP([path({ hops: exposureHops({ host }) })])
    expect(html).toContain("More than 1 hostnames point here")
    expect(html).toContain("More exist than are listed.")
  })
})

type VIn = Parameters<typeof verdictVariant>[0]
const vin = (source: string, finding_type: string, detail: Record<string, unknown> | null = {}): VIn => ({ source, finding_type, detail })

describe("Verdict band", () => {
  const TABLE: [VerdictVariant, VIn, string, string, string][] = [
    ["nuclei_check", { source: "nuclei", finding_type: "exposed_panel", detail: {} }, "Check matched", "A scanner check sent a request to this host, and the response matched the pattern for this issue.", "We did not go further than that one check. No attempt was made to use the issue."],
    ["nuclei_default_login", { source: "nuclei", finding_type: "tpl", detail: { tags: ["default-login"] } }, "Default login accepted", "A scanner check tried a known default username and password on this host, and the login was accepted.", "We did nothing after the login. Nothing was read or changed. We kept the check's result, nothing else from the session."],
    ["exposed_service_identified", { source: "constellus", finding_type: "exposed_service", detail: { confidence: "confirmed" } }, "Seen open", "A port scan found this port open, and the service answering on it was identified.", "We did not try to log in, send commands or test the service for weaknesses. An open service is an exposure, not a break-in."],
    ["exposed_service_unidentified", { source: "constellus", finding_type: "exposed_service", detail: { confidence: "potential" } }, "Seen open, service not identified", "A port scan found this port open. What answers on it was not identified; the finding goes by the port's usual service.", "We did not confirm what is answering, try to log in or test it for weaknesses."],
    ["dangling_fingerprint", { source: "constellus", finding_type: "dangling_dns", detail: { layer: "fingerprint" } }, "Check matched", "This DNS name points to a third-party service, and that service replied that nothing is set up there.", "We did not try to claim the resource. Whether someone else can claim it was not tested."],
    ["dangling_not_affine", { source: "constellus", finding_type: "dangling_dns", detail: { layer: "affinity_not_affine" } }, "No sign of this name", "This name points at a shared hosting address. The address answered, but showed no sign of serving this name.", "We did not try to take over the address or the name. Finding no sign is not proof the name is abandoned."],
    ["dangling_unreachable", { source: "constellus", finding_type: "dangling_dns", detail: { layer: "affinity_unreachable" } }, "No answer", "This name points at an address that did not answer on any port we tried.", "We did not find out why. The address may be retired, or something in front of it may still serve the name."],
    ["dangling_serves_others", { source: "constellus", finding_type: "dangling_dns", detail: { layer: "affinity_corroborated_alive" } }, "Serves another name", "This name points at an address that did not answer for this name but does serve a different one.", "We did not try to claim the address or serve anything under this name."],
    ["version_match_cve", { source: "version_match", finding_type: "cve", detail: {} }, "Inferred from a version", "Software on this host reported a version number, and that version is in the range this CVE affects.", "We did not test for the weakness itself. A vendor can patch it without changing the version number, so this can overstate."],
    ["shodan_cve", { source: "shodan", finding_type: "cve", detail: {} }, "Reported by Shodan", "Shodan listed this CVE for this address, from the software version it recorded there.", "We did not contact the host to check it, and neither we nor Shodan tested for the weakness itself. A version match can overstate."],
    ["shodan_cve_verified", { source: "shodan", finding_type: "cve", detail: { shodan_verified: true } }, "Tested by Shodan", "Shodan reports that it tested this address for this CVE and the test came back positive.", "We did not contact the host or repeat the test. Shodan's report is all we have."],
    ["shodan_label", { source: "shodan", finding_type: "malware", detail: null }, "Reported by Shodan", "Shodan labelled this address as compromised, hosting malware or a honeypot.", "We did not check the label ourselves. The record does not say what Shodan saw."],
    ["other", { source: "tenable", finding_type: "cve", detail: null }, "Reported by a source", "The source named on this finding reported it.", "No description of what that source checks is on file, so we cannot say what was and was not done."],
  ]

  it("each variant is chosen for its finding and carries its exact words", () => {
    expect(TABLE).toHaveLength(13)
    for (const [variant, f, label, saw, didNot] of TABLE) {
      expect(verdictVariant(f), variant).toBe(variant)
      expect(verdictFor(f), variant).toEqual({ label, saw, didNot })
    }
  })

  it("selection edges", () => {
    expect(verdictVariant(vin("nuclei", "t", { tags: ["cve", "default-login"] }))).toBe("nuclei_default_login")
    expect(verdictVariant(vin("nuclei", "t", { tags: "panel, default-login" }))).toBe("nuclei_default_login")
    expect(verdictVariant(vin("nuclei", "t", { tags: ["default-logins-x"] }))).toBe("nuclei_check")
    expect(verdictVariant(vin("nuclei", "t", null))).toBe("nuclei_check")
    expect(verdictVariant(vin("nuclei", "exposed_panel", { tags: 5 }))).toBe("nuclei_check")
    expect(verdictVariant(vin("nuclei", "exposed_panel"))).toBe("nuclei_check")
    expect(verdictVariant(vin("constellus", "exposed_service", {}))).toBe("exposed_service_unidentified")
    expect(verdictVariant(vin("constellus", "exposed_service", { confidence: "potential" }))).toBe("exposed_service_unidentified")
    expect(verdictVariant(vin("constellus", "dangling_dns", { layer: "something_new" }))).toBe("other")
    expect(verdictVariant(vin("constellus", "dangling_dns", {}))).toBe("other")
    expect(verdictVariant(vin("constellus", "x"))).toBe("other")
    expect(verdictVariant(vin("version_match", "x"))).toBe("other")
    expect(verdictVariant(vin("shodan", "cve", { shodan_verified: false }))).toBe("shodan_cve")
    expect(verdictVariant(vin("shodan", "cve", { shodan_verified: null }))).toBe("shodan_cve")
    expect(verdictVariant(vin("shodan", "cve", {}))).toBe("shodan_cve")
    expect(verdictVariant(vin("shodan", "cve", { shodan_verified: "true" }))).toBe("shodan_cve")
    expect(verdictVariant(vin("shodan", "honeypot"))).toBe("shodan_label")
    expect(verdictVariant(vin("shodan", "x"))).toBe("other")
    expect(verdictVariant(vin("tenable", "cve"))).toBe("other")
    expect(() => verdictVariant({} as VIn)).not.toThrow()
    expect(verdictVariant({} as VIn)).toBe("other")
  })

  it("invariants over every entry", () => {
    const entries = Object.entries(VERDICTS)
    expect(Object.keys(VERDICTS)).toHaveLength(13)
    for (const [k, v] of entries) {
      expect(v.label, k).not.toMatch(/confirmed|exploited/i)
      for (const part of [v.label, v.saw, v.didNot]) {
        expect(part.length, k).toBeGreaterThan(0)
        expect(part, k).not.toMatch(/\d/)
      }
      expect(v.saw, k).not.toMatch(/exploit/i)
      expect(v.didNot, k).not.toMatch(/exploit/i)
    }
  })

  it("the component prints label, both headings and both sentences, with no button", () => {
    const html = render(<VerdictBand finding={vin("version_match", "cve")} />)
    const t = text(html).replace(/&#x27;/g, "'")
    expect(t).toContain("Inferred from a version")
    expect(t).toContain("What we saw")
    expect(t).toContain("What we did not do")
    expect(t).toContain("Software on this host reported a version number, and that version is in the range this CVE affects.")
    expect(t).toContain("We did not test for the weakness itself. A vendor can patch it without changing the version number, so this can overstate.")
    expect(html).not.toContain("<button")
    expect(html.indexOf("What we saw")).toBeGreaterThanOrEqual(0)
    expect(html.indexOf("What we saw")).toBeLessThan(html.indexOf("What we did not do"))
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
  it("puts the verdict band above the first question", () => {
    const f = { title: TITLE, source: "version_match", finding_type: "cve", detail: {}, attribution: attribution(), exposure_paths: [path()] } as Finding
    const html = render(<TraceChains finding={f} />)
    expect(html.indexOf("Inferred from a version")).toBeGreaterThanOrEqual(0)
    expect(html.indexOf("Inferred from a version")).toBeLessThan(html.indexOf("Is it yours?"))
    expect(html.indexOf("Is it yours?")).toBeLessThan(html.indexOf("Can it be reached?"))
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
