import { describe, expect, it } from "vitest"
import type {
  AssetSurface, AttributionChain, AttributionEvidence, AttributionHop, ClaimEvidence,
  ExposureHop, ExposureHopCandidate, ExposurePath, RelationEvidence, SignalEvidence,
} from "@/lib/api"
import {
  STATUS_LABEL, STATUS_LEGEND, attributionHopCaption, attributionHopTitle, attributionLinkText,
  attributionSummary, candidateMeta, candidatesTitle, chainsNote, evidenceDocumentId, evidenceMeta,
  evidenceTitle, exposureHopCaption, exposureHopTitle, exposureSummary, humanise, observationLabel,
  ownershipAnswer, pathsAnswer, plural, seenText, sourcesText, traceDate,
} from "@/lib/trace"

const T1 = "2026-11-09T12:00:00Z"
const T2 = "2026-11-12T12:00:00Z"
const HOST = "shop.brightwatercold.example"
const ADDR = "203.0.113.47"

const cand = (over: Partial<ExposureHopCandidate> = {}): ExposureHopCandidate => ({
  asset_id: "a1", asset_type: "dns_record", value: HOST, record_type: "CNAME", distance: 1,
  link_first_seen_at: null, link_last_seen_at: null, ...over,
})

const base = { status: "observed" as const, reason: null, evidence: [], evidence_truncated: false, tier: null, first_seen_at: null, last_seen_at: null }

const orgHop = (over: Partial<Extract<AttributionHop, { kind: "organization" }>> = {}): AttributionHop => ({
  ...base, kind: "organization", entity_id: "e1", name: "Halvard Rhys Freight", relationship: "ours",
  marked_at: null, marked_by_id: null, marked_by_name: null, ...over,
})
const entityHop = (over: Partial<Extract<AttributionHop, { kind: "entity" }>> = {}): AttributionHop => ({
  ...base, kind: "entity", entity_id: "e2", name: "Brightwater Cold Chain", relation: "acquired", ...over,
})
const scopeHop = (over: Partial<Extract<AttributionHop, { kind: "scope" }>> = {}): AttributionHop => ({
  ...base, kind: "scope", target_id: "t1", target_type: "domain", value: "brightwatercold.example", candidate_id: null,
  claimed_at: null, claimed_by_id: null, claimed_by_name: null, ...over,
})
const hostHop = (over: Partial<Extract<AttributionHop, { kind: "host" }>> = {}): AttributionHop => ({
  ...base, kind: "host", asset_id: "h1", hostname: HOST, candidates: [], candidates_truncated: false, ...over,
})
const addrHop = (over: Partial<Extract<AttributionHop, { kind: "address" }>> = {}): AttributionHop => ({
  ...base, kind: "address", asset_id: "ip1", address: ADDR, ...over,
})

const relation = (over: Partial<RelationEvidence> = {}): RelationEvidence => ({
  kind: "relation", relation_id: "r1", relation: "acquired", source: "registry feed", tier: "strong",
  event_date: null, event_date_precision: "unknown", evidence_id: "doc1", confirmed_by: null, confirmed_at: null, ...over,
})
const signal = (over: Partial<SignalEvidence> = {}): SignalEvidence => ({
  kind: "signal", signal_id: "s1", signal_type: "registrant_org_match", label: "Registrant organization match",
  source: "whois", tier: "supporting", evidence_id: "doc2", first_seen_at: T1, last_seen_at: T2, ...over,
})
const claim = (over: Partial<ClaimEvidence> = {}): ClaimEvidence => ({
  kind: "claim", claim_id: "c1", claim_type: "observation", source: "cert log", source_trust: "observed", tier: "context",
  outcome: null, first_seen_at: T1, last_seen_at: T1, ...over,
})

const xbase = { status: "observed" as const, reason: null, sources: [], first_seen_at: null, last_seen_at: null }
const portHop = (over: Partial<Extract<ExposureHop, { kind: "port" }>> = {}): ExposureHop => ({
  ...xbase, kind: "port", port: 443, protocol: "tcp", ...over,
})
const xhost = (over: Partial<Extract<ExposureHop, { kind: "host" }>> = {}): ExposureHop => ({
  ...xbase, kind: "host", asset_id: "h1", hostname: HOST, candidates: [], candidates_truncated: false, ...over,
})
const xaddr = (over: Partial<Extract<ExposureHop, { kind: "address" }>> = {}): ExposureHop => ({
  ...xbase, kind: "address", asset_id: "ip1", address: ADDR, candidates: [], candidates_truncated: false, ...over,
})
const xservice = (over: Partial<Extract<ExposureHop, { kind: "service" }>> = {}): ExposureHop => ({
  ...xbase, kind: "service", asset_id: null, service: "nginx", version: "1.25.3", protocol: "tcp", ...over,
})
const xfinding = (over: Partial<Extract<ExposureHop, { kind: "finding" }>> = {}): ExposureHop => ({
  ...xbase, kind: "finding", finding_id: "f1", finding_type: "exposed_admin_panel", ...over,
})
const xinternet = (over: Partial<Extract<ExposureHop, { kind: "internet" }>> = {}): ExposureHop => ({
  ...xbase, kind: "internet", ...over,
})
const path = (over: Partial<ExposurePath> = {}): ExposurePath => ({
  endpoint_id: "p1", observation: "current", first_seen_at: T1, last_seen_at: T2,
  hops: [xinternet(), xhost(), xaddr(), portHop(), xservice(), xfinding()], ...over,
})

describe("basics", () => {
  it("labels and legend", () => {
    expect(STATUS_LABEL).toEqual({ observed: "Observed", derived: "Derived", unknown: "Not on record", not_applicable: "Does not apply" })
    expect(STATUS_LEGEND.map((l) => l.status)).toEqual(["observed", "derived", "unknown"])
    expect(STATUS_LEGEND.map((l) => l.meaning)).toEqual([
      "A source recorded it.", "Worked out from other records. Listed, never picked.", "Nothing on file. The reason is shown.",
    ])
  })
  it("traceDate uses local parts", () => {
    expect(traceDate(T1)).toBe("9 Nov 2026")
    expect(traceDate(null)).toBeNull()
    expect(traceDate(undefined)).toBeNull()
    expect(traceDate("not a date")).toBeNull()
  })
  it("plural and humanise", () => {
    expect(plural(1, "place", "places")).toBe("1 place")
    expect(plural(0, "place", "places")).toBe("0 places")
    expect(plural(2, "place", "places")).toBe("2 places")
    expect(humanise("confirmed_ours")).toBe("confirmed ours")
  })
})

describe("R1 ownershipAnswer", () => {
  it("takes only the surface", () => {
    expect(ownershipAnswer.length).toBe(1)
  })
  it("answers each surface", () => {
    const note = "The records below show how it came into scope. They do not make it yours."
    const cases: [AssetSurface, string, string | null][] = [
      ["proven_ours", "Yes. The record proves this is yours.", null],
      ["claimed_ours", "Claimed as yours, not proven.", null],
      ["not_ours", "No. The record says this is not yours.", note],
      ["unknown", "Not checked.", note],
    ]
    for (const [s, headline, n] of cases) expect(ownershipAnswer(s)).toEqual({ headline, note: n })
  })
})

describe("chainsNote", () => {
  it("covers each branch", () => {
    expect(chainsNote(0, false)).toBeNull()
    expect(chainsNote(1, false)).toBeNull()
    expect(chainsNote(3, false)).toBe("3 chains on record. None is the main one.")
    expect(chainsNote(3, true)).toBe("3 chains on record. None is the main one. More exist than are shown.")
    expect(chainsNote(1, true)).toBe("More chains exist than are shown.")
    expect(chainsNote(0, true)).toBe("More chains exist than are shown.")
  })
})

describe("candidatesTitle", () => {
  it("host", () => {
    const h = (n: number, t = false) => candidatesTitle({ kind: "host", candidates: Array.from({ length: n }, () => cand()), candidates_truncated: t })
    expect(h(0)).toBe("No hostname on record")
    expect(h(1)).toBe("1 hostname points here")
    expect(h(4)).toBe("4 hostnames point here")
    expect(h(4, true)).toBe("More than 4 hostnames point here")
  })
  it("address", () => {
    const a = (n: number, t = false) => candidatesTitle({ kind: "address", candidates: Array.from({ length: n }, () => cand()), candidates_truncated: t })
    expect(a(0)).toBe("No address on record")
    expect(a(1)).toBe("Points at 1 address")
    expect(a(3)).toBe("Points at 3 addresses")
    expect(a(3, true)).toBe("Points at more than 3 addresses")
  })
})

describe("candidateMeta", () => {
  it("builds fragments", () => {
    expect(candidateMeta(cand())).toEqual(["CNAME", "its own address record"])
    expect(candidateMeta(cand({ distance: 2, record_type: null, link_last_seen_at: T1 }))).toEqual(["through 1 CNAME record", "last seen 9 Nov 2026"])
    expect(candidateMeta(cand({ distance: 4 }))).toEqual(["CNAME", "through 3 CNAME records"])
  })
})

describe("attributionHopTitle", () => {
  it("organization", () => {
    expect(attributionHopTitle(orgHop())).toEqual({ text: "Halvard Rhys Freight", mono: false, href: "/organizations/entity/e1", missing: false })
    expect(attributionHopTitle(orgHop({ entity_id: null }))).toMatchObject({ href: null, missing: false })
    expect(attributionHopTitle(orgHop({ name: null, entity_id: null, status: "unknown", reason: "  odd reason " })))
      .toEqual({ text: "No organization on record", mono: false, href: null, missing: true })
  })
  it("entity", () => {
    expect(attributionHopTitle(entityHop())).toEqual({ text: "Brightwater Cold Chain", mono: false, href: "/organizations/entity/e2", missing: false })
  })
  it("scope", () => {
    expect(attributionHopTitle(scopeHop())).toEqual({ text: "brightwatercold.example", mono: true, href: "/targets/t1", missing: false })
    expect(attributionHopTitle(scopeHop({ target_id: null }))).toMatchObject({ href: null, missing: false })
    expect(attributionHopTitle(scopeHop({ value: null, target_id: null, status: "unknown" })))
      .toEqual({ text: "No target on record", mono: false, href: null, missing: true })
  })
  it("host and address", () => {
    expect(attributionHopTitle(hostHop())).toEqual({ text: HOST, mono: true, href: "/assets/h1", missing: false })
    expect(attributionHopTitle(hostHop({ asset_id: null }))).toMatchObject({ href: null })
    expect(attributionHopTitle(hostHop({ hostname: null, status: "unknown" }))).toMatchObject({ text: "No hostname on record", missing: true })
    expect(attributionHopTitle(addrHop())).toEqual({ text: ADDR, mono: true, href: "/assets/ip1", missing: false })
    expect(attributionHopTitle(addrHop({ asset_id: null }))).toMatchObject({ href: null })
    expect(attributionHopTitle(addrHop({ address: null, status: "unknown" }))).toMatchObject({ text: "No address on record", missing: true })
  })
  it("R3: a derived host with one candidate does not take its value", () => {
    const hop = hostHop({ status: "derived", hostname: null, candidates: [cand({ value: "only.brightwatercold.example" })] })
    const t = attributionHopTitle(hop)
    expect(t).toEqual({ text: "1 hostname points here", mono: false, href: null, missing: false })
    expect(t.text).not.toContain("only.brightwatercold.example")
    const out = attributionSummary({ target_id: null, hops: [hop] })
    expect(JSON.stringify(out)).not.toContain("only.brightwatercold.example")
  })
  it("R3: a derived exposure host or address with one candidate", () => {
    const h = xhost({ status: "derived", hostname: null, candidates: [cand({ value: "only.brightwatercold.example" })] })
    const a = xaddr({ status: "derived", address: null, candidates: [cand({ value: "203.0.113.99", asset_type: "ip_address" })] })
    expect(exposureHopTitle(h, null).text).toBe("1 hostname points here")
    expect(exposureHopTitle(a, null).text).toBe("Points at 1 address")
    const out = JSON.stringify(exposureSummary(path({ hops: [h, a] }), null))
    expect(out).not.toContain("only.brightwatercold.example")
    expect(out).not.toContain("203.0.113.99")
  })
})

describe("attributionHopCaption", () => {
  it("organization", () => {
    expect(attributionHopCaption(orgHop())).toBe("your organization")
    expect(attributionHopCaption(orgHop({ marked_at: T1, marked_by_id: "u1", marked_by_name: "Imogen Vale" }))).toBe("your organization, marked by Imogen Vale on 9 Nov 2026")
    expect(attributionHopCaption(orgHop({ marked_at: T1, marked_by_id: "u1", marked_by_name: null }))).toBe("your organization, marked by a person on 9 Nov 2026")
    expect(attributionHopCaption(orgHop({ marked_at: T1, marked_by_id: null }))).toBe("your organization, marked on 9 Nov 2026")
    expect(attributionHopCaption(orgHop({ relationship: "ma_target" }))).toBe("acquisition target")
    expect(attributionHopCaption(orgHop({ relationship: null }))).toBeNull()
  })
  it("ma_target ignores a marker", () => {
    expect(attributionHopCaption(orgHop({ relationship: "ma_target", marked_at: T1, marked_by_id: "u1", marked_by_name: "Imogen Vale" }))).toBe("acquisition target")
  })
  it("scope", () => {
    expect(attributionHopCaption(scopeHop({ claimed_at: T1, claimed_by_id: "u1", claimed_by_name: "Imogen Vale" }))).toBe("claimed by Imogen Vale on 9 Nov 2026")
    expect(attributionHopCaption(scopeHop({ claimed_at: T1, claimed_by_id: "u1", claimed_by_name: null }))).toBe("claimed by a person on 9 Nov 2026")
    const noId = attributionHopCaption(scopeHop({ claimed_at: T1, claimed_by_id: null }))
    expect(noId).toBe("claimed on 9 Nov 2026")
    expect(noId).not.toContain("by")
    expect(attributionHopCaption(scopeHop())).toBeNull()
  })
  it("other kinds", () => {
    expect(attributionHopCaption(entityHop())).toBeNull()
    expect(attributionHopCaption(hostHop())).toBeNull()
    expect(attributionHopCaption(addrHop())).toBeNull()
  })
})

describe("attributionLinkText", () => {
  it("organization has none", () => {
    expect(attributionLinkText(orgHop())).toBeNull()
  })
  it("entity relation wording", () => {
    expect(attributionLinkText(entityHop())).toBe("acquired by the entity above")
    expect(attributionLinkText(entityHop({ relation: "subsidiary_of" }))).toBe("a subsidiary of the entity above")
    expect(attributionLinkText(entityHop({ relation: null }))).toBeNull()
  })
  it("entity date at each precision", () => {
    const d = (precision: RelationEvidence["event_date_precision"]) =>
      attributionLinkText(entityHop({ evidence: [relation({ event_date: "2024-03-15", event_date_precision: precision })] }))
    expect(d("day")).toBe("acquired by the entity above, dated 15 Mar 2024")
    expect(d("month")).toBe("acquired by the entity above, dated Mar 2024")
    expect(d("year")).toBe("acquired by the entity above, dated 2024")
    expect(d("unknown")).toBe("acquired by the entity above")
    expect(attributionLinkText(entityHop({ evidence: [relation({ event_date: null, event_date_precision: "day" })] }))).toBe("acquired by the entity above")
  })
  it("entity with two rows appends no date", () => {
    const rows = [relation({ event_date: "2024-03-15", event_date_precision: "day" }), relation({ relation_id: "r2", event_date: "2024-03-15", event_date_precision: "day" })]
    expect(attributionLinkText(entityHop({ evidence: rows }))).toBe("acquired by the entity above")
  })
  it("scope", () => {
    expect(attributionLinkText(scopeHop())).toBeNull()
    expect(attributionLinkText(scopeHop({ evidence: [claim()] }))).toBe("Sighting")
    expect(attributionLinkText(scopeHop({ evidence: [claim(), signal(), claim({ claim_id: "c2" })] }))).toBe("linked by 3 signals")
  })
  it("host and address count distinct sources", () => {
    expect(attributionLinkText(hostHop())).toBeNull()
    expect(attributionLinkText(addrHop())).toBeNull()
    expect(attributionLinkText(hostHop({ evidence: [signal({ source: "whois" }), signal({ signal_id: "s2", source: "whois" })] }))).toBe("recorded by 1 source")
    expect(attributionLinkText(addrHop({ evidence: [signal({ source: "whois" }), claim({ source: "cert log" })] }))).toBe("recorded by 2 sources")
    expect(attributionLinkText(hostHop({ evidence: [signal({ source: null }), signal({ signal_id: "s2", source: null })] }))).toBe("2 records on file")
    expect(attributionLinkText(addrHop({ evidence: [signal({ source: null })] }))).toBe("1 record on file")
  })
})

describe("evidence", () => {
  it("titles", () => {
    expect(evidenceTitle(relation())).toBe("Acquired")
    expect(evidenceTitle(relation({ relation: "subsidiary_of" }))).toBe("Subsidiary of")
    expect(evidenceTitle(signal())).toBe("Registrant organization match")
    expect(evidenceTitle(signal({ label: null, signal_type: "shared_mail_server" }))).toBe("shared mail server")
    const claims: Record<string, string> = {
      observation: "Sighting", ct_cert_issuance: "Certificate issued", cloud_inventory: "Cloud inventory",
      affinity_confirmation: "Ownership check", tenancy: "Tenancy",
    }
    for (const [k, v] of Object.entries(claims)) expect(evidenceTitle(claim({ claim_type: k }))).toBe(v)
    expect(evidenceTitle(claim({ claim_type: "new_kind" }))).toBe("new kind")
  })
  it("relation meta", () => {
    expect(evidenceMeta(relation({ source: null }))).toEqual([])
    expect(evidenceMeta(relation({ event_date: "2024-03-15", event_date_precision: "month", confirmed_by: "person", confirmed_at: T1 })))
      .toEqual(["registry feed", "dated Mar 2024", "confirmed by a person on 9 Nov 2026"])
    expect(evidenceMeta(relation({ event_date: "2024-03-15", event_date_precision: "unknown", confirmed_by: "source" })))
      .toEqual(["registry feed", "confirmed by the source"])
  })
  it("signal meta", () => {
    expect(evidenceMeta(signal())).toEqual(["whois", "first seen 9 Nov 2026", "last seen 12 Nov 2026"])
    expect(evidenceMeta(signal({ last_seen_at: T1 }))).toEqual(["whois", "first seen 9 Nov 2026"])
    expect(evidenceMeta(signal({ source: null, first_seen_at: null, last_seen_at: null }))).toEqual([])
  })
  it("claim meta", () => {
    expect(evidenceMeta(claim({ outcome: "confirmed_ours", last_seen_at: T2 })))
      .toEqual(["outcome: confirmed ours", "cert log (observed)", "first seen 9 Nov 2026", "last seen 12 Nov 2026"])
    expect(evidenceMeta(claim({ source_trust: null, first_seen_at: null, last_seen_at: null }))).toEqual(["cert log"])
  })
  it("R2: meta never carries a tier word", () => {
    const rows: AttributionEvidence[] = [relation({ tier: "strong" }), signal({ tier: "supporting" }), claim({ tier: "context" })]
    for (const r of rows) {
      const text = evidenceMeta(r).join(" ").toLowerCase()
      expect(text).not.toMatch(/strong|supporting|context|tier|unknown/)
    }
  })
  it("document id", () => {
    expect(evidenceDocumentId(relation())).toBe("doc1")
    expect(evidenceDocumentId(signal())).toBe("doc2")
    expect(evidenceDocumentId(signal({ evidence_id: null }))).toBeNull()
    expect(evidenceDocumentId(claim())).toBeNull()
  })
})

describe("pathsAnswer and observationLabel", () => {
  it("answers", () => {
    expect(pathsAnswer([])).toBe("No place is recorded for this finding.")
    expect(pathsAnswer([path({ observation: "not_recorded" }), path({ observation: "not_recorded" })])).toBe("The source recorded no place for this finding.")
    expect(pathsAnswer([path()])).toBe("Observed at 1 place in the latest observation.")
    expect(pathsAnswer([path(), path()])).toBe("Observed at 2 places in the latest observation.")
    expect(pathsAnswer([path({ observation: "not_reobserved" })])).toBe("Not observed at any place in the latest observation. 1 earlier place was not seen again.")
    expect(pathsAnswer([path(), path({ observation: "not_reobserved" }), path({ observation: "not_reobserved" })]))
      .toBe("Observed at 1 place in the latest observation. 2 earlier places were not seen again.")
    expect(pathsAnswer([path(), path({ observation: "not_recorded" })])).toBe("Observed at 1 place in the latest observation.")
  })
  it("labels", () => {
    expect(observationLabel(path())).toBe("Seen in the latest observation")
    expect(observationLabel(path({ observation: "not_reobserved", last_seen_at: T2 }))).toBe("Not seen again since 12 Nov 2026")
    expect(observationLabel(path({ observation: "not_reobserved", last_seen_at: null }))).toBe("Not seen again")
    expect(observationLabel(path({ observation: "not_recorded" }))).toBe("No place recorded")
  })
  it("R4: not_reobserved never reads as closed", () => {
    const re = /closed|resolved|fixed|gone/i
    for (const last of [T2, null]) {
      const p = path({ observation: "not_reobserved", last_seen_at: last })
      expect(observationLabel(p)).not.toMatch(re)
      expect(pathsAnswer([p])).not.toMatch(re)
      expect(pathsAnswer([path(), p, p])).not.toMatch(re)
    }
  })
})

describe("exposureHopTitle", () => {
  it("internet, host, address", () => {
    expect(exposureHopTitle(xinternet(), null)).toEqual({ text: "Internet", mono: false, href: null, missing: false })
    expect(exposureHopTitle(xhost(), null)).toEqual({ text: HOST, mono: true, href: "/assets/h1", missing: false })
    expect(exposureHopTitle(xhost({ asset_id: null }), null)).toMatchObject({ text: HOST, href: null })
    expect(exposureHopTitle(xhost({ hostname: null, status: "unknown" }), null)).toMatchObject({ text: "No hostname on record", missing: true })
    expect(exposureHopTitle(xaddr(), null)).toEqual({ text: ADDR, mono: true, href: "/assets/ip1", missing: false })
    expect(exposureHopTitle(xaddr({ asset_id: null }), null)).toMatchObject({ href: null })
    expect(exposureHopTitle(xaddr({ address: null, status: "unknown" }), null)).toMatchObject({ text: "No address on record", missing: true })
  })
  it("port", () => {
    expect(exposureHopTitle(portHop(), null)).toEqual({ text: "443/tcp", mono: true, href: null, missing: false })
    expect(exposureHopTitle(portHop({ protocol: "udp", port: 53 }), null).text).toBe("53/udp")
    expect(exposureHopTitle(portHop({ port: null, protocol: null, status: "unknown" }), null)).toMatchObject({ text: "No port on record", missing: true })
  })
  it("R5: no protocol never prints tcp", () => {
    const hop = portHop({ protocol: null })
    expect(exposureHopTitle(hop, null).text).toBe("443")
    const seg = exposureSummary(path({ hops: [hop] }), null)
    expect(seg).toEqual([{ text: ":443", mono: true, missing: false }])
    expect(JSON.stringify(seg)).not.toContain("tcp")
  })
  it("service", () => {
    expect(exposureHopTitle(xservice(), null)).toEqual({ text: "nginx 1.25.3", mono: false, href: null, missing: false })
    expect(exposureHopTitle(xservice({ version: null }), null).text).toBe("nginx")
    expect(exposureHopTitle(xservice({ service: null, status: "unknown" }), null)).toMatchObject({ text: "No service on record", missing: true })
  })
  it("finding", () => {
    expect(exposureHopTitle(xfinding(), "Admin panel exposed").text).toBe("Admin panel exposed")
    expect(exposureHopTitle(xfinding(), null).text).toBe("exposed admin panel")
  })
  it("not_applicable on any kind", () => {
    const hops: ExposureHop[] = [xinternet(), xhost(), xaddr(), portHop(), xservice(), xfinding()].map((h) => ({ ...h, status: "not_applicable" as const }))
    for (const h of hops) expect(exposureHopTitle(h, "x")).toEqual({ text: "Does not apply", mono: false, href: null, missing: true })
  })
})

describe("captions and small texts", () => {
  it("exposureHopCaption", () => {
    expect(exposureHopCaption(xservice())).toBe("the port inventory lists tcp")
    expect(exposureHopCaption(xservice({ protocol: null }))).toBeNull()
    expect(exposureHopCaption(portHop())).toBeNull()
  })
  it("sourcesText", () => {
    expect(sourcesText([])).toBeNull()
    expect(sourcesText(["naabu", "shodan"])).toBe("Recorded by naabu, shodan")
  })
  it("seenText", () => {
    expect(seenText(T1, T2)).toBe("first seen 9 Nov 2026, last seen 12 Nov 2026")
    expect(seenText(T1, T1)).toBe("seen 9 Nov 2026")
    expect(seenText(T1, null)).toBe("first seen 9 Nov 2026")
    expect(seenText(null, T2)).toBe("last seen 12 Nov 2026")
    expect(seenText(null, null)).toBeNull()
  })
})

describe("summaries", () => {
  it("attributionSummary keeps unknown hops as missing", () => {
    const chain: AttributionChain = {
      target_id: null,
      hops: [orgHop(), scopeHop({ value: null, target_id: null, status: "unknown", reason: "No target covers this." }), hostHop(), addrHop({ address: null, status: "unknown" })],
    }
    expect(attributionSummary(chain)).toEqual([
      { text: "Halvard Rhys Freight", mono: false, missing: false },
      { text: "No target on record", mono: false, missing: true },
      { text: HOST, mono: true, missing: false },
      { text: "No address on record", mono: false, missing: true },
    ])
  })
  it("exposureSummary drops not_applicable hops and prefixes the port", () => {
    const p = path({ hops: [xinternet(), xhost(), xaddr({ status: "not_applicable" }), portHop(), xservice(), xfinding()] })
    expect(exposureSummary(p, "Admin panel exposed")).toEqual([
      { text: "Internet", mono: false, missing: false },
      { text: HOST, mono: true, missing: false },
      { text: ":443/tcp", mono: true, missing: false },
      { text: "nginx 1.25.3", mono: false, missing: false },
      { text: "Admin panel exposed", mono: false, missing: false },
    ])
  })
})

describe("R6 R7 R8 R2 sweeps", () => {
  it("unknown hops say nothing is on record and the reason is untouched", () => {
    const reason = "  Odd   spacing, kept.  "
    const hops: AttributionHop[] = [
      orgHop({ name: null, entity_id: null }), scopeHop({ value: null, target_id: null }),
      hostHop({ hostname: null }), addrHop({ address: null }),
    ].map((h) => ({ ...h, status: "unknown" as const, reason }))
    for (const h of hops) {
      const t = attributionHopTitle(h)
      expect(t.missing).toBe(true)
      expect(t.text).toMatch(/on record$/)
      expect(t.text).not.toBe("")
      expect(h.reason).toBe(reason)
    }
  })
  it("no output says registered, unknown tier or Unknown; labels pass through", () => {
    const sig = signal()
    const chain: AttributionChain = { target_id: "t1", hops: [orgHop(), entityHop({ evidence: [relation()] }), scopeHop({ evidence: [sig] }), hostHop({ evidence: [sig] }), addrHop({ evidence: [sig] })] }
    const outputs: string[] = []
    for (const hop of chain.hops) {
      outputs.push(attributionHopTitle(hop).text, attributionHopCaption(hop) ?? "", attributionLinkText(hop) ?? "")
      for (const e of hop.evidence) outputs.push(evidenceTitle(e), ...evidenceMeta(e))
    }
    outputs.push(...attributionSummary(chain).map((s) => s.text))
    const p = path()
    outputs.push(pathsAnswer([p]), observationLabel(p), ...exposureSummary(p, null).map((s) => s.text))
    outputs.push(...p.hops.map((h) => exposureHopTitle(h, null).text), ...STATUS_LEGEND.map((l) => l.meaning), ...Object.values(STATUS_LABEL))
    outputs.push(ownershipAnswer("unknown").headline, ownershipAnswer("unknown").note ?? "", chainsNote(2, true) ?? "")
    expect(evidenceTitle(sig)).toBe("Registrant organization match")
    for (const o of outputs) {
      expect(o.toLowerCase()).not.toContain("registered")
      expect(o).not.toMatch(/unknown/i)
    }
  })
  it("a signal type alone is humanised without inventing the word registered", () => {
    expect(evidenceTitle(signal({ label: null }))).toBe("registrant org match")
  })
})
