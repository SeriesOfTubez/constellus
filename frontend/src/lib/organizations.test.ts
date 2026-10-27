import { describe, expect, it } from "vitest"
import {
  defaultSegment,
  type AddOrgState, type CandidateRow, type SignalDetail, type TreeNode,
  addOrgRequest, addOrgStepValid, filerStatsLine, relationshipOptions,
  entityHref, orgEntityTarget, registryChangeText, registryHolder,
  formatClosed, formatShare, ipSpaceLabel, postureLabel,
  anchorText, candidateParams, groupRows, relationNote, segmentCount, severityBar, splitSignals, stateInfo, tierChipClass, treeRows,
} from "@/lib/organizations"

const row = (over: Partial<CandidateRow> = {}): CandidateRow => ({
  id: "c1", root_entity_id: "r", value: "fabrikam.com", kind: "domain", status: "open", strength: "strong", proposable: true,
  affiliated: { id: "a", name: "Example Holdings A" }, affiliated_is_default: false, signals: [], first_seen_at: null,
  previously_rejected: null, target_id: null, decided_by_connector_instance_id: null, asset_count: null,
  open_findings: null, worst_severity: null, rir: null, rir_handle: null, ...over,
})

describe("candidateParams", () => {
  it("maps each segment to a status", () => {
    expect(candidateParams({ segment: "candidates" }).get("status")).toBe("open")
    expect(candidateParams({ segment: "claimed" }).get("status")).toBe("claimed")
    expect(candidateParams({ segment: "rejected" }).get("status")).toBe("rejected")
    expect(candidateParams({ segment: "all" }).get("status")).toBe("all")
  })
  it("carries filters, paging and leads_only (which replaces status)", () => {
    const p = candidateParams({ segment: "candidates", q: "fab", strength: "strong", signalType: "mx_into_claimed", subtreeOf: "n1", offset: 200 })
    expect(p.get("q")).toBe("fab"); expect(p.get("strength")).toBe("strong")
    expect(p.get("signal_type")).toBe("mx_into_claimed"); expect(p.get("subtree_of")).toBe("n1")
    expect(p.get("limit")).toBe("200"); expect(p.get("offset")).toBe("200")
    const l = candidateParams({ segment: "candidates", leadsOnly: true, strength: "all", signalType: "all" })
    expect(l.get("leads_only")).toBe("true"); expect(l.has("status")).toBe(false)
    expect(l.has("strength")).toBe(false); expect(l.has("signal_type")).toBe(false)
  })
  it("segment counts come from the summary", () => {
    const s = { claimed: 3, to_review: 5, leads: 2, rejected: 1, assets_under_claimed_scope: 0, affiliates: 0, proposed_affiliates: 0, has_filer: false }
    expect(segmentCount("candidates", s)).toBe(5)
    expect(segmentCount("all", s)).toBe(9)
  })
})

describe("anchorText", () => {
  const a = (kind: string, over = {}) => ({ kind, candidate_id: null, candidate_value: null, entity_id: null, entity_name: null, user_id: null, ...over })
  it("derives text from the anchor kind", () => {
    expect(anchorText(a("claimed_candidate", { candidate_value: "contoso.com" }))).toBe("via claimed domain contoso.com")
    expect(anchorText(a("filer_filing", { entity_name: "Example Holdings A" }))).toBe("via filer Example Holdings A")
    expect(anchorText(a("person"))).toBe("via a person")
    expect(anchorText(a("connector_instance"))).toBe("via connector")
  })
})

describe("tierChipClass", () => {
  it("never uses a severity colour", () => {
    for (const t of ["strong", "supporting", "context"]) {
      expect(tierChipClass(t)).not.toMatch(/red|orange|yellow|blue|amber/)
    }
    expect(tierChipClass("strong")).toContain("bg-primary")
    expect(tierChipClass("context")).toContain("muted")
  })
})

describe("severityBar", () => {
  it("builds ordered segments and the worst severity", () => {
    const b = severityBar({ critical: 0, high: 1, medium: 3, low: 0, unknown: 0 })
    expect(b.total).toBe(4)
    expect(b.worst).toBe("high")
    expect(b.segments.map(s => s.severity)).toEqual(["high", "medium"])
    expect(b.segments[1].pct).toBe(75)
  })
  it("is empty for null or all-zero counts", () => {
    expect(severityBar(null).worst).toBeNull()
    expect(severityBar({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }).segments).toEqual([])
  })
})

describe("tree", () => {
  const n = (over: Partial<TreeNode>): TreeNode => ({
    entity_id: "e", name: "X", parent_id: null, relation: null, event_date: null, status: "confirmed", depth: 0, ...over,
  })
  it("notes the relation", () => {
    expect(relationNote("acquired", "2021-06-30")).toBe("acquired 2021")
    expect(relationNote("acquired", null)).toBe("acquired")
    expect(relationNote("subsidiary_of", null)).toBe("subsidiary")
    expect(relationNote(null, null)).toBeNull()
  })
  it("indents by depth and makes proposed nodes non-selectable", () => {
    const rows = treeRows([n({}), n({ entity_id: "b", depth: 1, relation: "subsidiary_of" }), n({ entity_id: "c", depth: 2, status: "proposed" })])
    expect(rows.map(r => r.indent)).toEqual([0, 1, 2])
    expect(rows.map(r => r.selectable)).toEqual([true, true, false])
    expect(rows[1].note).toBe("subsidiary")
  })
})

describe("stateInfo / grouping / signals", () => {
  it("labels claimed seed, connector and previously rejected", () => {
    const seed = [{ signal_type: "admin_seed", tier: "strong" as const, family: "seed", count: 1 }]
    expect(stateInfo(row({ status: "claimed", signals: seed })).label).toBe("Claimed · seed")
    expect(stateInfo(row({ status: "claimed" })).label).toBe("Claimed")
    expect(stateInfo(row({ decided_by_connector_instance_id: "k" })).viaConnector).toBe(true)
    expect(stateInfo(row({ previously_rejected: { reason: "x", at: "t" } })).previouslyRejected).toBe(true)
  })
  it("groups by organization and by signal", () => {
    const rs = [row({ id: "1" }), row({ id: "2", affiliated: { id: "b", name: "Example Holdings B" } })]
    expect(groupRows(rs, "organization", t => t).map(g => g.label)).toEqual(["Example Holdings A", "Example Holdings B"])
    expect(groupRows(rs, "signal", t => t).map(g => g.label)).toEqual(["No signals"])
  })
  it("splits Context from counting signals, Strong first", () => {
    const d = (id: string, tier: SignalDetail["tier"]) => ({ id, tier } as SignalDetail)
    const s = splitSignals([d("a", "supporting"), d("b", "context"), d("c", "strong")])
    expect(s.counting.map(x => x.id)).toEqual(["c", "a"])
    expect(s.context.map(x => x.id)).toEqual(["b"])
  })
})

describe("add-organization helpers", () => {
  const st = (over: Partial<AddOrgState> = {}): AddOrgState => ({
    domain: "  fabrikam.com ", cik: "0000000001", orgName: " Example Holdings A ", relationship: "ours",
    reference: " TICKET-1 ", engagementName: "", ...over,
  })
  it("filerStatsLine formats and marks partial", () => {
    const s = { total_filings: 12, first_filing: "2001-02-03", last_filing: "2024-05-06", latest_10k: "2024-03-01", partial: false }
    expect(filerStatsLine(s)).toBe("12 filings, 2001–2024, latest 10-K 2024-03-01")
    expect(filerStatsLine({ ...s, partial: true })).toBe("12 filings, 2001–2024, latest 10-K 2024-03-01 (partial)")
    expect(filerStatsLine({ ...s, total_filings: 1, first_filing: null, latest_10k: null })).toBe("1 filing")
    expect(filerStatsLine(null)).toBeNull()
  })
  it("addOrgRequest trims and nulls", () => {
    expect(addOrgRequest(st())).toEqual({
      seed_domain: "fabrikam.com", org_name: "Example Holdings A", cik: "0000000001",
      relationship: "ours", reference: "TICKET-1", engagement_name: null,
    })
  })
  it("addOrgRequest: cik null for none; engagement_name null for ours even if typed; set for ma_target", () => {
    expect(addOrgRequest(st({ cik: null, engagementName: "Typed earlier" }))).toMatchObject({ cik: null, engagement_name: null })
    expect(addOrgRequest(st({ relationship: "ma_target", engagementName: " Deal X " }))).toMatchObject({ engagement_name: "Deal X" })
  })
  it("addOrgRequest refuses a missing relationship", () => {
    expect(() => addOrgRequest(st({ relationship: null }))).toThrow()
  })
  it("step validity", () => {
    expect(addOrgStepValid(1, st({ domain: "   " }), true)).toBe(false)
    expect(addOrgStepValid(1, st(), true)).toBe(true)
    expect(addOrgStepValid(2, st({ domain: "" }), true)).toBe(true)
    expect(addOrgStepValid(3, st(), true)).toBe(true)
    expect(addOrgStepValid(3, st({ reference: "  " }), true)).toBe(false)
    expect(addOrgStepValid(3, st({ orgName: " " }), true)).toBe(false)
    expect(addOrgStepValid(3, st({ relationship: null }), true)).toBe(false)
    expect(addOrgStepValid(3, st(), false)).toBe(false)
    expect(addOrgStepValid(3, st({ relationship: "ma_target" }), false)).toBe(false) // no engagement name
    expect(addOrgStepValid(3, st({ relationship: "ma_target", engagementName: "Deal X" }), false)).toBe(true)
  })
  it("relationshipOptions", () => {
    expect(relationshipOptions(true).map(o => [o.value, o.disabled])).toEqual([["ours", false], ["ma_target", false]])
    const noPerm = relationshipOptions(false)
    expect(noPerm[0]).toMatchObject({ value: "ours", disabled: true, hint: "Needs permission to mark organizations as ours" })
    expect(noPerm[1].disabled).toBe(false)
    expect(relationshipOptions(true, "ours").map(o => o.value)).toEqual(["ours"])
  })
})

describe("entity links", () => {
  const ID = "7a1b2c3d-0000-4000-8000-000000000001"
  it("entityHref points at the resolver route", () => {
    expect(entityHref(ID)).toBe(`/organizations/entity/${ID}`)
  })
  it("orgEntityTarget omits node for a root", () => {
    expect(orgEntityTarget({ org_id: "o1", node: null })).toBe("/organizations/o1?tab=companies")
  })
  it("orgEntityTarget carries the node", () => {
    expect(orgEntityTarget({ org_id: "o1", node: "n2" })).toBe("/organizations/o1?tab=companies&node=n2")
  })
})

describe("defaultSegment", () => {
  it("opens on Candidates while there is something to review", () => {
    expect(defaultSegment({ claimed: 3, proposed: 2 })).toBe("candidates")
    expect(defaultSegment({ claimed: 0, proposed: 0 })).toBe("candidates")
  })
  it("opens on All when nothing is to review but something is claimed (a just-added org)", () => {
    expect(defaultSegment({ claimed: 1, proposed: 0 })).toBe("all")
  })
})

describe("registry observations (S3d)", () => {
  const r = (over = {}) => ({ rir: "arin", prefix: "192.0.2.0/25", new_holder_kind: "org" as const, new_holder_handle: "EXAMPLE-ORG-1", ...over })
  it("words each holder kind exactly", () => {
    expect(registryChangeText(r())).toBe("ARIN now lists 192.0.2.0/25 under EXAMPLE-ORG-1 (organization)")
    expect(registryChangeText(r({ new_holder_kind: "customer", new_holder_handle: "CUST-EX1" }))).toBe("ARIN now lists 192.0.2.0/25 under CUST-EX1 (customer)")
    expect(registryChangeText(r({ new_holder_kind: "unknown", new_holder_handle: null }))).toBe("ARIN now lists 192.0.2.0/25 under an unidentified holder")
    expect(registryChangeText(r({ new_holder_kind: "unregistered", new_holder_handle: null }))).toBe("ARIN shows 192.0.2.0/25 is no longer registered to anyone")
  })
  it("treats org/customer without a handle as unknown, and a null rir as The registry", () => {
    expect(registryChangeText(r({ new_holder_handle: null }))).toBe("ARIN now lists 192.0.2.0/25 under an unidentified holder")
    expect(registryChangeText(r({ new_holder_kind: "customer", new_holder_handle: null }))).toContain("an unidentified holder")
    expect(registryChangeText(r({ rir: null }))).toBe("The registry now lists 192.0.2.0/25 under EXAMPLE-ORG-1 (organization)")
    expect(registryChangeText(r({ rir: "ripe" }))).toMatch(/^RIPE now lists/)
  })
  it("candidateParams carries kind and reassigned only when asked", () => {
    const p = candidateParams({ segment: "claimed", kind: "cidr", reassigned: true })
    expect(p.get("kind")).toBe("cidr"); expect(p.get("reassigned")).toBe("true")
    expect(candidateParams({ segment: "claimed", kind: "asn", reassigned: false }).get("reassigned")).toBe("false")
    expect(candidateParams({ segment: "claimed", kind: "domain" }).toString()).toBe(candidateParams({ segment: "claimed" }).toString())
    expect(candidateParams({ segment: "claimed" }).has("reassigned")).toBe(false)
  })
  it("registryHolder joins RIR and handle, dash when neither", () => {
    expect(registryHolder(row({ rir: "arin", rir_handle: "EXAMPLE-ORG-1" }))).toBe("ARIN · EXAMPLE-ORG-1")
    expect(registryHolder(row({ rir: "ripe", rir_handle: "ORG-EX1-RIPE" }))).toBe("RIPE · ORG-EX1-RIPE")
    expect(registryHolder(row())).toBe("—")
  })
})

describe("acquisition helpers", () => {
  it("formatClosed does not timezone-shift and honours precision", () => {
    expect(formatClosed("2021-03-01", "day")).toBe("1 Mar 2021")
    expect(formatClosed("2021-03-12", "day")).toBe("12 Mar 2021")
    expect(formatClosed("2021-03-01", "month")).toBe("Mar 2021")
    expect(formatClosed("2021-01-01", "year")).toBe("2021")
    expect(formatClosed("2021-03-12", "unknown")).toBe("12 Mar 2021")
    expect(formatClosed("2021-03-12", null)).toBe("12 Mar 2021")
    expect(formatClosed(null, "day")).toBe("—")
  })
  it("formatShare", () => {
    expect(formatShare(null)).toBe("—")
    expect(formatShare(0)).toBe("0%")
    expect(formatShare(0.004)).toBe("<1%")
    expect(formatShare(0.01)).toBe("1%")
    expect(formatShare(0.456)).toBe("46%")
  })
  it("ipSpaceLabel", () => {
    expect(ipSpaceLabel({ asns_claimed: 1, cidrs_claimed: 2 })).toBe("1 ASN · 2 prefixes")
    expect(ipSpaceLabel({ asns_claimed: 0, cidrs_claimed: 3 })).toBe("3 prefixes")
    expect(ipSpaceLabel({ asns_claimed: 2, cidrs_claimed: 1 })).toBe("2 ASNs · 1 prefix")
    expect(ipSpaceLabel({ asns_claimed: 0, cidrs_claimed: 0 })).toBe("—")
  })
  it("postureLabel", () => {
    expect(postureLabel("pre_close")).toBe("pre-close")
    expect(postureLabel("day_0")).toBe("day 0")
    expect(postureLabel("estate")).toBe("estate")
    expect(postureLabel("weird")).toBe("weird")
  })
})
