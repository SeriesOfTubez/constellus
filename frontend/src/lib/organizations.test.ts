import { describe, expect, it } from "vitest"
import {
  type CandidateRow, type SignalDetail, type TreeNode,
  anchorText, candidateParams, groupRows, relationNote, segmentCount, severityBar, splitSignals, stateInfo, tierChipClass, treeRows,
} from "@/lib/organizations"

const row = (over: Partial<CandidateRow> = {}): CandidateRow => ({
  id: "c1", root_entity_id: "r", value: "fabrikam.com", kind: "domain", status: "open", strength: "strong", proposable: true,
  affiliated: { id: "a", name: "Example Holdings A" }, affiliated_is_default: false, signals: [], first_seen_at: null,
  previously_rejected: null, target_id: null, decided_by_connector_instance_id: null, asset_count: null,
  open_findings: null, worst_severity: null, ...over,
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
