import { describe, expect, it } from "vitest"
import type { BindingSuggestion } from "@/lib/api"
import { inst, typ } from "@/lib/connectors.fixtures"
import {
  bindingControl, bindingErrorMessage, bindingWarning, clashReasonLabel, canSync, deleteConflictMessage, groupByPhase, hasZones, instancePatch, suggestionCopy,
} from "@/lib/connectors"

describe("groupByPhase", () => {
  it("buckets types by phase and leaves empty phases empty", () => {
    const g = groupByPhase([typ(), typ({ id: "naabu", phase: "scanning" })])
    expect(g.discovery.map((t) => t.id)).toEqual(["cloudflare"])
    expect(g.scanning.map((t) => t.id)).toEqual(["naabu"])
    expect(g.enrichment).toEqual([])
  })
})

describe("bindingWarning / canSync", () => {
  it("warns only when the binding is no longer allowed, and then blocks sync", () => {
    expect(bindingWarning(inst())).toBeNull()
    expect(bindingWarning(inst({ binding_ok: false }))).toContain("Syncing is paused")
    expect(canSync(typ(), inst())).toBe(true)
    expect(canSync(typ(), inst({ binding_ok: false }))).toBe(false)
    expect(canSync(typ(), inst({ enabled: false }))).toBe(false)
    expect(canSync(typ({ account_scoped: false, supports_zones: false }), inst())).toBe(false)
    expect(hasZones(typ({ supports_zones: false }))).toBe(false)
  })
})

describe("suggestionCopy", () => {
  const cands = [{ entity_id: "o1", name: "Example Holdings A", matches: 3 }]
  it("names the match count for a suggestion", () => {
    const s: BindingSuggestion = { suggested_entity_id: "o1", candidates: cands, zone_count: 12 }
    expect(suggestionCopy(s)).toBe("3 of 12 zones match Example Holdings A")
  })
  it("says plainly when nothing matches", () => {
    const s: BindingSuggestion = { suggested_entity_id: null, candidates: [], zone_count: 12 }
    expect(suggestionCopy(s)).toContain("No organization's claimed domains match these zones")
  })
  it("points at the token when the provider returned no zones", () => {
    const s: BindingSuggestion = { suggested_entity_id: null, candidates: [], zone_count: 0 }
    expect(suggestionCopy(s)).toContain("Check the token with Test")
  })
  it("lists a tie instead of choosing", () => {
    const s: BindingSuggestion = {
      suggested_entity_id: null, zone_count: 4,
      candidates: [...cands, { entity_id: "o2", name: "Example Holdings B", matches: 3 }],
    }
    expect(suggestionCopy(s)).toContain("Example Holdings A: 3, Example Holdings B: 3")
  })
})

describe("bindingErrorMessage", () => {
  it("reads each 422 code", () => {
    expect(bindingErrorMessage({ detail: { code: "binding_required", reason: "x" } })).toContain("Pick the organization")
    expect(bindingErrorMessage({ detail: { code: "binding_forbidden", reason: "x" } })).toContain("global")
    expect(bindingErrorMessage({ detail: { code: "binding_not_allowed", reason: "deal_not_closed" } })).toContain("has not closed")
    expect(bindingErrorMessage({ detail: { code: "binding_not_allowed", reason: "not_visible" } })).toContain("do not have access")
  })
  it("falls back to a plain-string detail, then the message", () => {
    expect(bindingErrorMessage({ detail: "name must not be empty" })).toBe("name must not be empty")
    expect(bindingErrorMessage({ message: "Request failed" })).toBe("Request failed")
  })
})

describe("deleteConflictMessage", () => {
  it("counts the referencing targets from the 409 body", () => {
    expect(deleteConflictMessage({ status: 409, body: { target_ids: ["a", "b"] } })).toBe("Used by 2 targets — disable it instead")
    expect(deleteConflictMessage({ status: 409, body: { target_ids: ["a"] } })).toBe("Used by 1 target — disable it instead")
  })
  it("is null for any other status", () => {
    expect(deleteConflictMessage({ status: 500, body: { target_ids: ["a"] } })).toBeNull()
  })
})

describe("clashReasonLabel", () => {
  it("words all five server reasons and passes an unknown one through", () => {
    expect(clashReasonLabel("claimed_by_other_org")).toBe("already claimed by another organization")
    expect(clashReasonLabel("target_in_other_scope")).toBe("already a target in another scope")
    expect(clashReasonLabel("target_other_entity")).toBe("already a target of another company")
    expect(clashReasonLabel("not_a_claimable_domain")).toBe("not a domain that can be claimed")
    expect(clashReasonLabel("conflict_not_visible")).toBe("conflicts with something you can't see")
    expect(clashReasonLabel("brand_new_reason")).toBe("brand_new_reason")
  })
})

describe("bindingControl", () => {
  it("covers all four combinations", () => {
    expect(bindingControl(true, true)).toBe("picker")
    expect(bindingControl(true, false)).toBe("blocked")
    expect(bindingControl(false, true)).toBe("picker")
    expect(bindingControl(false, false)).toBe("readonly")
  })
})

describe("instancePatch", () => {
  const cur = { name: "A", bound_entity_id: "o1" }
  it("sends a changed binding only with decide permission", () => {
    expect(instancePatch(cur, { name: "A", org: "o2" }, true)).toEqual({ bound_entity_id: "o2" })
    expect(instancePatch(cur, { name: "A", org: "o2" }, false)).toEqual({})
  })
  it("omits an unchanged or empty binding even with permission, and always sends a rename", () => {
    expect(instancePatch(cur, { name: "A", org: "o1" }, true)).toEqual({})
    expect(instancePatch(cur, { name: "A", org: "" }, true)).toEqual({})
    expect(instancePatch(cur, { name: " B ", org: "o2" }, false)).toEqual({ name: "B" })
  })
})
