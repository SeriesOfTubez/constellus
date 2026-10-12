import { describe, expect, it } from "vitest"
import { hopSummary, refusedReasonText, statusCell, titleCell, type RedirectHop } from "./redirectChain"

const hop = (over: Partial<RedirectHop> = {}): RedirectHop => ({
  hop_index: 0, url: "https://login.fabrikam.example/", followed: true, reason: null,
  http_status: null, http_title: null, hop_asset_id: null, ...over,
})

describe("refusedReasonText", () => {
  it.each([
    ["posture:passive_only", "the target is limited to passive observation"],
    ["probe_class:no_probe", "the destination is not authorised for probing"],
    ["probe_class:unprojected", "the destination has not been classified yet"],
    ["scope:unresolved_asset", "the destination is not a known asset"],
    ["unresolved_asset", "the destination is not a known asset"],
    ["scope:out_of_scope", "the destination is outside the scan scope"],
    ["scope:anything_else", "the destination is outside the scan scope"],
    ["addressing_not_permitted", "the destination cannot be probed this way"],
    ["no_authorised_names", "the destination has no authorised hostname"],
    ["denied", "the probe gate refused it"],
    ["loop", "the redirect loops back on itself"],
    ["hop_cap", "too many redirects (limit reached)"],
    ["unsupported_url", "the redirect URL is not supported"],
    ["ssrf_blocked", "the destination resolves to a private or reserved address"],
    ["dns_failed", "the destination hostname did not resolve"],
    ["worker_unavailable", "the scanner was unavailable"],
    ["some_new_reason", "some_new_reason"],
    ["constructor", "constructor"],
  ])("%s", (reason, text) => expect(refusedReasonText(reason)).toBe(text))
})

describe("hopSummary", () => {
  it("followed: status and title", () =>
    expect(hopSummary(hop({ http_status: 200, http_title: "Sign in" }))).toBe("200 · Sign in"))
  it("followed: status only", () => expect(hopSummary(hop({ http_status: 301 }))).toBe("301"))
  it("followed: title only", () => expect(hopSummary(hop({ http_title: "Sign in" }))).toBe("Sign in"))
  it("followed: neither", () => expect(hopSummary(hop())).toBe(""))
  it("followed: empty title ignored", () =>
    expect(hopSummary(hop({ http_status: 200, http_title: "" }))).toBe("200"))
  it("refused", () =>
    expect(hopSummary(hop({ followed: false, reason: "posture:passive_only", http_status: 200, http_title: "x" })))
      .toBe("Not followed: the target is limited to passive observation"))
})

describe("titleCell", () => {
  it("keeps the endpoint's own title over any chain", () => {
    expect(titleCell("Own Page", [hop({ http_title: "Dest" })])).toEqual({ text: "Own Page", tooltip: "Own Page", destination: false })
  })
  it("shows a dash with no title and no chain", () => {
    expect(titleCell(null, [])).toEqual({ text: "—", destination: false })
  })
  it("marks the LAST followed hop's title as the destination's", () => {
    const c = titleCell(null, [hop({ http_title: "Middle" }), hop({ hop_index: 2, url: "https://b.fabrikam.example/", http_title: "Final" })])
    expect(c.text).toBe("↪ Final")
    expect(c.destination).toBe(true)
    expect(c.tooltip).toBe("Redirects to https://b.fabrikam.example/. Page title of the destination, not of this endpoint")
  })
  it("says not followed with the plain reason and the raw rule for a refused last hop", () => {
    const c = titleCell(null, [hop({ followed: false, reason: "posture:passive_only" })])
    expect(c.text).toBe("↪ not followed")
    expect(c.tooltip).toBe("Redirects to https://login.fabrikam.example/. Not followed: the target is limited to passive observation (rule: posture:passive_only)")
  })
  it("shows a dash but keeps the destination URL when the followed hop has no title", () => {
    expect(titleCell(null, [hop({ http_status: 200 })])).toEqual({ text: "—", tooltip: "Redirects to https://login.fabrikam.example/", destination: true })
  })
})

describe("statusCell", () => {
  it("adds the final status of a followed chain", () => {
    expect(statusCell(302, [hop({ http_status: 301 }), hop({ hop_index: 2, http_status: 200 })])).toBe("302 → 200")
  })
  it("is the own status alone when the last hop was refused or has no status", () => {
    expect(statusCell(302, [hop({ followed: false, reason: "loop" })])).toBe("302")
    expect(statusCell(302, [hop()])).toBe("302")
    expect(statusCell(200, [])).toBe("200")
  })
  it("is a dash with no own status", () => {
    expect(statusCell(null, [hop({ http_status: 200 })])).toBe("—")
  })
})
