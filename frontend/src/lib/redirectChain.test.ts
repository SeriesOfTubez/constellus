import { describe, expect, it } from "vitest"
import { hopSummary, refusedReasonText, type RedirectHop } from "./redirectChain"

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
