import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { RedirectChain } from "./RedirectChain"
import type { RedirectHop } from "@/lib/redirectChain"

const URL1 = "https://login.fabrikam.example/start"
const hop = (over: Partial<RedirectHop> = {}): RedirectHop => ({
  hop_index: 0, url: URL1, followed: true, reason: null,
  http_status: 200, http_title: "Sign in", hop_asset_id: null, ...over,
})
const render = (chain: RedirectHop[], compact = false) =>
  renderToStaticMarkup(<MemoryRouter><RedirectChain chain={chain} compact={compact} /></MemoryRouter>)

describe("RedirectChain", () => {
  it("renders nothing for an empty chain", () => expect(render([])).toBe(""))

  it("followed hop with asset links to the asset, never to the url", () => {
    const html = render([hop({ hop_asset_id: "abc-123" })])
    expect(html).toContain('href="/assets/abc-123"')
    expect(html).toContain("Redirects to")
    expect(html).toContain(">200<")
    expect(html).toContain("Sign in")
    expect(html).toContain('title="Page title of the redirect destination, not of this endpoint"')
    expect(html).not.toContain(`href="${URL1}"`)
  })

  it("without a hop asset there is no anchor at all", () => {
    const html = render([hop()])
    expect(html).not.toContain("<a")
    expect(html).toContain(URL1)
  })

  it("refused hop shows plain text and the rule tooltip", () => {
    const html = render([hop({ followed: false, reason: "posture:passive_only", http_status: null, http_title: null })])
    expect(html).toContain("Not followed:")
    expect(html).toContain("the target is limited to passive observation")
    expect(html).toContain('title="Rule: posture:passive_only"')
    expect(html).not.toContain("Page title of the redirect destination")
  })

  it("two hops: first 'Redirects to', then 'then', in order", () => {
    const html = render([
      hop({ hop_index: 0, url: "https://a.fabrikam.example/" }),
      hop({ hop_index: 1, url: "https://b.fabrikam.example/" }),
    ])
    expect(html.split("Redirects to").length - 1).toBe(1)
    expect(html.split(">then<").length - 1).toBe(1)
    expect(html.indexOf("Redirects to")).toBeLessThan(html.indexOf("a.fabrikam"))
    expect(html.indexOf("a.fabrikam")).toBeLessThan(html.indexOf(">then<"))
    expect(html.indexOf(">then<")).toBeLessThan(html.indexOf("b.fabrikam"))
  })

  it("compact and full variants differ in size class", () => {
    expect(render([hop()], true)).toContain("text-[10px]")
    expect(render([hop()])).toContain("text-xs")
  })
})
