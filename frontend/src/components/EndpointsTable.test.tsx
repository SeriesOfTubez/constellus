import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { TooltipProvider } from "@/components/ui/tooltip"
import { EndpointsTable } from "./EndpointsTable"
import type { WebEndpointState } from "@/lib/webClassification"

const row = (over: Partial<WebEndpointState> = {}): WebEndpointState => ({
  port: 443, kind: null, environment: null, product: null, source: "none",
  http_title: null, http_status: 302, service: null, ai: null, override: null, active: null,
  last_failure: null, ai_inputs_changed: null, override_stale: null, ai_suggests: null,
  asset_id: "a1", asset_value: "203.0.113.7", asset_type: "ip",
  redirect_chain: [{
    hop_index: 1, url: "https://login.fabrikam.example/", followed: true, reason: null,
    http_status: 200, http_title: "Fabrikam Sign In", hop_asset_id: null,
  }],
  ...over,
})

const render = (rows: WebEndpointState[]) => renderToStaticMarkup(
  <MemoryRouter><TooltipProvider>
    <EndpointsTable groups={[{ key: "all", label: null, rows }]} onOpen={() => {}} filtered={false} />
  </TooltipProvider></MemoryRouter>,
)

describe("EndpointsTable redirect columns", () => {
  it("shows a redirecting endpoint's destination title marked as such, and both statuses", () => {
    const html = render([row()])
    expect(html).toContain("↪ Fabrikam Sign In")
    expect(html).toContain("Page title of the destination, not of this endpoint")
    expect(html).toContain("302 → 200")
  })
  it("keeps the endpoint's own title unmarked when it has one", () => {
    const html = render([row({ http_title: "Own Console", http_status: 200, redirect_chain: [] })])
    expect(html).toContain("Own Console")
    expect(html).not.toContain("↪")
  })
})
