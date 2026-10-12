import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { EndpointHttpSummary } from "./EndpointSheet"
import type { WebEndpointState } from "@/lib/webClassification"

const row: WebEndpointState = {
  port: 443, kind: null, environment: null, product: null, source: "none",
  http_title: null, http_status: 302, service: null, ai: null, override: null, active: null,
  last_failure: null, ai_inputs_changed: null, override_stale: null, ai_suggests: null,
  asset_id: "a1", asset_value: "203.0.113.7", asset_type: "ip",
  redirect_chain: [{
    hop_index: 0, url: "https://login.fabrikam.example/", followed: true, reason: null,
    http_status: 200, http_title: "Fabrikam Sign In", hop_asset_id: null,
  }],
}

describe("EndpointSheet redirect chain", () => {
  it("never shows a hop title as the endpoint's own title", () => {
    const html = renderToStaticMarkup(<MemoryRouter><EndpointHttpSummary row={row} /></MemoryRouter>)
    expect(html).toContain("No page title recorded")
    expect(html.split("Fabrikam Sign In").length - 1).toBe(1)
    expect(html).toContain("Redirects to")
    expect(html).toContain('title="Page title of the redirect destination, not of this endpoint"')
  })
})
