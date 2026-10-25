import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import OrganizationEntityRedirect, { locateKey } from "@/pages/OrganizationEntityRedirect"
import { ApiError } from "@/lib/api"

const ID = "7a1b2c3d-0000-4000-8000-000000000001"

function render(seed: (qc: QueryClient) => void) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  seed(qc)
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[`/organizations/entity/${ID}`]}>
        <Routes>
          <Route path="/organizations/entity/:id" element={<OrganizationEntityRedirect />} />
          <Route path="/organizations/:orgId" element={<p>LANDED</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe("OrganizationEntityRedirect", () => {
  it("a located root renders no skeleton and no message", () => {
    // <Navigate> acts in an effect, which renderToStaticMarkup never runs, so the
    // redirect target itself is asserted on orgEntityTarget (organizations.test.ts).
    // Here: a located entity renders neither the skeleton nor the 404 message.
    const html = render(qc => qc.setQueryData(locateKey(ID), { org_id: "o1", node: null }))
    expect(html).not.toContain("animate-pulse")
    expect(html).not.toContain("not part of an organization")
  })
  it("a located subsidiary renders no skeleton", () => {
    const html = render(qc => qc.setQueryData(locateKey(ID), { org_id: "o1", node: "n2" }))
    expect(html).not.toContain("animate-pulse")
  })
  it("shows a skeleton while loading, not the message or a redirect", () => {
    const html = render(() => {})
    expect(html).toContain("animate-pulse")
    expect(html).not.toContain("not part of an organization")
  })
  it("shows the not-visible message and a link on 404", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, retryOnMount: false } } })
    await qc.fetchQuery({ queryKey: locateKey(ID), queryFn: () => Promise.reject(new ApiError(404, "Not found")), retry: false }).catch(() => {})
    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[`/organizations/entity/${ID}`]}>
          <Routes><Route path="/organizations/entity/:id" element={<OrganizationEntityRedirect />} /></Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(html).toContain("This company is not part of an organization you can see.")
    expect(html).toContain('href="/organizations"')
  })
})
