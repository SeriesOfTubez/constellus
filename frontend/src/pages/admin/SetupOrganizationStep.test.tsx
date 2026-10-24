import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { SetupOrganizationStep } from "@/pages/admin/SetupOrganizationStep"

describe("SetupOrganizationStep", () => {
  it("starts at the domain step with a skip path and no registrant name search", () => {
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <SetupOrganizationStep onContinue={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(html).toContain("Your company")
    expect(html).toContain("Primary domain")
    expect(html).toContain("Skip this step")
    expect(html).not.toContain("Search SEC filings")
    expect(html).not.toContain("match anywhere")
  })
})
