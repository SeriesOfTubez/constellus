import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { CompanySeedStep } from "@/pages/admin/CompanySeedStep"

describe("CompanySeedStep", () => {
  it("search phase explains nothing is matched automatically and offers a skip", () => {
    const html = renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter>
          <CompanySeedStep onContinue={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(html).toContain("nothing is matched automatically")
    expect(html).toContain("Skip this step")
    expect(html).toContain("Search SEC filings")
    expect(html).toContain("match anywhere in the name")
  })
})
