import { describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { Sidebar } from "@/components/Sidebar"

describe("Sidebar", () => {
  it("links to organizations and no longer to /entities", () => {
    vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => {} })
    const html = renderToStaticMarkup(<MemoryRouter><Sidebar /></MemoryRouter>)
    expect(html).toContain('href="/organizations"')
    expect(html).toContain('href="/assets"') // the nav rendered at all
    expect(html).not.toContain('href="/entities"')
  })
})
