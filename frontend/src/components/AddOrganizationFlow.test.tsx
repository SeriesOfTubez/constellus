import { afterEach, describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

// zustand's server snapshot ignores setState, so (as in OrgCandidateParts.test)
// the permission hook is mocked rather than the auth store seeded.
const perms = vi.hoisted(() => ({ current: [] as string[] }))
vi.mock("@/lib/permissions", () => ({
  useCan: () => (p: string) => perms.current.includes(p),
  usePermissionsSync: () => undefined,
}))

import { AddOrganizationFlow, OrgDetailsStep } from "@/components/AddOrganizationFlow"
import Organizations from "@/pages/Organizations"

const asUser = (permissions: string[]) => { perms.current = permissions }
afterEach(() => { perms.current = [] })

const wrap = (node: React.ReactNode, qc = new QueryClient()) =>
  renderToStaticMarkup(
    <QueryClientProvider client={qc}><MemoryRouter>{node}</MemoryRouter></QueryClientProvider>,
  )

describe("AddOrganizationFlow", () => {
  it("renders step 1: a domain input and a disabled Continue", () => {
    const html = wrap(<AddOrganizationFlow onCreated={() => {}} />)
    expect(html).toContain("Primary domain")
    expect(html).toContain("Step 1 of 3")
    expect(html).toMatch(/<button[^>]*disabled[^>]*>Continue<\/button>/)
  })
})

describe("Organizations empty state", () => {
  const emptyList = () => {
    const qc = new QueryClient()
    qc.setQueryData(["organizations"], [])
    return qc
  }
  it("offers Add organization to a user holding organizations.create", () => {
    asUser(["organizations.create"])
    const html = wrap(<Organizations />, emptyList())
    expect(html).toContain("No organizations yet")
    expect(html).toContain("Add organization")
  })
  it("does not offer it without the permission", () => {
    asUser(["entities.read"])
    const html = wrap(<Organizations />, emptyList())
    expect(html).toContain("No organizations yet")
    expect(html).not.toContain("Add organization")
  })
})

describe("OrgDetailsStep (step 3) Ours gate", () => {
  const base = { orgName: "Example Holdings A", reference: "T-1", engagementName: "" }
  const noop = () => {}
  const create = { isPending: false, isError: false, error: null, reset: noop }
  const render = (relationship: "ours" | "ma_target" | null, preset?: "ours") =>
    wrap(<OrgDetailsStep s={{ domain: "", cik: null, ...base, relationship }} set={noop} presetRelationship={preset}
      create={create} onNameEdit={noop} onBack={noop} onFinish={noop} />)
  const oursDisabled = (html: string) => /<button[^>]*\sdisabled=""[^>]*>(?:(?!<\/button>).)*Ours/.test(html)
  const finishDisabled = (html: string) => /<button[^>]*\sdisabled=""[^>]*>Finish<\/button>/.test(html)

  it("enables Ours and Finish for Ours with entities.mark_ours", () => {
    asUser(["entities.mark_ours"])
    const html = render("ours")
    expect(oursDisabled(html)).toBe(false)
    expect(html).not.toContain("Needs permission to mark organizations as ours")
    expect(finishDisabled(html)).toBe(false)
  })
  it("disables Ours with a hint, and Finish when Ours is selected, without it", () => {
    asUser(["organizations.create"])
    const html = render("ours")
    expect(oursDisabled(html)).toBe(true)
    expect(html).toContain("Needs permission to mark organizations as ours")
    expect(finishDisabled(html)).toBe(true)
  })
})
