import { describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { TooltipProvider } from "@/components/ui/tooltip"
import { AddInstanceButton, ConnectorTypeCard, InstanceBindingControl } from "@/pages/admin/Connectors"
import { inst, typ } from "@/lib/connectors.fixtures"

// zustand's server snapshot is the store's INITIAL state, so setState is invisible to
// renderToStaticMarkup; stub the permission lookup instead (useCan's own logic is trivial).
const perms = vi.hoisted(() => ({ current: [] as string[] }))
vi.mock("@/lib/permissions", () => ({
  useCan: () => (p: string) => perms.current.includes(p),
}))

const noop = () => {}
const render = (t: ReturnType<typeof typ>) =>
  renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <TooltipProvider>
        <MemoryRouter>
          <ConnectorTypeCard type={t} onConfigure={noop} onAdd={noop} onDelete={noop} />
        </MemoryRouter>
      </TooltipProvider>
    </QueryClientProvider>,
  )

describe("ConnectorTypeCard", () => {
  it("lists two account instances, warns on the regressed one and offers Add another", () => {
    const html = render(typ({
      instances: [
        inst({ id: "i1", name: "Example Holdings A" }),
        inst({ id: "i2", name: "Example Holdings B", bound_entity_name: "Example Holdings B", binding_ok: false }),
      ],
    }))
    expect(html).toContain("Example Holdings A")
    expect(html).toContain("Example Holdings B")
    expect(html).toContain("Syncing is paused")
    expect(html.match(/Syncing is paused/g)).toHaveLength(1)
    expect(html).toContain("Add another")
  })

  it("offers plain Add for an account type with no instances, and Set up for a global one", () => {
    const empty = render(typ())
    expect(empty).toContain(">Add<")
    expect(empty).not.toContain("Add another")
    const global = render(typ({ id: "naabu", name: "Naabu", phase: "scanning", account_scoped: false, multi_instance: false }))
    expect(global).toContain("Set up")
    expect(global).not.toContain("Add another")
  })
})

describe("Clashes section", () => {
  it("shows Clashes (2) when the instance has open clashes, nothing when it has none", () => {
    const withClashes = render(typ({ instances: [inst({ open_zone_clashes: 2 })] }))
    expect(withClashes).toContain("Clashes (2)")
    const none = render(typ({ instances: [inst({ open_zone_clashes: 0 })] }))
    expect(none).not.toContain("Clashes")
  })
})

describe("InstanceBindingControl permission gating", () => {
  const setPerms = (permissions: string[]) => { perms.current = permissions }
  const renderControl = () =>
    renderToStaticMarkup(
      <QueryClientProvider client={new QueryClient()}>
        <InstanceBindingControl type={typ()} instance={inst()} org="o1" onChange={noop} getConfig={() => ({})} />
      </QueryClientProvider>,
    )

  it("renders the picker with entities.decide_candidate and the read-only binding without it", () => {
    setPerms(["entities.decide_candidate"])
    const can = renderControl()
    expect(can).toContain("Find matching organization")
    expect(can).not.toContain("Bound to Example Holdings A")

    setPerms(["entities.read"])
    const cannot = renderControl()
    expect(cannot).toContain("Bound to Example Holdings A")
    expect(cannot).toContain("Changing the binding needs permission to decide candidates.")
    expect(cannot).not.toContain("Find matching organization")
  })
})

describe("AddInstanceButton permission gating", () => {
  const render = (accountScoped: boolean, disabled = false) =>
    renderToStaticMarkup(<AddInstanceButton accountScoped={accountScoped} disabled={disabled} pending={false} onClick={noop} />)
  const isDisabled = (html: string) => /<button[^>]*\sdisabled=""/.test(html)

  it("is enabled for an account-scoped type with entities.decide_candidate", () => {
    perms.current = ["entities.decide_candidate"]
    expect(isDisabled(render(true))).toBe(false)
  })
  it("is disabled for an account-scoped type without it, but not for a global type", () => {
    perms.current = ["entities.read"]
    expect(isDisabled(render(true))).toBe(true)
    expect(isDisabled(render(false))).toBe(false)
  })
  it("stays disabled when the caller says so, even with the permission", () => {
    perms.current = ["entities.decide_candidate"]
    expect(isDisabled(render(true, true))).toBe(true)
  })
})
