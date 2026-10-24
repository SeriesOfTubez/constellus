import { describe, expect, it } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { TooltipProvider } from "@/components/ui/tooltip"
import { ConnectorTypeCard } from "@/pages/admin/Connectors"
import { inst, typ } from "@/lib/connectors.fixtures"

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
