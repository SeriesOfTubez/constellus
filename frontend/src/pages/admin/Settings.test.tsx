import { describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { TooltipProvider } from "@/components/ui/tooltip"
import Settings from "@/pages/admin/Settings"

// zustand's server snapshot is the store's INITIAL state, so setState is invisible to
// renderToStaticMarkup; stub the permission lookup instead (useCan's own logic is trivial).
const perms = vi.hoisted(() => ({ current: [] as string[] }))
vi.mock("@/lib/permissions", () => ({
  useCan: () => (p: string) => perms.current.includes(p),
}))

const render = (held: string[]) => {
  perms.current = held
  return renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <TooltipProvider>
        <MemoryRouter>
          <Settings />
        </MemoryRouter>
      </TooltipProvider>
    </QueryClientProvider>,
  )
}

// Card title -> the permissions its GET requests need (backend/app/api/settings.py,
// jobs.py, monitoring.py, notifications.py).
const CARDS: Record<string, string[]> = {
  "Organization branding": ["settings.read"],
  "Scan aggressiveness": ["settings.read"],
  "Monitoring policies": ["monitoring.read"],
  "Page capture": ["settings.read"],
  "Discovery": ["settings.read"],
  "Scheduled jobs": ["settings.read", "jobs.read"],
  "Logging": ["settings.read"],
  "Notification rules": ["notifications.read"],
}
const ALL = [...new Set(Object.values(CARDS).flat())]
// A card's title as the page renders it: bare in its CardTitle, or after an icon.
const shows = (html: string, title: string) => html.includes(`${title}</h3>`)

describe("Settings page cards by permission (planning#339)", () => {
  it("shows every card to a user holding every permission", () => {
    const html = render(ALL)
    for (const title of Object.keys(CARDS)) expect(shows(html, title), title).toBe(true)
  })

  it("shows an integration admin only the cards it can read", () => {
    // What that role holds of the permissions above (core/permissions.py).
    const html = render(["monitoring.read", "notifications.read"])
    expect(shows(html, "Monitoring policies")).toBe(true)
    expect(shows(html, "Notification rules")).toBe(true)
    for (const title of ["Organization branding", "Scan aggressiveness", "Page capture",
      "Discovery", "Scheduled jobs", "Logging"]) {
      expect(shows(html, title), title).toBe(false)
    }
    // The page itself still renders.
    expect(shows(html, "System")).toBe(true)
  })

  it.each(Object.entries(CARDS))("hides %s when one of its permissions is missing", (title, needs) => {
    for (const missing of needs) {
      const html = render(ALL.filter(p => p !== missing))
      expect(shows(html, title), `${title} without ${missing}`).toBe(false)
    }
  })
})
