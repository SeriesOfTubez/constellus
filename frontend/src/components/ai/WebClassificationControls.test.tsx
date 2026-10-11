import { beforeEach, describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { WebClassificationControls } from "@/components/ai/WebClassificationControls"
import type { WebEndpointState } from "@/lib/webClassification"

function state(over: Partial<WebEndpointState> = {}): WebEndpointState {
  return {
    port: 443, kind: "login_portal", environment: "production", product: null, source: "ai",
    http_title: null, http_status: null, service: null, ai: null, override: null, active: null,
    last_failure: null, ai_inputs_changed: null, override_stale: null, ai_suggests: null,
    ...over,
  }
}

// zustand v5 serves the INITIAL state to server renders (useSyncExternalStore's
// getServerSnapshot), so useAuthStore.setState() is invisible to
// renderToStaticMarkup. Stub the hook with a selector over a controllable user.
const auth = vi.hoisted(() => ({ role: null as string | null }))
vi.mock("@/lib/auth", () => ({
  useAuthStore: (sel: (s: { user: { role: string } | null }) => unknown) =>
    sel({ user: auth.role === null ? null : { role: auth.role } }),
}))

function setRole(role: string | null) {
  auth.role = role
}

const render = (s: WebEndpointState) =>
  renderToStaticMarkup(
    <QueryClientProvider client={new QueryClient()}>
      <WebClassificationControls assetId="asset-1" state={s} />
    </QueryClientProvider>,
  )

describe("WebClassificationControls", () => {
  beforeEach(() => setRole(null))

  it("renders the correct control for an admin (path reached)", () => {
    setRole("admin")
    expect(render(state())).toContain("Wrong? Correct it")
  })

  it.each(["integration_admin", "viewer", "analyst"])("renders nothing for %s", (role) => {
    // Guard against a vacuous pass: the same state renders for an admin.
    setRole("admin")
    expect(render(state())).not.toBe("")
    setRole(role)
    expect(render(state())).toBe("")
  })

  it("renders nothing when signed out", () => {
    setRole("admin")
    expect(render(state())).not.toBe("")
    setRole(null)
    expect(render(state())).toBe("")
  })

  it("offers Revert to AI only when the source is user", () => {
    setRole("admin")
    expect(render(state({ source: "ai" }))).not.toContain("Revert to AI")
    expect(render(state({ source: "none", kind: null, environment: null }))).not.toContain("Revert to AI")
    expect(render(state({ source: "user" }))).toContain("Revert to AI")
  })
})
