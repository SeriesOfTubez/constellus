import { describe, expect, it } from "vitest"
import { useAuthStore } from "@/lib/auth"
import { holdsPermission, shouldRefreshPermissions } from "@/lib/permissions"

describe("auth store", () => {
  it("setUser keeps tokens and replaces the user (permissions refresh)", () => {
    useAuthStore.setState({ user: null, tokens: { access_token: "a", refresh_token: "r", token_type: "bearer" } })
    useAuthStore.getState().setUser({
      id: "u", email: "e", full_name: "n", role: "r", is_active: true, created_at: "", last_login_at: null,
      permissions: ["entities.read"],
    })
    expect(useAuthStore.getState().user?.permissions).toEqual(["entities.read"])
    expect(useAuthStore.getState().tokens?.access_token).toBe("a")
  })
})

describe("shouldRefreshPermissions", () => {
  it("refreshes once per load for a signed-in user, even with permissions present", () => {
    expect(shouldRefreshPermissions(true, false)).toBe(true)
  })
  it("does not refresh when signed out or already refreshed this load", () => {
    expect(shouldRefreshPermissions(false, false)).toBe(false)
    expect(shouldRefreshPermissions(true, true)).toBe(false)
  })
})

describe("holdsPermission (the core of useCan)", () => {
  it("is true only for a held permission; false for another and for unknown permissions", () => {
    expect(holdsPermission(["entities.read"], "entities.read")).toBe(true)
    expect(holdsPermission(["entities.read"], "entities.decide_candidate")).toBe(false)
    expect(holdsPermission([], "entities.read")).toBe(false)
    expect(holdsPermission(undefined, "entities.read")).toBe(false)
  })
})
