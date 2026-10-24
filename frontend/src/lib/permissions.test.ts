import { describe, expect, it } from "vitest"
import { useAuthStore } from "@/lib/auth"

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
