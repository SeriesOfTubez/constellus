import { useEffect } from "react"
import { api, type User } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"

/** `useCan()("entities.decide_candidate")` — does the signed-in user hold this
 *  permission? False while unknown (no user, or a session persisted before
 *  `/auth/me` carried `permissions`). UI gating is cosmetic: the server enforces
 *  every permission independently, so never treat this as security. */
export function useCan(): (perm: string) => boolean {
  const permissions = useAuthStore(s => s.user?.permissions)
  return (perm: string) => permissions?.includes(perm) ?? false
}

/** Refreshes the stored user once when its permissions are unknown (a session
 *  that predates the `permissions` field), so gated controls appear without a
 *  re-login. Failure is silent: the controls simply stay hidden. */
export function usePermissionsSync(): void {
  const hasUser = useAuthStore(s => s.user !== null)
  const known = useAuthStore(s => s.user?.permissions !== undefined)
  const setUser = useAuthStore(s => s.setUser)
  useEffect(() => {
    if (!hasUser || known) return
    api.get<User>("/auth/me").then(setUser).catch(() => undefined)
  }, [hasUser, known, setUser])
}
