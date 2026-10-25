import { useEffect } from "react"
import { api, type User } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"

/** `useCan()("entities.decide_candidate")` — does the signed-in user hold this
 *  permission? False while unknown (no user, or a session persisted before
 *  `/auth/me` carried `permissions`). UI gating is cosmetic: the server enforces
 *  every permission independently, so never treat this as security. */
export function useCan(): (perm: string) => boolean {
  const permissions = useAuthStore(s => s.user?.permissions)
  return (perm: string) => holdsPermission(permissions, perm)
}

/** Pure core of `useCan`: unknown (undefined) permissions hold nothing. */
export function holdsPermission(permissions: string[] | undefined, perm: string): boolean {
  return permissions?.includes(perm) ?? false
}

/** Refresh once per app load whenever a user is signed in, so a role change
 *  shows without re-login (the persisted user's permissions may be stale). */
export function shouldRefreshPermissions(hasUser: boolean, alreadyRefreshedThisLoad: boolean): boolean {
  return hasUser && !alreadyRefreshedThisLoad
}

let refreshedThisLoad = false
/** Test-only: forget that this load already refreshed. */
export function resetPermissionsRefreshForTests(): void {
  refreshedThisLoad = false
}

/** Refreshes the stored user from `/auth/me` once per app load (module-level
 *  guard, so remounts don't refetch). Failure is silent: gates keep the
 *  persisted permissions, or stay hidden if there were none. */
export function usePermissionsSync(): void {
  const hasUser = useAuthStore(s => s.user !== null)
  const setUser = useAuthStore(s => s.setUser)
  useEffect(() => {
    if (!shouldRefreshPermissions(hasUser, refreshedThisLoad)) return
    refreshedThisLoad = true
    api.get<User>("/auth/me").then(setUser).catch(() => undefined)
  }, [hasUser, setUser])
}
