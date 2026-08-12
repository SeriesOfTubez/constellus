/** Roles allowed to perform mutating actions (suppress/resolve findings,
 * delete/recheck assets, etc.). Mirrors the backend's require_role(ADMIN,
 * INTEGRATION_ADMIN) gate on the equivalent endpoints (planning#87) — this
 * is a UX mirror of that real control, not a security boundary itself. */
export function canMutate(role: string | undefined): boolean {
  return role === "admin" || role === "integration_admin"
}
