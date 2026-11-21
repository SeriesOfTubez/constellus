/**
 * Whether a finding's fix window passes the list's `?bod=` filter (planning#382).
 * `3d` also takes `3d+triage` (both are a three-day fix); every other value is
 * an exact match. A hand-typed `?bod=3d+triage` decodes its `+` to a space, so
 * a space is read as `+`. A finding with no window passes only `all`.
 */
export function matchesFixWindow(window: string | null | undefined, filter: string): boolean {
  if (filter === "all") return true
  if (!window) return false
  const wanted = filter.replace(/ /g, "+")
  if (wanted === "3d") return window === "3d" || window === "3d+triage"
  return window === wanted
}
