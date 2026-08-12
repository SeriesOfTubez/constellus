// Stale threshold for assets and findings. If an item's last_seen_at is
// older than this, it hasn't been observed in recent monitoring runs and
// is flagged in the UI. Hardcoded for now — moving to app_settings is a
// backlog item.
export const STALE_AFTER_DAYS = 14

export function daysSince(iso: string | null | undefined): number | null {
  if (!iso) return null
  const ms = Date.now() - new Date(iso).getTime()
  if (Number.isNaN(ms)) return null
  return Math.floor(ms / (24 * 3600 * 1000))
}

export function isStale(iso: string | null | undefined): boolean {
  const d = daysSince(iso)
  return d !== null && d >= STALE_AFTER_DAYS
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—"
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return "—"
  const diffSec = Math.floor((Date.now() - then) / 1000)

  if (diffSec < 60) return "just now"
  if (diffSec < 3600) {
    const m = Math.floor(diffSec / 60)
    return `${m} min${m !== 1 ? "s" : ""} ago`
  }
  if (diffSec < 86_400) {
    const h = Math.floor(diffSec / 3600)
    return `${h} hour${h !== 1 ? "s" : ""} ago`
  }
  const d = Math.floor(diffSec / 86_400)
  if (d < 30) return `${d} day${d !== 1 ? "s" : ""} ago`
  if (d < 365) {
    const months = Math.floor(d / 30)
    return `${months} month${months !== 1 ? "s" : ""} ago`
  }
  const years = Math.floor(d / 365)
  return `${years} year${years !== 1 ? "s" : ""} ago`
}

export function relativeFuture(iso: string | null | undefined): string {
  if (!iso) return "—"
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return "—"
  const diffSec = Math.floor((then - Date.now()) / 1000)

  if (diffSec <= 0) return "now"
  if (diffSec < 60) return `in ${diffSec}s`
  if (diffSec < 3600) {
    const m = Math.floor(diffSec / 60)
    return `in ${m} min${m !== 1 ? "s" : ""}`
  }
  if (diffSec < 86_400) {
    const h = Math.floor(diffSec / 3600)
    return `in ${h} hour${h !== 1 ? "s" : ""}`
  }
  const d = Math.floor(diffSec / 86_400)
  return `in ${d} day${d !== 1 ? "s" : ""}`
}
