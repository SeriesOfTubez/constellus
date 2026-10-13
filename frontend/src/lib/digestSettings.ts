// Client-side mirrors of the server's digest-settings rules (planning#233).

/** Amber note for digest hours that collide with scheduled jobs; null otherwise. */
export function digestHourWarning(hour: number): string | null {
  if (hour === 2) {
    return "Monitoring scans run at 02:00 UTC. A digest at this hour may miss their results until the next day."
  }
  if (hour === 3) {
    return "The nightly re-score runs at 03:00 UTC. A digest at this hour may miss their results until the next day."
  }
  return null
}

const BASE_URL_RE = /^https?:\/\/[^\s/?#@]+(\/[^\s?#]*)?$/
export const BASE_URL_MAX = 200

/** Empty, or an http(s) URL of at most 200 chars (same rule as the server). */
export function validBaseUrl(v: string): boolean {
  if (v === "") return true
  return v.length <= BASE_URL_MAX && BASE_URL_RE.test(v)
}

/** Integer 0-23. */
export function validDigestHour(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= 23
}
