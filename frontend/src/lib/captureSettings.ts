import type { CaptureSettings } from "@/lib/api"

// Bounds mirror backend page_capture.py. The backend is authoritative (it
// returns 422); these only give early inline feedback.
export const REVISIT_DAYS_MIN = 1
export const REVISIT_DAYS_MAX = 365
export const MAX_IMAGE_BYTES_MIN = 65536
export const MAX_IMAGE_BYTES_MAX = 8388608
export const QUEUE_TIMEOUT_MIN = 60
export const QUEUE_TIMEOUT_MAX = 3600
export const IMAGE_KEEP_MIN = 1
export const IMAGE_KEEP_MAX = 50
export const PROXY_CONNECT_TIMEOUT_MIN = 1
export const PROXY_CONNECT_TIMEOUT_MAX = 60
export const PROXY_IDLE_TIMEOUT_MIN = 5
export const PROXY_IDLE_TIMEOUT_MAX = 600
export const PROXY_MAX_CONN_MIN = 1
export const PROXY_MAX_CONN_MAX = 1024
export const ARCHIVE_FRESHNESS_MIN = 1
export const ARCHIVE_FRESHNESS_MAX = 90
export const UA_MAX_LEN = 256
export const IMAGE_KIB_MIN = MAX_IMAGE_BYTES_MIN / 1024 // 64
export const IMAGE_KIB_MAX = MAX_IMAGE_BYTES_MAX / 1024 // 8192

export const bytesToKiB = (bytes: number): number => bytes / 1024
export const kibToBytes = (kib: number): number => kib * 1024

/** 1..256 chars, every char printable ASCII (0x20..0x7e). */
export function validUserAgent(s: string): boolean {
  if (s.length < 1 || s.length > UA_MAX_LEN) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x20 || c > 0x7e) return false
  }
  return true
}

const inRange = (n: number, lo: number, hi: number) => Number.isInteger(n) && n >= lo && n <= hi

/** First error message, or null when the draft is acceptable. */
export function validateCaptureSettings(d: CaptureSettings): string | null {
  if (!inRange(d.browse_revisit_days, REVISIT_DAYS_MIN, REVISIT_DAYS_MAX))
    return `Revisit budget must be a whole number from ${REVISIT_DAYS_MIN} to ${REVISIT_DAYS_MAX} days.`
  if (d.identifying_user_agent !== "" && !validUserAgent(d.identifying_user_agent))
    return `The identifying User-Agent must be printable ASCII, up to ${UA_MAX_LEN} characters.`
  if (d.user_agent_mode === "identifying" && d.identifying_user_agent === "")
    return "Enter an identifying User-Agent string, or choose Stock browser."
  if (!inRange(d.max_image_bytes, MAX_IMAGE_BYTES_MIN, MAX_IMAGE_BYTES_MAX))
    return `Max screenshot size must be a whole number of KiB from ${IMAGE_KIB_MIN} to ${IMAGE_KIB_MAX}.`
  if (!inRange(d.queue_timeout_seconds, QUEUE_TIMEOUT_MIN, QUEUE_TIMEOUT_MAX))
    return `Queue timeout must be a whole number from ${QUEUE_TIMEOUT_MIN} to ${QUEUE_TIMEOUT_MAX} seconds.`
  if (!inRange(d.image_keep_count, IMAGE_KEEP_MIN, IMAGE_KEEP_MAX))
    return `Screenshots kept per domain must be a whole number from ${IMAGE_KEEP_MIN} to ${IMAGE_KEEP_MAX}.`
  if (!inRange(d.proxy_connect_timeout_seconds, PROXY_CONNECT_TIMEOUT_MIN, PROXY_CONNECT_TIMEOUT_MAX))
    return `Proxy connect timeout must be a whole number from ${PROXY_CONNECT_TIMEOUT_MIN} to ${PROXY_CONNECT_TIMEOUT_MAX} seconds.`
  if (!inRange(d.proxy_idle_timeout_seconds, PROXY_IDLE_TIMEOUT_MIN, PROXY_IDLE_TIMEOUT_MAX))
    return `Proxy idle timeout must be a whole number from ${PROXY_IDLE_TIMEOUT_MIN} to ${PROXY_IDLE_TIMEOUT_MAX} seconds.`
  if (!inRange(d.proxy_max_connections, PROXY_MAX_CONN_MIN, PROXY_MAX_CONN_MAX))
    return `Proxy max connections must be a whole number from ${PROXY_MAX_CONN_MIN} to ${PROXY_MAX_CONN_MAX}.`
  if (!inRange(d.archive_freshness_days, ARCHIVE_FRESHNESS_MIN, ARCHIVE_FRESHNESS_MAX))
    return `Archive snapshot freshness must be a whole number from ${ARCHIVE_FRESHNESS_MIN} to ${ARCHIVE_FRESHNESS_MAX} days.`
  return null
}
