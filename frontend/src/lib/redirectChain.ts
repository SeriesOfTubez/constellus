// planning#271 — redirect chain display helpers. A hop's title/status belong to
// the redirect DESTINATION, never to the endpoint the chain hangs off.
export interface RedirectHop {
  hop_index: number
  url: string
  followed: boolean
  reason: string | null
  http_status: number | null
  http_title: string | null
  hop_asset_id: string | null
}

const REASON_TEXT: Record<string, string> = {
  "posture:passive_only": "the target is limited to passive observation",
  "probe_class:no_probe": "the destination is not authorised for probing",
  "probe_class:unprojected": "the destination has not been classified yet",
  "scope:unresolved_asset": "the destination is not a known asset",
  unresolved_asset: "the destination is not a known asset",
  addressing_not_permitted: "the destination cannot be probed this way",
  no_authorised_names: "the destination has no authorised hostname",
  denied: "the probe gate refused it",
  loop: "the redirect loops back on itself",
  hop_cap: "too many redirects (limit reached)",
  unsupported_url: "the redirect URL is not supported",
  ssrf_blocked: "the destination resolves to a private or reserved address",
  dns_failed: "the destination hostname did not resolve",
  worker_unavailable: "the scanner was unavailable",
}

export function refusedReasonText(reason: string): string {
  if (Object.prototype.hasOwnProperty.call(REASON_TEXT, reason)) return REASON_TEXT[reason]
  if (reason.startsWith("scope:")) return "the destination is outside the scan scope"
  return reason
}

export function hopSummary(hop: RedirectHop): string {
  if (hop.followed) {
    const parts: string[] = []
    if (hop.http_status != null) parts.push(String(hop.http_status))
    if (hop.http_title) parts.push(hop.http_title)
    return parts.join(" · ")
  }
  return `Not followed: ${refusedReasonText(hop.reason ?? "")}`
}
