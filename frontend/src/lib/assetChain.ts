import type { Asset } from "@/lib/api"

// NOTE: keep in sync with its backend twin, backend/app/services/asset_chain.py
// (`chain_target_ids`). Both walk the same CNAME chain and must agree on which
// host a record resolves to. The backend variant returns every asset id along
// the chain (for findings/risk rollup); this one returns just the terminal IP
// (for borrowing the IP's network enrichment). Same traversal, different payload.

const norm = (s: string) => s.toLowerCase().replace(/\.$/, "")

/**
 * Resolve the terminal IP a DNS record ultimately points at, following CNAME
 * chains through the in-scope asset list.
 *
 *   host1 → CNAME → host2 → A → 10.0.0.1   ⇒  resolveTerminalIp(host1) = "10.0.0.1"
 *
 * Ports, TLS, and WHOIS enrichment are stored on the `ip_address` asset; DNS
 * records borrow that data by resolving to the IP. The detail/flyout views
 * already did this for A/AAAA records (one hop); this walks multi-hop CNAME
 * chains so an intermediate hostname surfaces the same network data as the
 * host it resolves to — they're effectively the same host.
 *
 * Returns null when the chain dead-ends (e.g. a CDN CNAME whose terminal A
 * records are suppressed — those carry their own synthetic open_ports instead)
 * or loops back on itself.
 */
export function resolveTerminalIp(asset: Asset, allAssets: Asset[]): string | null {
  if (asset.asset_type === "ip_address") return asset.value
  if (asset.asset_type !== "dns_record") return null

  const md = asset.asset_metadata
  const rt = String(md.record_type ?? "")
  const content = typeof md.content === "string" ? md.content : null

  if ((rt === "A" || rt === "AAAA") && content) return content
  if (rt !== "CNAME" || !content) return null

  const visited = new Set<string>([norm(asset.value)])
  let name = norm(content)

  while (name && !visited.has(name)) {
    visited.add(name)
    const recs = allAssets.filter(
      a => a.asset_type === "dns_record" && norm(a.value) === name,
    )
    const addr = recs.find(a => {
      const r = String(a.asset_metadata.record_type ?? "")
      return r === "A" || r === "AAAA"
    })
    if (addr && typeof addr.asset_metadata.content === "string") {
      return addr.asset_metadata.content as string
    }
    const cname = recs.find(a => String(a.asset_metadata.record_type ?? "") === "CNAME")
    const next =
      cname && typeof cname.asset_metadata.content === "string"
        ? norm(cname.asset_metadata.content as string)
        : null
    if (!next) break
    name = next
  }
  return null
}
