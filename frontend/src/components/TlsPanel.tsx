import { useMemo } from "react"
import { ShieldAlert, Fingerprint, Network } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { OverflowCell } from "@/components/ui/overflow-cell"
import { displayName } from "@/lib/apex"
import { type Asset } from "@/lib/api"
import {
  type OpenPortEntry, type CertSummary,
  SOURCE_LABELS, certExpiryState,
} from "@/components/OpenPortsPanel"

/**
 * Unified TLS panel (#56). Reads the per-port `cert_summary` that tlsx and
 * Shodan write into `open_ports[]` and renders one card per distinct
 * certificate (deduped by fingerprint within the asset). Surfaces SAN list,
 * issuer, validity with expiry warnings, negotiated crypto with a weak-crypto
 * flag, the sha256 fingerprint, JA3/JARM, and source attribution. When the
 * full asset list is available it adds a read-time "also on N other assets"
 * cert-reuse hint — a lightweight shared-infra signal.
 */

type CertCard = {
  key: string
  cert: CertSummary
  ports: number[]
  sources: string[]
  jarm?: string
}

// A cert is identified by fingerprint when we have one; otherwise fall back to
// subject+issuer+expiry so older (pre-fingerprint) data still dedups sensibly.
function certKey(cert: CertSummary): string {
  return cert.fingerprint
    ?? `${cert.subject_cn ?? ""}|${cert.issuer_cn ?? ""}|${cert.not_after ?? ""}`
}

function collectCerts(entries: OpenPortEntry[]): CertCard[] {
  const byKey = new Map<string, CertCard>()
  for (const e of entries) {
    if (!e.cert_summary) continue
    const key = certKey(e.cert_summary)
    const existing = byKey.get(key)
    if (existing) {
      if (!existing.ports.includes(e.port)) existing.ports.push(e.port)
      for (const s of e.sources ?? []) if (!existing.sources.includes(s)) existing.sources.push(s)
      if (!existing.jarm && e.jarm) existing.jarm = e.jarm
    } else {
      byKey.set(key, {
        key,
        cert: e.cert_summary,
        ports: [e.port],
        sources: [...(e.sources ?? [])],
        jarm: e.jarm,
      })
    }
  }
  return [...byKey.values()].sort((a, b) => a.ports[0] - b.ports[0])
}

// Outdated protocol versions / weak ciphers worth flagging. Normalised so both
// tlsx ("tls10") and Shodan ("TLSv1.0") forms match.
function weakTls(tlsVersion?: string): boolean {
  if (!tlsVersion) return false
  const v = tlsVersion.toLowerCase().replace(/[^a-z0-9]/g, "")
  return v.startsWith("ssl") || v.endsWith("10") || v.endsWith("11")
}
const WEAK_CIPHER_RE = /rc4|3des|[^a-z]des|null|export|md5|anon/i
function weakCipher(cipher?: string): boolean {
  return !!cipher && WEAK_CIPHER_RE.test(cipher)
}

// fingerprint → set of asset ids carrying it, built once from the full asset
// list. Drives the cross-asset reuse hint.
function buildReuseIndex(allAssets: Asset[] | undefined): Map<string, Map<string, string>> {
  const index = new Map<string, Map<string, string>>()
  for (const a of allAssets ?? []) {
    const ports = (a.asset_metadata as Record<string, unknown>)?.open_ports
    if (!Array.isArray(ports)) continue
    for (const p of ports as OpenPortEntry[]) {
      const fp = p?.cert_summary?.fingerprint
      if (!fp) continue
      let assets = index.get(fp)
      if (!assets) { assets = new Map(); index.set(fp, assets) }
      assets.set(a.id, a.value)
    }
  }
  return index
}

export function TlsPanel({
  entries,
  allAssets,
  selfId,
}: {
  entries: OpenPortEntry[]
  allAssets?: Asset[]
  selfId?: string
}) {
  const certs = useMemo(() => collectCerts(entries), [entries])
  const reuseIndex = useMemo(() => buildReuseIndex(allAssets), [allAssets])

  if (certs.length === 0) {
    return <p className="text-sm text-muted-foreground">No TLS certificates observed on this asset.</p>
  }

  return (
    <div className="space-y-3">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        TLS certificates ({certs.length})
      </p>
      {certs.map(card => (
        <CertCardView key={card.key} card={card} reuseIndex={reuseIndex} selfId={selfId} />
      ))}
    </div>
  )
}

function CertCardView({
  card, reuseIndex, selfId,
}: {
  card: CertCard
  reuseIndex: Map<string, Map<string, string>>
  selfId?: string
}) {
  const { cert, ports, sources } = card
  const { date: expiry, daysToExpiry, expired, expiringSoon } = certExpiryState(cert.not_after)
  const isWeakTls = weakTls(cert.tls_version)
  const isWeakCipher = weakCipher(cert.cipher)

  // Cross-asset reuse: other assets sharing this fingerprint.
  const others = cert.fingerprint
    ? [...(reuseIndex.get(cert.fingerprint)?.entries() ?? [])].filter(([id]) => id !== selfId)
    : []

  const expiryCls = expired ? "text-destructive font-medium" : expiringSoon ? "text-orange-500 font-medium" : "text-muted-foreground"

  return (
    <div className="rounded-md border p-3 space-y-2 text-sm">
      {/* Subject + the ports this cert is served on */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-mono font-medium break-all">{cert.subject_cn ?? "(no subject CN)"}</span>
        <div className="flex items-center gap-1">
          {ports.sort((a, b) => a - b).map(p => (
            <Badge key={p} variant="outline" className="h-4 px-1.5 py-0 text-[9px] font-normal font-mono">:{p}</Badge>
          ))}
        </div>
      </div>

      {/* SANs */}
      {cert.sans && cert.sans.length > 0 && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground w-20 shrink-0">SANs</span>
          <OverflowCell
            items={cert.sans}
            limit={3}
            getLabel={(s) => s}
            renderItem={(s) => <span key={s} className="font-mono text-xs break-all">{s}</span>}
            renderOverflowItem={(s) => <span key={s} className="font-mono">{s}</span>}
          />
        </div>
      )}

      {/* Issuer */}
      {(cert.issuer_cn || cert.issuer_org) && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground w-20 shrink-0">Issuer</span>
          <span className="text-xs break-all">{cert.issuer_cn || cert.issuer_org}{cert.issuer_cn && cert.issuer_org ? ` · ${cert.issuer_org}` : ""}</span>
        </div>
      )}

      {/* Validity */}
      {(cert.not_before || cert.not_after) && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground w-20 shrink-0">Valid</span>
          <span className="text-xs">
            {cert.not_before ? new Date(cert.not_before).toLocaleDateString() : "?"}
            {" – "}
            <span className={expiryCls}>
              {expiry ? expiry.toLocaleDateString() : "?"}
              {expired ? " (expired)" : expiringSoon ? ` (${daysToExpiry}d)` : ""}
            </span>
          </span>
        </div>
      )}

      {/* Negotiated crypto + weak flags */}
      {(cert.tls_version || cert.cipher) && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-muted-foreground w-20 shrink-0">Crypto</span>
          <div className="flex items-center gap-1.5 flex-wrap">
            {cert.tls_version && (
              <Badge variant="outline" className={`h-4 px-1.5 py-0 text-[9px] font-normal ${isWeakTls ? "border-destructive/50 text-destructive" : ""}`}>
                {cert.tls_version}
              </Badge>
            )}
            {cert.cipher && (
              <span className={`font-mono text-[10px] ${isWeakCipher ? "text-destructive" : "text-muted-foreground"}`}>{cert.cipher}</span>
            )}
            {(isWeakTls || isWeakCipher) && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="inline-flex items-center gap-1 rounded border border-destructive/50 bg-destructive/10 px-1.5 py-0.5 text-[10px] font-medium text-destructive cursor-help">
                    <ShieldAlert className="h-2.5 w-2.5" />weak
                  </span>
                </TooltipTrigger>
                <TooltipContent side="top" className="max-w-xs">
                  {isWeakTls && "Outdated TLS/SSL protocol version. "}
                  {isWeakCipher && "Weak or deprecated cipher suite. "}
                  Consider disabling.
                </TooltipContent>
              </Tooltip>
            )}
          </div>
        </div>
      )}

      {/* Fingerprint + JA3/JARM */}
      {(cert.fingerprint || cert.ja3 || cert.ja3s || card.jarm) && (
        <div className="flex items-start gap-2">
          <span className="text-xs text-muted-foreground w-20 shrink-0">Fingerprint</span>
          <div className="space-y-0.5 min-w-0">
            {cert.fingerprint && (
              <p className="font-mono text-[10px] text-muted-foreground break-all" title={cert.fingerprint}>
                <Fingerprint className="inline h-2.5 w-2.5 mr-1" />{cert.fingerprint.slice(0, 32)}…
              </p>
            )}
            <div className="flex items-center gap-2 flex-wrap text-[10px] text-muted-foreground/80 font-mono">
              {cert.ja3 && <span title="JA3 client hash">ja3:{cert.ja3.slice(0, 12)}</span>}
              {cert.ja3s && <span title="JA3S server hash">ja3s:{cert.ja3s.slice(0, 12)}</span>}
              {card.jarm && <span title="JARM fingerprint">jarm:{card.jarm.slice(0, 12)}</span>}
            </div>
          </div>
        </div>
      )}

      {/* Source attribution + cross-asset reuse */}
      <div className="flex items-center gap-2 flex-wrap pt-1 border-t">
        <span className="text-xs text-muted-foreground w-20 shrink-0">Source</span>
        <div className="flex items-center gap-1 flex-wrap">
          {sources.map(s => (
            <Tooltip key={s}>
              <TooltipTrigger asChild>
                <Badge variant="outline" className="h-4 px-1.5 py-0 text-[9px] font-normal capitalize cursor-help">{s}</Badge>
              </TooltipTrigger>
              <TooltipContent side="top">{SOURCE_LABELS[s] ?? s}</TooltipContent>
            </Tooltip>
          ))}
          {others.length > 0 && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="inline-flex items-center gap-1 rounded border border-violet-500/40 bg-violet-500/10 px-1.5 py-0.5 text-[10px] font-medium text-violet-600 dark:text-violet-400 cursor-help">
                  <Network className="h-2.5 w-2.5" />also on {others.length} other asset{others.length === 1 ? "" : "s"}
                </span>
              </TooltipTrigger>
              <TooltipContent side="top" className="max-w-xs">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground mb-1">Same certificate</p>
                <div className="space-y-0.5">
                  {others.slice(0, 12).map(([id, value]) => <div key={id} className="font-mono text-xs break-all">{displayName(value)}</div>)}
                  {others.length > 12 && <div className="text-xs text-muted-foreground">+{others.length - 12} more</div>}
                </div>
              </TooltipContent>
            </Tooltip>
          )}
        </div>
      </div>
    </div>
  )
}
