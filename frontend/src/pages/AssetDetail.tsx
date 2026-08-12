import { Link, useParams, useNavigate } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ChevronLeft, RefreshCw, Eye, EyeOff, Trash2 } from "lucide-react"

import { ConnectedEntities, type ObservedName } from "@/components/ConnectedEntities"
import { OpenPortsPanel, type OpenPortEntry } from "@/components/OpenPortsPanel"
import { TlsPanel } from "@/components/TlsPanel"
import { AssetRiskCard } from "@/components/AssetRiskCard"
import { SourceBadges, SOURCE_META, RecordTypeBadge, AssetTypeBadge } from "@/components/asset-badges"
import { CategoryBadge, StateBadge, FindingRiskBadge } from "@/components/finding-badges"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { TagEditor } from "@/components/ui/tag-editor"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table"
import { api, type Asset, type DomainWhoisInfo, type Finding, type WhoisInfo } from "@/lib/api"
import { apexFromFqdn, displayName } from "@/lib/apex"
import { resolveTerminalIp } from "@/lib/assetChain"
import { relativeTime } from "@/lib/time"

// Underline tab trigger — mirrors the flyout's tab styling for a consistent contract.
const TAB = "h-9 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-foreground text-muted-foreground text-sm font-medium px-3 transition-none"

/**
 * Full-detail page for an asset.
 *
 * Page shell with tabbed data that mirrors the Assets-page flyout (Overview /
 * Findings / Relationships / Timeline / Raw), the same way FindingDetail mirrors
 * the finding flyout. Reuses the shared leaf components (AssetRiskCard,
 * OpenPortsPanel, ConnectedEntities) so the two surfaces can't drift.
 * Permalinkable: any row in any list can deep-link here.
 */
export default function AssetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const { data: asset, isLoading, isError } = useQuery({
    queryKey: ["asset-detail", id],
    queryFn: () => api.get<Asset>(`/assets/${id}`),
    enabled: !!id,
  })

  // Pull the full asset list so we can find the related ip_address asset for
  // A/AAAA records (enrichment data lives on the IP, not the DNS record).
  // Cached by the Assets page already in most navigation flows.
  const { data: allAssets } = useQuery({
    queryKey: ["assets", true],
    queryFn: () => api.get<Asset[]>("/assets/?show_ignored=true"),
  })

  const scanMutation = useMutation({
    mutationFn: () => api.post(`/assets/${id}/scan`),
    onSuccess: () => { toast.success("Recheck queued"); qc.invalidateQueries({ queryKey: ["scans"] }) },
    onError: () => toast.error("Failed to start recheck"),
  })

  const ignoreMutation = useMutation({
    mutationFn: (ignored: boolean) => api.patch(`/assets/${id}/ignore`, { ignored }),
    onSuccess: (_, ignored) => {
      toast.success(ignored ? "Asset ignored" : "Asset restored")
      qc.invalidateQueries({ queryKey: ["asset-detail", id] })
      qc.invalidateQueries({ queryKey: ["assets"] })
    },
    onError: () => toast.error("Failed to update asset"),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/assets/${id}`),
    onSuccess: () => {
      toast.success("Asset deleted")
      qc.invalidateQueries({ queryKey: ["assets"] })
      navigate("/assets")
    },
    onError: () => toast.error("Failed to delete asset"),
  })

  const tagMutation = useMutation({
    mutationFn: (tags: string[]) => api.patch(`/tags/assets/${id}`, { tags }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["asset-detail", id] }),
    onError: () => toast.error("Failed to update asset"),
  })

  if (isLoading) return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-4">
      <Skeleton className="h-6 w-32" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-64 w-full" />
    </div>
  )

  if (isError || !asset) return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-4">
      <Link to="/assets" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="h-4 w-4" />Assets
      </Link>
      <div className="rounded-md border bg-card p-6 text-sm text-muted-foreground">
        Asset not found or no longer in scope.
      </div>
    </div>
  )

  return <AssetDetailBody
    asset={asset}
    allAssets={allAssets ?? []}
    onScan={() => scanMutation.mutate()}
    onIgnore={(ignored) => ignoreMutation.mutate(ignored)}
    onDelete={() => deleteMutation.mutate()}
    onTagChange={(tags) => tagMutation.mutate(tags)}
    isMutating={scanMutation.isPending || ignoreMutation.isPending || deleteMutation.isPending}
  />
}

type EolService = { port: number; service: string | null; product: string; version: string; eol_date: string | null; is_eol: boolean; days_past_eol: number | null; latest: string | null }

function AssetDetailBody({
  asset, allAssets, onScan, onIgnore, onDelete, onTagChange, isMutating,
}: {
  asset: Asset
  allAssets: Asset[]
  onScan: () => void
  onIgnore: (ignored: boolean) => void
  onDelete: () => void
  onTagChange: (tags: string[]) => void
  isMutating: boolean
}) {
  const m = asset.asset_metadata
  const sources: string[] = Array.isArray(m.sources)
    ? (m.sources as string[])
    : m.source ? [m.source as string] : []

  const content = typeof m.content === "string" ? m.content : null
  // Follows CNAME chains (host1 → host2 → IP) so an intermediate hostname
  // surfaces the same ports/TLS/WHOIS as the host it resolves to.
  const ipForWhois = resolveTerminalIp(asset, allAssets)

  const { data: whois } = useQuery<WhoisInfo>({
    queryKey: ["whois", ipForWhois],
    queryFn: () => api.get<WhoisInfo>(`/assets/whois?ip=${encodeURIComponent(ipForWhois!)}`),
    enabled: !!ipForWhois,
    staleTime: 60 * 60 * 1000,
  })

  const domainForWhois = asset.asset_type === "dns_record" ? apexFromFqdn(asset.value) : null
  const { data: domainWhois } = useQuery<DomainWhoisInfo>({
    queryKey: ["domain-whois", domainForWhois],
    queryFn: () => api.get<DomainWhoisInfo>(`/assets/whois-domain?domain=${encodeURIComponent(domainForWhois!)}`),
    enabled: !!domainForWhois,
    staleTime: 60 * 60 * 1000,
  })

  // include_children rolls up findings on the IP(s) this asset resolves to —
  // matching the Assets risk column — so a hostname surfaces its IP's exposures.
  const { data: findings } = useQuery({
    queryKey: ["asset-findings", asset.id],
    queryFn: () => api.get<Finding[]>(`/findings/?asset_canonical_id=${asset.id}&include_children=true`),
  })

  // Hide resolved findings by default — they're noise unless you're specifically
  // looking for them. The Findings page keeps its own state filter for that.
  const activeFindings = (findings ?? []).filter(f => f.state !== "resolved")

  const enrichmentIpAsset: Asset | null =
    asset.asset_type === "ip_address" ? asset
    : asset.asset_type === "dns_record" && ipForWhois
      ? allAssets.find(a => a.asset_type === "ip_address" && a.value === ipForWhois) ?? null
      : null

  const enrichMeta = enrichmentIpAsset?.asset_metadata ?? {}
  const enrichSources: string[] = Array.isArray(enrichMeta.sources) ? enrichMeta.sources as string[] : []
  const hasShodanEnrichment = enrichSources.includes("shodan")

  type NetworkRow = { label: string; value: string; source: string; mono?: boolean }
  const networkRows: NetworkRow[] = []
  if (ipForWhois) networkRows.push({ label: "IP", value: ipForWhois, source: "asset", mono: true })
  if (whois?.org) networkRows.push({ label: "Organization", value: whois.org, source: "RDAP" })
  else if (hasShodanEnrichment && typeof enrichMeta.shodan_org === "string") networkRows.push({ label: "Organization", value: enrichMeta.shodan_org, source: "shodan" })
  if (whois?.asn) networkRows.push({ label: "ASN", value: whois.asn, source: "RDAP", mono: true })
  else if (hasShodanEnrichment && enrichMeta.shodan_asn) networkRows.push({ label: "ASN", value: `AS${enrichMeta.shodan_asn}`, source: "shodan", mono: true })
  if (hasShodanEnrichment && typeof enrichMeta.shodan_isp === "string") networkRows.push({ label: "ISP", value: enrichMeta.shodan_isp, source: "shodan" })
  if (hasShodanEnrichment && typeof enrichMeta.shodan_country === "string") networkRows.push({ label: "Country", value: enrichMeta.shodan_country, source: "shodan" })
  if (hasShodanEnrichment && typeof enrichMeta.shodan_os === "string") networkRows.push({ label: "OS", value: enrichMeta.shodan_os, source: "shodan" })

  const portEntries: OpenPortEntry[] = Array.isArray(enrichMeta.open_ports)
    ? (enrichMeta.open_ports as OpenPortEntry[])
    : Array.isArray(m.open_ports)
      ? (m.open_ports as OpenPortEntry[])
      : []
  const legacyShodanPorts: number[] = hasShodanEnrichment && Array.isArray(enrichMeta.shodan_ports)
    ? (enrichMeta.shodan_ports as number[])
    : []
  const hasCerts = portEntries.some(e => e.cert_summary)
  const eolServices: EolService[] = Array.isArray(enrichMeta.eol_services)
    ? (enrichMeta.eol_services as EolService[])
    : []

  const trackedDnsNames = new Set<string>()
  for (const other of allAssets) {
    if (other.asset_type === "dns_record") {
      trackedDnsNames.add(other.value.toLowerCase().replace(/\.$/, ""))
    }
  }
  const observedNames: ObservedName[] = []
  if (hasShodanEnrichment && Array.isArray(enrichMeta.shodan_hostnames)) {
    for (const h of enrichMeta.shodan_hostnames as string[]) {
      const norm = String(h).toLowerCase().replace(/\.$/, "")
      if (trackedDnsNames.has(norm)) continue
      observedNames.push({ value: h, source: "shodan" })
    }
  }

  type Signal = { value: string; source: string; severity?: "critical" | "info" }
  const signals: Signal[] = []
  if (hasShodanEnrichment && Array.isArray(enrichMeta.shodan_tags)) {
    for (const t of enrichMeta.shodan_tags as string[]) {
      const sev = (t === "malware" || t === "compromised" || t === "honeypot") ? "critical" : "info"
      signals.push({ value: t, source: "shodan", severity: sev })
    }
  }

  const hasDomainData = domainWhois && (
    domainWhois.registrar || domainWhois.registrant_org || domainWhois.creation_date ||
    domainWhois.expiration_date || domainWhois.name_servers.length > 0
  )

  const timelineEvents = [
    { date: asset.first_seen_at, label: "First discovered" },
    asset.last_seen_at !== asset.first_seen_at ? { date: asset.last_seen_at, label: "Last seen" } : null,
  ].filter(Boolean) as { date: string; label: string }[]

  return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-6">
      <Link to="/assets" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="h-4 w-4" />Assets
      </Link>

      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 flex-wrap">
          {asset.asset_type === "dns_record" && m.record_type
            ? <RecordTypeBadge type={String(m.record_type)} />
            : <AssetTypeBadge type={asset.asset_type} />}
          {asset.ignored && <span className="text-xs text-muted-foreground italic">ignored</span>}
          {sources.map(src => {
            const meta = SOURCE_META[src] ?? { label: src.slice(0, 2).toUpperCase(), color: "bg-muted text-muted-foreground", description: src }
            return (
              <span key={src}
                className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold cursor-default ${meta.color}`}
                title={meta.description}
              >{meta.label}</span>
            )
          })}
        </div>
        <h1 className="font-mono text-xl break-all leading-tight" title={asset.value}>{displayName(asset.value)}</h1>
        {asset.asset_type === "dns_record" && content && (
          <p className="text-sm font-mono text-muted-foreground break-all">→ {content}</p>
        )}
        {asset.parent_value && (
          <p className="text-xs text-muted-foreground">
            parent: <span className="font-mono">{displayName(asset.parent_value)}</span>
          </p>
        )}

        {/* Action bar */}
        <div className="flex flex-wrap gap-2 pt-1">
          {!asset.ignored && (
            <Button size="sm" variant="outline" disabled={isMutating} onClick={onScan}>
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />Recheck
            </Button>
          )}
          <Button size="sm" variant="outline" disabled={isMutating} onClick={() => onIgnore(!asset.ignored)}>
            {asset.ignored ? <Eye className="h-3.5 w-3.5 mr-1.5" /> : <EyeOff className="h-3.5 w-3.5 mr-1.5" />}
            {asset.ignored ? "Restore" : "Ignore"}
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={isMutating}
            onClick={() => {
              if (confirm(`Delete asset ${displayName(asset.value)}? This cannot be undone.`)) onDelete()
            }}
            className="text-destructive hover:text-destructive hover:bg-destructive/10"
          >
            <Trash2 className="h-3.5 w-3.5 mr-1.5" />Delete
          </Button>
        </div>
      </div>

      {/* Tabbed detail — mirrors the Assets-page flyout contract */}
      <Tabs defaultValue="overview" className="w-full">
        <div className="border-b overflow-x-auto">
          <TabsList className="h-auto w-full justify-start gap-0 bg-transparent rounded-none p-0">
            <TabsTrigger value="overview" className={TAB}>Overview</TabsTrigger>
            <TabsTrigger value="findings" className={TAB}>
              Findings
              {activeFindings.length > 0 && (
                <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[9px] font-semibold">{activeFindings.length}</span>
              )}
            </TabsTrigger>
            {hasCerts && <TabsTrigger value="tls" className={TAB}>TLS</TabsTrigger>}
            <TabsTrigger value="relationships" className={TAB}>Relationships</TabsTrigger>
            <TabsTrigger value="timeline" className={TAB}>Timeline</TabsTrigger>
            <TabsTrigger value="raw" className={TAB}>Raw</TabsTrigger>
          </TabsList>
        </div>

        {/* ── Overview — verdict + network/registration surfaces ── */}
        <TabsContent value="overview" className="pt-5 space-y-6">
          <AssetRiskCard asset={asset} findings={findings ?? []} />

          {/* Network */}
          {networkRows.length > 0 && (
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Network</p>
              <div className="rounded-md border divide-y text-sm">
                {networkRows.map(row => (
                  <div key={row.label} className="flex items-start gap-3 px-3 py-2">
                    <span className="text-muted-foreground shrink-0 w-28">{row.label}</span>
                    <span className={`flex-1 break-all text-foreground ${row.mono ? "font-mono" : ""}`}>{row.value}</span>
                    {row.source !== "asset" && (
                      <span className="text-[10px] uppercase tracking-wider text-muted-foreground shrink-0">{row.source}</span>
                    )}
                  </div>
                ))}
                {whois?.looked_up_at && (
                  <div className="flex items-start gap-3 px-3 py-2">
                    <span className="text-muted-foreground shrink-0 w-28">Last lookup</span>
                    <span className="flex-1 text-muted-foreground">{new Date(whois.looked_up_at).toLocaleDateString()}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Open ports */}
          {(portEntries.length > 0 || legacyShodanPorts.length > 0) && (
            <OpenPortsPanel entries={portEntries} legacyShodanPorts={legacyShodanPorts} />
          )}

          {/* Software inventory (EOL) */}
          {eolServices.length > 0 && (
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Software inventory</p>
              <div className="rounded-md border divide-y text-xs">
                {eolServices.map((svc, i) => (
                  <div key={i} className="flex items-center gap-2 px-3 py-2">
                    <span className="font-mono text-muted-foreground shrink-0 w-12">:{svc.port}</span>
                    <span className="font-medium capitalize flex-1">{svc.product}</span>
                    <span className="text-muted-foreground font-mono">{svc.version}</span>
                    {svc.is_eol ? (
                      <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold bg-amber-500/10 text-amber-500 border-amber-500/30 shrink-0">
                        EOL{svc.days_past_eol !== null ? ` · ${svc.days_past_eol}d` : ""}
                      </span>
                    ) : (
                      <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold bg-emerald-500/10 text-emerald-600 border-emerald-500/30 shrink-0">
                        Supported
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Signals */}
          {signals.length > 0 && (
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Signals</p>
              <div className="rounded-md border px-3 py-2 flex flex-wrap gap-1">
                {signals.map(s => (
                  <span
                    key={`${s.value}-${s.source}`}
                    className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs ${s.severity === "critical" ? "bg-destructive/15 text-destructive" : "bg-muted text-foreground"}`}
                  >
                    {s.value}
                    <span className="text-[9px] uppercase tracking-wider opacity-60">{s.source}</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Domain registration */}
          {domainForWhois && hasDomainData && (
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Domain registration</p>
              <div className="rounded-md border divide-y text-sm">
                <div className="flex items-start gap-3 px-3 py-2">
                  <span className="text-muted-foreground shrink-0 w-32">Domain</span>
                  <span className="font-mono text-foreground break-all">{domainWhois!.domain}</span>
                </div>
                {domainWhois!.registrar && (
                  <div className="flex items-start gap-3 px-3 py-2">
                    <span className="text-muted-foreground shrink-0 w-32">Registrar</span>
                    <span className="text-foreground break-all">{domainWhois!.registrar}</span>
                  </div>
                )}
                {domainWhois!.registrant_org && (
                  <div className="flex items-start gap-3 px-3 py-2">
                    <span className="text-muted-foreground shrink-0 w-32">Registrant</span>
                    <span className="text-foreground break-all">{domainWhois!.registrant_org}</span>
                  </div>
                )}
                {domainWhois!.creation_date && (
                  <div className="flex items-start gap-3 px-3 py-2">
                    <span className="text-muted-foreground shrink-0 w-32">Created</span>
                    <span className="text-foreground">{new Date(domainWhois!.creation_date).toLocaleDateString()}</span>
                  </div>
                )}
                {domainWhois!.expiration_date && (
                  <div className="flex items-start gap-3 px-3 py-2">
                    <span className="text-muted-foreground shrink-0 w-32">Expires</span>
                    <span className="text-foreground">{new Date(domainWhois!.expiration_date).toLocaleDateString()}</span>
                  </div>
                )}
                {domainWhois!.name_servers.length > 0 && (
                  <div className="flex items-start gap-3 px-3 py-2">
                    <span className="text-muted-foreground shrink-0 w-32">Nameservers</span>
                    <div className="font-mono text-foreground space-y-0.5 break-all">
                      {domainWhois!.name_servers.map(ns => <div key={ns}>{ns}</div>)}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tags */}
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Tags</p>
            <TagEditor tags={asset.tags ?? []} entityType="asset" onChange={onTagChange} />
          </div>

          {/* Sources */}
          {sources.length > 0 && (
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Sources</p>
              <SourceBadges metadata={asset.asset_metadata} />
            </div>
          )}
        </TabsContent>

        {/* ── Findings ── */}
        <TabsContent value="findings" className="pt-5">
          {activeFindings.length === 0 ? (
            <p className="py-10 text-center text-sm text-muted-foreground">No findings on this asset.</p>
          ) : (
            <div className="rounded-md border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-24">Risk</TableHead>
                    <TableHead className="w-36 hidden sm:table-cell">Category</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead className="w-28">State</TableHead>
                    <TableHead className="w-32 hidden md:table-cell">Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {activeFindings.map(f => (
                    <TableRow
                      key={f.id}
                      className="cursor-pointer"
                      onClick={() => window.location.assign(`/findings?id=${f.id}`)}
                    >
                      <TableCell><FindingRiskBadge finding={f} /></TableCell>
                      <TableCell className="hidden sm:table-cell"><CategoryBadge category={f.category} /></TableCell>
                      <TableCell>
                        <p className="text-sm font-medium leading-tight">{f.title}</p>
                        {f.cve_id && (
                          <p className="text-xs font-mono text-muted-foreground mt-0.5">{f.cve_id}</p>
                        )}
                      </TableCell>
                      <TableCell><StateBadge state={f.state} /></TableCell>
                      <TableCell className="hidden md:table-cell text-xs text-muted-foreground">
                        {relativeTime(f.last_seen_at)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </TabsContent>

        {/* ── TLS certificates ── */}
        {hasCerts && (
          <TabsContent value="tls" className="pt-5">
            <TlsPanel entries={portEntries} allAssets={allAssets} selfId={asset.id} />
          </TabsContent>
        )}

        {/* ── Relationships ── */}
        <TabsContent value="relationships" className="pt-5">
          <ConnectedEntities
            nodeType="asset_canonical"
            nodeId={asset.id}
            observedNames={observedNames}
          />
        </TabsContent>

        {/* ── Timeline ── */}
        <TabsContent value="timeline" className="pt-5">
          {timelineEvents.map((ev, i) => (
            <div key={i} className="flex items-start gap-3 pb-4">
              <div className="mt-1 h-2 w-2 rounded-full border-2 border-primary bg-background shrink-0" />
              <div className="space-y-0.5 text-sm">
                <p className="font-medium">{ev.label}</p>
                <p className="text-xs text-muted-foreground">
                  {new Date(ev.date).toLocaleString()} · {relativeTime(ev.date)}
                </p>
              </div>
            </div>
          ))}
        </TabsContent>

        {/* ── Raw ── */}
        <TabsContent value="raw" className="pt-5">
          <pre className="text-xs font-mono bg-muted/40 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(asset.asset_metadata, null, 2)}
          </pre>
        </TabsContent>
      </Tabs>
    </div>
  )
}
