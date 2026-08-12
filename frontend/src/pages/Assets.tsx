import React, { useState } from "react"
import { Link } from "react-router-dom"
import { useFlyout } from "@/lib/flyout"
import { useListView, type GroupMode } from "@/lib/listView"
import { ViewToggle, GroupBySelect } from "@/components/ListControls"
import { AssetCard } from "@/components/AssetCard"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  Globe, RefreshCw, Filter, Trash2, Loader2,
  EyeOff, Eye, Tag, ChevronDown, ChevronRight,
  ChevronsDownUp, ChevronsUpDown, Clock, SquareArrowOutUpRight, Sparkles,
} from "lucide-react"
import { ConnectedEntities, type ObservedName } from "@/components/ConnectedEntities"
import { OpenPortsPanel, type OpenPortEntry } from "@/components/OpenPortsPanel"
import { WorkspaceShell, type TabDef } from "@/components/WorkspaceShell"
import { PivotTable, type PivotSummaryRow, type PivotAssetRow, SENSITIVE_PORTS } from "@/components/PivotTable"
import { IndeterminateCheckbox } from "@/components/ui/indeterminate-checkbox"
import { OverflowCell } from "@/components/ui/overflow-cell"
import { relativeTime, isStale, daysSince } from "@/lib/time"
import { apexFromFqdn, displayName } from "@/lib/apex"
import { resolveTerminalIp } from "@/lib/assetChain"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { TagBadge } from "@/components/ui/tag-badge"
import { TagEditor } from "@/components/ui/tag-editor"
import { SourceBadges, SOURCE_META, RecordTypeBadge, AssetTypeBadge } from "@/components/asset-badges"
import { SeverityBadge, StateBadge, RiskBandBadge, FindingRiskBadge, RISK_BAND_LABEL, RISK_BAND_ORDER } from "@/components/finding-badges"
import { AssetRiskCard } from "@/components/AssetRiskCard"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { api, ApiError, type Asset, type Finding, type WhoisInfo, type DomainWhoisInfo } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { canMutate } from "@/lib/roles"

const PREVIEW_LIMIT = 20
const NEW_ASSET_DAYS = 7

const ASSETS_GROUP_OPTIONS: Array<{ value: GroupMode; label: string }> = [
  { value: "apex", label: "Group by domain" },
  { value: "band", label: "Group by risk" },
  { value: "none", label: "No grouping" },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function apexGroupKey(asset: Asset): string {
  if (asset.asset_type === "dns_record") return asset.parent_value ?? apexFromFqdn(asset.value)
  if (asset.asset_type === "ip_address" && asset.parent_value) return apexFromFqdn(asset.parent_value)
  return "Ungrouped"
}

// Asset risk bands extend the Findings vocabulary with "secure" (org-only verdict)
// and "unrated" (risk score not yet computed).
const ASSET_BAND_ORDER = [...RISK_BAND_ORDER, "secure", "unrated"]
const ASSET_BAND_LABEL: Record<string, string> = { ...RISK_BAND_LABEL, unrated: "Unrated" }

function bandGroupKey(asset: Asset): string {
  return asset.risk_band ?? "unrated"
}

/** Resolves an asset to its grouping-section key for the active GroupBySelect mode. */
function groupKeyFor(asset: Asset, group: GroupMode): string {
  if (group === "band") return bandGroupKey(asset)
  if (group === "apex") return apexGroupKey(asset)
  return "All assets"
}

/** Section header label for a group key, given the active grouping mode. */
function groupLabel(key: string, group: GroupMode): string {
  if (group === "band") return ASSET_BAND_LABEL[key] ?? key
  if (group === "none") return "All assets"
  return displayName(key)
}

function isRowVisible(asset: Asset, allAssets: Asset[]): boolean {
  if (asset.asset_type !== "ip_address") return true
  return !allAssets.some(a => a.asset_type === "dns_record" && a.value === asset.parent_value)
}

function isNew(asset: Asset): boolean {
  return (Date.now() - new Date(asset.first_seen_at).getTime()) < NEW_ASSET_DAYS * 86_400_000
}

// ── Port / service pivot derives ──────────────────────────────────────────────

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

// ── Verdict / emotional-design helpers ───────────────────────────────────────

// Top-border accent for the flyout, keyed on the asset's Risk Score band.
const BAND_BORDER: Record<string, string> = {
  imminent_compromise: "border-t-red-500",
  high:                "border-t-orange-500",
  elevated:            "border-t-amber-500",
  low:                 "border-t-blue-500",
  secure:              "border-t-emerald-500",
}

const FLY_TRIGGER = "h-9 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-foreground text-muted-foreground text-xs font-medium px-3 transition-none"

function worstOf(rows: PivotAssetRow[]): Finding["severity"] | null {
  return rows.reduce<Finding["severity"] | null>((best, a) => {
    const ra = a.worstSeverity ? (SEV_RANK[a.worstSeverity] ?? 0) : 0
    const rb = best ? (SEV_RANK[best] ?? 0) : 0
    return ra > rb ? a.worstSeverity : best
  }, null)
}

function pivotSort(rows: PivotSummaryRow[]): PivotSummaryRow[] {
  return rows.sort((a, b) => {
    const ra = a.worstSeverity ? (SEV_RANK[a.worstSeverity] ?? 0) : 0
    const rb = b.worstSeverity ? (SEV_RANK[b.worstSeverity] ?? 0) : 0
    if (ra !== rb) return rb - ra
    return b.assetCount - a.assetCount
  })
}

function derivePivotPortRows(assets: Asset[]): PivotSummaryRow[] {
  const map = new Map<number, {
    services: Set<string>
    versions: Set<string>
    assets: Map<string, PivotAssetRow>
  }>()
  for (const asset of assets) {
    if (asset.asset_type !== "ip_address") continue
    const ports = asset.asset_metadata.open_ports as OpenPortEntry[] | undefined
    if (!ports?.length) continue
    for (const p of ports) {
      if (!map.has(p.port)) map.set(p.port, { services: new Set(), versions: new Set(), assets: new Map() })
      const entry = map.get(p.port)!
      if (p.service)         entry.services.add(p.service)
      if (p.service_version) entry.versions.add(p.service_version)
      entry.assets.set(asset.id, {
        assetId:          asset.id,
        assetValue:       asset.value,
        assetParentValue: asset.parent_value,
        port:             p.port,
        service:          p.service ?? null,
        serviceVersion:   p.service_version ?? null,
        lastSeenAt:       p.last_seen_at ?? null,
        worstSeverity:    asset.worst_severity,
      })
    }
  }
  const rows: PivotSummaryRow[] = []
  for (const [port, entry] of map) {
    const services = [...entry.services]
    const versions = [...entry.versions]
    const assetList = [...entry.assets.values()]
    rows.push({
      key:           String(port),
      label:         String(port),
      sublabel:      services[0],
      isSensitive:   SENSITIVE_PORTS.has(port),
      services,
      ports:         [port],
      versions,
      hasDrift:      versions.length > 1,
      assetCount:    entry.assets.size,
      worstSeverity: worstOf(assetList),
      assets:        assetList,
    })
  }
  return pivotSort(rows)
}

function derivePivotServiceRows(assets: Asset[]): PivotSummaryRow[] {
  const map = new Map<string, {
    ports:    Set<number>
    versions: Set<string>
    assets:   Map<string, PivotAssetRow>
  }>()
  for (const asset of assets) {
    if (asset.asset_type !== "ip_address") continue
    const ports = asset.asset_metadata.open_ports as OpenPortEntry[] | undefined
    if (!ports?.length) continue
    for (const p of ports) {
      const svc = p.service ?? "unknown"
      if (!map.has(svc)) map.set(svc, { ports: new Set(), versions: new Set(), assets: new Map() })
      const entry = map.get(svc)!
      entry.ports.add(p.port)
      if (p.service_version) entry.versions.add(p.service_version)
      entry.assets.set(`${asset.id}:${p.port}`, {
        assetId:          asset.id,
        assetValue:       asset.value,
        assetParentValue: asset.parent_value,
        port:             p.port,
        service:          p.service ?? null,
        serviceVersion:   p.service_version ?? null,
        lastSeenAt:       p.last_seen_at ?? null,
        worstSeverity:    asset.worst_severity,
      })
    }
  }
  const rows: PivotSummaryRow[] = []
  for (const [svc, entry] of map) {
    const ports = [...entry.ports].sort((a, b) => a - b)
    const versions = [...entry.versions]
    const assetList = [...entry.assets.values()]
    const uniqueAssetCount = new Set(assetList.map(a => a.assetId)).size
    rows.push({
      key:           svc,
      label:         svc,
      isSensitive:   ports.some(p => SENSITIVE_PORTS.has(p)),
      services:      [svc],
      ports,
      versions,
      hasDrift:      versions.length > 1,
      assetCount:    uniqueAssetCount,
      worstSeverity: worstOf(assetList),
      assets:        assetList,
    })
  }
  return pivotSort(rows)
}

// ── Tab definitions ───────────────────────────────────────────────────────────

const ASSET_TAB_KEYS = ["all", "dns_record", "ip_address"] as const

function buildTabs(assets: Asset[] | undefined, pivotPortRows: PivotSummaryRow[], pivotServiceRows: PivotSummaryRow[]): TabDef[] {
  const counts: Record<string, number> = { all: 0 }
  for (const a of assets ?? []) {
    counts.all = (counts.all ?? 0) + 1
    counts[a.asset_type] = (counts[a.asset_type] ?? 0) + 1
  }
  const assetTabs = ASSET_TAB_KEYS
    .filter(k => k === "all" || (counts[k] ?? 0) > 0)
    .map(k => ({ key: k, label: k === "all" ? "All" : k === "dns_record" ? "Domains" : "IPs", count: counts[k] ?? 0 }))

  const pivotTabs: TabDef[] = [
    { key: "ports",    label: "Ports",    count: pivotPortRows.length },
    { key: "services", label: "Services", count: pivotServiceRows.length },
  ].filter(t => t.count > 0)

  return [...assetTabs, ...pivotTabs]
}

// ── Asset detail flyout ───────────────────────────────────────────────────────

function AssetDetailSheet({
  asset, allAssets, onClose, onScan, onIgnore,
}: {
  asset: Asset
  allAssets: Asset[]
  onClose: () => void
  onScan: (id: string) => void
  onIgnore: (id: string, ignored: boolean) => void
}) {
  const qc = useQueryClient()
  const tagMutation = useMutation({
    mutationFn: (tags: string[]) => api.patch(`/tags/assets/${asset.id}`, { tags }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["assets"] }),
    onError: () => toast.error("Failed to update tags"),
  })

  const { data: assetFindings = [] } = useQuery<Finding[]>({
    queryKey: ["findings", "asset", asset.id],
    // include_children rolls up findings from the IP(s) this asset resolves to,
    // matching the Assets risk column (which aggregates the same way).
    queryFn: () => api.get<Finding[]>(`/findings/?asset_canonical_id=${asset.id}&include_children=true`),
    staleTime: 30_000,
  })

  const activeFindings = assetFindings.filter(f => f.state === "open" || f.state === "acknowledged")

  const m = asset.asset_metadata
  const sources: string[] = Array.isArray(m.sources)
    ? (m.sources as string[])
    : m.source ? [m.source as string] : []

  // Follows CNAME chains (host1 → host2 → IP) so an intermediate hostname
  // surfaces the same ports/TLS/WHOIS as the host it resolves to.
  const ipForWhois = resolveTerminalIp(asset, allAssets)

  const { data: whois, isLoading: whoisLoading } = useQuery<WhoisInfo>({
    queryKey: ["whois", ipForWhois],
    queryFn: () => api.get<WhoisInfo>(`/assets/whois?ip=${encodeURIComponent(ipForWhois!)}`),
    enabled: !!ipForWhois,
    staleTime: 60 * 60 * 1000,
  })

  const domainForWhois = asset.asset_type === "dns_record" ? apexFromFqdn(asset.value) : null
  const { data: domainWhois, isLoading: domainWhoisLoading } = useQuery<DomainWhoisInfo>({
    queryKey: ["domain-whois", domainForWhois],
    queryFn: () => api.get<DomainWhoisInfo>(`/assets/whois-domain?domain=${encodeURIComponent(domainForWhois!)}`),
    enabled: !!domainForWhois,
    staleTime: 60 * 60 * 1000,
  })

  const expiryDate = domainWhois?.expiration_date ? new Date(domainWhois.expiration_date) : null
  const daysToExpiry = expiryDate ? Math.floor((expiryDate.getTime() - Date.now()) / 86_400_000) : null
  const expiringSoon = daysToExpiry !== null && daysToExpiry <= 30 && daysToExpiry >= 0
  const expired = daysToExpiry !== null && daysToExpiry < 0
  const hasDomainData = domainWhois && (
    domainWhois.registrar || domainWhois.registrant_org || domainWhois.creation_date ||
    domainWhois.expiration_date || domainWhois.name_servers.length > 0
  )

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
  const legacyShodanPorts: number[] = hasShodanEnrichment && Array.isArray(enrichMeta.shodan_ports) ? (enrichMeta.shodan_ports as number[]) : []
  const hasAnyPorts = portEntries.length > 0 || legacyShodanPorts.length > 0

  type EolService = { port: number; service: string | null; product: string; version: string; eol_date: string | null; is_eol: boolean; days_past_eol: number | null; latest: string | null }
  const eolServices: EolService[] = Array.isArray(enrichMeta.eol_services) ? (enrichMeta.eol_services as EolService[]) : []

  const trackedDnsNames = new Set<string>()
  for (const other of allAssets) {
    if (other.asset_type === "dns_record") trackedDnsNames.add(other.value.toLowerCase().replace(/\.$/, ""))
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

  const showNetworkLookup = ipForWhois && whoisLoading && !networkRows.length
  const showNetworkEmpty = ipForWhois && !whoisLoading && !networkRows.length && whois && !whois.public

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className={`w-[540px] sm:max-w-[540px] flex flex-col gap-0 p-0 border-t-2 ${BAND_BORDER[asset.risk_band ?? "secure"] ?? BAND_BORDER.secure}`}>
        <SheetHeader className="px-6 pt-5 pb-3 border-b space-y-1.5 shrink-0">
          <div className="flex items-center gap-2 flex-wrap">
            {asset.asset_type === "dns_record" && m.record_type
              ? <RecordTypeBadge type={String(m.record_type)} />
              : <AssetTypeBadge type={asset.asset_type} />}
            {asset.ignored && <span className="text-xs text-muted-foreground italic">ignored</span>}
            <Link
              to={`/assets/${asset.id}`}
              className="ml-auto mr-6 text-muted-foreground hover:text-foreground"
              title="Open full asset view"
            >
              <SquareArrowOutUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>
          <SheetTitle className="font-mono text-sm break-all leading-relaxed" title={asset.value}>
            {displayName(asset.value)}
          </SheetTitle>
          <SheetDescription className="sr-only">
            Detail panel for {asset.asset_type.replace("_", " ")} {asset.value}
          </SheetDescription>
          {asset.asset_type === "dns_record" && typeof m.content === "string" && (
            <p className="text-xs font-mono text-muted-foreground break-all">→ {m.content}</p>
          )}
        </SheetHeader>

        <Tabs defaultValue="overview" className="flex-1 flex flex-col min-h-0">
          <div className="border-b shrink-0 px-2">
            <TabsList className="h-auto w-full justify-start gap-0 bg-transparent rounded-none p-0">
              <TabsTrigger value="overview"      className={FLY_TRIGGER}>Overview</TabsTrigger>
              <TabsTrigger value="findings"      className={FLY_TRIGGER}>
                Findings
                {activeFindings.length > 0 && (
                  <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[9px] font-semibold">
                    {activeFindings.length}
                  </span>
                )}
              </TabsTrigger>
              <TabsTrigger value="relationships" className={FLY_TRIGGER}>Relationships</TabsTrigger>
              <TabsTrigger value="timeline"      className={FLY_TRIGGER}>Timeline</TabsTrigger>
              <TabsTrigger value="raw"           className={FLY_TRIGGER}>Raw</TabsTrigger>
            </TabsList>
          </div>

          <div className="flex-1 overflow-y-auto">

            {/* ── Overview ── */}
            <TabsContent value="overview" className="m-0">
              <div className="px-6 py-5 space-y-5">

                {/* Risk verdict hero + band distribution + top finding spotlight */}
                <AssetRiskCard asset={asset} findings={assetFindings} />

                <Separator />

                {/* Identity grid */}
                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div className="space-y-0.5">
                    <p className="text-muted-foreground">Parent</p>
                    <p className="font-mono break-all">{asset.parent_value ? displayName(asset.parent_value) : "—"}</p>
                  </div>
                  <div className="space-y-0.5">
                    <p className="text-muted-foreground">First seen</p>
                    <p>{new Date(asset.first_seen_at).toLocaleString()}</p>
                  </div>
                  <div className="space-y-0.5">
                    <p className="text-muted-foreground">Last seen</p>
                    <p>
                      {new Date(asset.last_seen_at).toLocaleString()}
                      <span className="text-muted-foreground"> · {relativeTime(asset.last_seen_at)}</span>
                    </p>
                  </div>
                </div>

                {sources.length > 0 && (
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Sources</span>
                    {sources.map(src => {
                      const meta = SOURCE_META[src] ?? { label: src.slice(0, 2).toUpperCase(), color: "bg-muted text-muted-foreground", description: src }
                      return (
                        <span key={src} className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold cursor-default ${meta.color}`} title={meta.description}>
                          {meta.label}
                        </span>
                      )
                    })}
                  </div>
                )}

                <div className="space-y-2">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Tags</p>
                  <TagEditor tags={asset.tags ?? []} entityType="asset" onChange={tags => tagMutation.mutate(tags)} />
                </div>

                {(networkRows.length > 0 || showNetworkLookup || showNetworkEmpty) && (
                  <div className="space-y-2">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Network</p>
                    {showNetworkLookup ? (
                      <p className="text-xs text-muted-foreground italic">Looking up…</p>
                    ) : showNetworkEmpty ? (
                      <p className="text-xs text-muted-foreground italic">Private / non-routable IP — no public network info available.</p>
                    ) : (
                      <div className="rounded-md border divide-y text-xs">
                        {networkRows.map(row => (
                          <div key={row.label} className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-24">{row.label}</span>
                            <span className={`flex-1 break-all text-foreground ${row.mono ? "font-mono" : ""}`}>{row.value}</span>
                            {row.source !== "asset" && (
                              <span className="text-[10px] uppercase tracking-wider text-muted-foreground shrink-0">{row.source}</span>
                            )}
                          </div>
                        ))}
                        {whois?.looked_up_at && (
                          <div className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-24">Last lookup</span>
                            <span className="flex-1 text-muted-foreground">{new Date(whois.looked_up_at).toLocaleDateString()}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {hasAnyPorts && <OpenPortsPanel entries={portEntries} legacyShodanPorts={legacyShodanPorts} />}

                {eolServices.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Software Inventory</p>
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

                {signals.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Signals</p>
                    <div className="rounded-md border px-3 py-2 flex flex-wrap gap-1">
                      {signals.map(s => (
                        <span key={`${s.value}-${s.source}`} className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs ${s.severity === "critical" ? "bg-destructive/15 text-destructive" : "bg-muted text-foreground"}`}>
                          {s.value}
                          <span className="text-[9px] uppercase tracking-wider opacity-60">{s.source}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {domainForWhois && (
                  <div className="space-y-2">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Domain Registration</p>
                    {domainWhoisLoading ? (
                      <p className="text-xs text-muted-foreground italic">Looking up…</p>
                    ) : hasDomainData ? (
                      <div className="rounded-md border divide-y text-xs">
                        <div className="flex items-start gap-3 px-3 py-2">
                          <span className="text-muted-foreground shrink-0 w-28">Domain</span>
                          <span className="font-mono text-foreground break-all">{domainWhois!.domain}</span>
                        </div>
                        {domainWhois!.registrar && (
                          <div className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-28">Registrar</span>
                            <span className="text-foreground break-all">{domainWhois!.registrar}</span>
                          </div>
                        )}
                        {domainWhois!.registrant_org && (
                          <div className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-28">Registrant</span>
                            <span className="text-foreground break-all">{domainWhois!.registrant_org}</span>
                          </div>
                        )}
                        {domainWhois!.registrant_country && (
                          <div className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-28">Country</span>
                            <span className="text-foreground">{domainWhois!.registrant_country}</span>
                          </div>
                        )}
                        {domainWhois!.creation_date && (
                          <div className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-28">Created</span>
                            <span className="text-foreground">{new Date(domainWhois!.creation_date).toLocaleDateString()}</span>
                          </div>
                        )}
                        {domainWhois!.expiration_date && (
                          <div className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-28">Expires</span>
                            <span className={expired ? "text-destructive font-medium" : expiringSoon ? "text-orange-500 font-medium" : "text-foreground"}>
                              {new Date(domainWhois!.expiration_date).toLocaleDateString()}
                              {expired && " — expired"}
                              {expiringSoon && ` — expires in ${daysToExpiry} day${daysToExpiry !== 1 ? "s" : ""}`}
                            </span>
                          </div>
                        )}
                        {domainWhois!.name_servers.length > 0 && (
                          <div className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-28">Nameservers</span>
                            <div className="font-mono text-foreground space-y-0.5 break-all">
                              {domainWhois!.name_servers.map(ns => <div key={ns}>{ns}</div>)}
                            </div>
                          </div>
                        )}
                        {domainWhois!.status.length > 0 && (
                          <div className="flex items-start gap-3 px-3 py-2">
                            <span className="text-muted-foreground shrink-0 w-28">Status</span>
                            <div className="text-muted-foreground space-y-0.5 break-all">
                              {domainWhois!.status.map(s => <div key={s}>{s}</div>)}
                            </div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground italic">WHOIS data unavailable for this TLD.</p>
                    )}
                  </div>
                )}
              </div>
            </TabsContent>

            {/* ── Findings ── */}
            <TabsContent value="findings" className="m-0">
              <div className="px-6 py-5 space-y-3">
                <p className="text-xs text-muted-foreground">
                  {assetFindings.length} finding{assetFindings.length !== 1 ? "s" : ""} on this asset
                </p>
                {assetFindings.length === 0 ? (
                  <p className="py-8 text-center text-sm text-muted-foreground">No findings</p>
                ) : (
                  <div className="space-y-1.5">
                    {[...assetFindings]
                      .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))
                      .map(f => (
                        <Link
                          key={f.id}
                          to={`/findings?id=${f.id}`}
                          className="flex items-center gap-2 px-3 py-2 rounded-md border hover:bg-muted/50 transition-colors"
                        >
                          <FindingRiskBadge finding={f} />
                          <StateBadge state={f.state} />
                          <span className="flex-1 text-xs min-w-0 truncate">{f.title}</span>
                          <SquareArrowOutUpRight className="h-3 w-3 shrink-0 text-muted-foreground" />
                        </Link>
                      ))}
                  </div>
                )}
              </div>
            </TabsContent>

            {/* ── Relationships ── */}
            <TabsContent value="relationships" className="m-0">
              <div className="px-6 py-5">
                <ConnectedEntities nodeType="asset_canonical" nodeId={asset.id} observedNames={observedNames} />
              </div>
            </TabsContent>

            {/* ── Timeline ── */}
            <TabsContent value="timeline" className="m-0">
              <div className="px-6 py-5">
                {[
                  { date: asset.first_seen_at, label: "First discovered" },
                  asset.last_seen_at !== asset.first_seen_at
                    ? { date: asset.last_seen_at, label: "Last seen" }
                    : null,
                ].filter(Boolean).map((ev, i) => (
                  <div key={i} className="flex items-start gap-3 pb-4">
                    <div className="mt-1 h-2 w-2 rounded-full border-2 border-primary bg-background shrink-0" />
                    <div className="space-y-0.5 text-sm">
                      <p className="font-medium">{ev!.label}</p>
                      <p className="text-xs text-muted-foreground">
                        {new Date(ev!.date).toLocaleString()} · {relativeTime(ev!.date)}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </TabsContent>

            {/* ── Raw ── */}
            <TabsContent value="raw" className="m-0">
              <div className="px-6 py-5">
                <pre className="text-xs font-mono bg-muted/40 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(asset.asset_metadata, null, 2)}
                </pre>
              </div>
            </TabsContent>
          </div>
        </Tabs>

        <div className="px-6 py-4 border-t flex gap-2 shrink-0">
          {!asset.ignored && (
            <Button size="sm" variant="outline" onClick={() => { onScan(asset.id); onClose() }}>
              <RefreshCw className="h-3.5 w-3.5 mr-1.5" />Recheck
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => onIgnore(asset.id, !asset.ignored)}>
            {asset.ignored ? <Eye className="h-3.5 w-3.5 mr-1.5" /> : <EyeOff className="h-3.5 w-3.5 mr-1.5" />}
            {asset.ignored ? "Restore" : "Ignore"}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  )
}

// (PortsTable + ServicesTable replaced by <PivotTable> component)

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Assets() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const mutable = canMutate(user?.role)
  const [activeTab, setActiveTab]       = useState<string>("all")
  const [search, setSearch]             = useState("")
  const [showIgnored, setShowIgnored]   = useState(false)
  const [tagFilter, setTagFilter]       = useState("all")
  const [collapsedGroups, setCollapsedGroups] = useState(new Set<string>())
  const [expandedGroups, setExpandedGroups]   = useState(new Set<string>())
  const [selectedIds, setSelectedIds]   = useState(new Set<string>())
  const [bulkDeleteOpen, setBulkDeleteOpen]   = useState(false)
  const { view, setView, group, setGroup } = useListView("apex")

  const { data: assets, isLoading } = useQuery({
    queryKey: ["assets", showIgnored],
    queryFn: () => {
      const params = new URLSearchParams()
      if (showIgnored) params.set("show_ignored", "true")
      return api.get<Asset[]>(`/assets/?${params}`)
    },
  })

  const scanMutation = useMutation({
    mutationFn: (assetId: string) => api.post(`/assets/${assetId}/scan`),
    onSuccess: () => { toast.success("Recheck queued"); qc.invalidateQueries({ queryKey: ["scans"] }) },
    onError: () => toast.error("Failed to start recheck"),
  })

  const bulkRecheckMutation = useMutation({
    mutationFn: (assetIds: string[]) =>
      api.post<{ scan_id: string; asset_count: number }>("/assets/bulk/recheck", { asset_ids: assetIds }),
    onSuccess: (r) => {
      toast.success(`Recheck queued for ${r.asset_count} asset${r.asset_count !== 1 ? "s" : ""}`)
      setSelectedIds(new Set())
      qc.invalidateQueries({ queryKey: ["scans"] })
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Failed to queue recheck"),
  })

  const ignoreMutation = useMutation({
    mutationFn: ({ assetId, ignored }: { assetId: string; ignored: boolean }) =>
      api.patch(`/assets/${assetId}/ignore`, { ignored }),
    onSuccess: (_, { ignored }) => {
      toast.success(ignored ? "Asset ignored" : "Asset restored")
      qc.invalidateQueries({ queryKey: ["assets"] })
    },
    onError: () => toast.error("Failed to update asset"),
  })

  const bulkDeleteMutation = useMutation({
    mutationFn: (assetIds: string[]) =>
      api.delete<{ deleted: number }>("/assets/bulk", { asset_ids: assetIds }),
    onSuccess: (r) => {
      toast.success(`${r.deleted} asset${r.deleted !== 1 ? "s" : ""} deleted`)
      setSelectedIds(new Set())
      setBulkDeleteOpen(false)
      qc.invalidateQueries({ queryKey: ["assets"] })
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Failed to delete assets"),
  })

  // Tab drives the type filter; other filters layer on top
  const filtered = (assets ?? []).filter(a => {
    if (activeTab !== "all" && a.asset_type !== activeTab) return false
    if (tagFilter !== "all" && !(a.tags ?? []).includes(tagFilter)) return false
    if (search) {
      const q = search.toLowerCase()
      if (!a.value.toLowerCase().includes(q) && !displayName(a.value).toLowerCase().includes(q)) return false
    }
    return true
  })

  const isFiltering = search !== "" || tagFilter !== "all"
  const visibleRows = filtered.filter(a => isRowVisible(a, filtered))

  const grouped = new Map<string, Asset[]>()
  for (const asset of visibleRows) {
    const key = groupKeyFor(asset, group)
    const existing = grouped.get(key) ?? []
    existing.push(asset)
    grouped.set(key, existing)
  }

  const sortedGroups = [...grouped.keys()].sort((a, b) => {
    if (group === "band") return ASSET_BAND_ORDER.indexOf(a) - ASSET_BAND_ORDER.indexOf(b)
    if (a === "Ungrouped") return 1
    if (b === "Ungrouped") return -1
    return a.localeCompare(b)
  })

  const allCollapsed = sortedGroups.every(k => collapsedGroups.has(k))

  function toggleAllCollapse() {
    if (allCollapsed) setCollapsedGroups(new Set())
    else setCollapsedGroups(new Set(sortedGroups))
  }

  function toggleOneAsset(id: string, checked: boolean) {
    setSelectedIds(prev => { const next = new Set(prev); if (checked) next.add(id); else next.delete(id); return next })
  }

  function toggleGroupAssets(key: string, checked: boolean) {
    const groupAssets = grouped.get(key) ?? []
    setSelectedIds(prev => {
      const next = new Set(prev)
      for (const a of groupAssets) { if (checked) next.add(a.id); else next.delete(a.id) }
      return next
    })
  }

  const availableTags = [...new Set((assets ?? []).flatMap(a => a.tags ?? []))].sort()
  const pivotPortRows    = React.useMemo(() => derivePivotPortRows(assets ?? []),    [assets])
  const pivotServiceRows = React.useMemo(() => derivePivotServiceRows(assets ?? []), [assets])
  const tabs = buildTabs(assets, pivotPortRows, pivotServiceRows)
  const isPivotTab = activeTab === "ports" || activeTab === "services"
  // Look up the selected asset across ALL assets (not just visibleRows) so the
  // flyout opens for IPs shown only in the Ports/Services pivots (hidden children).
  const { selected: selectedAsset, open: openAsset, close: closeAsset } = useFlyout(visibleRows, "id", assets ?? [])

  const filteredPivotPortRows = React.useMemo(() => {
    if (!search) return pivotPortRows
    const q = search.toLowerCase()
    return pivotPortRows.filter(r =>
      r.label.includes(q) ||
      r.services.some(s => s.toLowerCase().includes(q)) ||
      r.assets.some(a => a.assetValue.toLowerCase().includes(q) || (a.assetParentValue?.toLowerCase().includes(q) ?? false))
    )
  }, [pivotPortRows, search])

  const filteredPivotServiceRows = React.useMemo(() => {
    if (!search) return pivotServiceRows
    const q = search.toLowerCase()
    return pivotServiceRows.filter(r =>
      r.label.toLowerCase().includes(q) ||
      r.ports.some(p => String(p).includes(q))
    )
  }, [pivotServiceRows, search])

  const handlePivotAssetClick = React.useCallback((assetId: string) => {
    const asset = (assets ?? []).find(a => a.id === assetId)
    if (asset) openAsset(asset)
  }, [assets, openAsset])

  // ── Toolbar ─────────────────────────────────────────────────────────────────

  const searchPlaceholder =
    activeTab === "ports"    ? "Filter by port or service…" :
    activeTab === "services" ? "Filter by service…" :
    "Filter by value…"

  const toolbar = (
    <>
      <div className="relative flex-1 min-w-48 max-w-sm">
        <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
        <Input className="pl-8 h-9 text-sm" placeholder={searchPlaceholder}
          value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {!isPivotTab && availableTags.length > 0 && (
        <Select value={tagFilter} onValueChange={setTagFilter}>
          <SelectTrigger className="w-36 h-9 text-sm">
            <Tag className="h-3 w-3 mr-1.5 text-muted-foreground" />
            <SelectValue placeholder="All tags" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All tags</SelectItem>
            {availableTags.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
          </SelectContent>
        </Select>
      )}

      {!isPivotTab && (
        <Button variant={showIgnored ? "secondary" : "outline"} size="sm" className="h-9 gap-1.5"
          onClick={() => setShowIgnored(v => !v)}>
          {showIgnored ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
          {showIgnored ? "Showing ignored" : "Show ignored"}
        </Button>
      )}

      {!isPivotTab && sortedGroups.length > 1 && (
        <Button variant="outline" size="sm" className="h-9 gap-1.5" onClick={toggleAllCollapse}>
          {allCollapsed
            ? <><ChevronsUpDown className="h-3.5 w-3.5" />Expand all</>
            : <><ChevronsDownUp className="h-3.5 w-3.5" />Collapse all</>}
        </Button>
      )}

      <div className="ml-auto flex items-center gap-2">
        <span className="text-xs text-muted-foreground">
          {isPivotTab
            ? activeTab === "ports"
              ? `${filteredPivotPortRows.length} port${filteredPivotPortRows.length !== 1 ? "s" : ""}`
              : `${filteredPivotServiceRows.length} service${filteredPivotServiceRows.length !== 1 ? "s" : ""}`
            : `${visibleRows.length} asset${visibleRows.length !== 1 ? "s" : ""}`}
        </span>
        {!isPivotTab && <GroupBySelect group={group} onChange={setGroup} options={ASSETS_GROUP_OPTIONS} />}
        {!isPivotTab && <ViewToggle view={view} onChange={setView} />}
      </div>
    </>
  )

  // ── Bulk action bar ──────────────────────────────────────────────────────────

  const selectedAssets = (assets ?? []).filter(a => selectedIds.has(a.id))
  const rescannable = selectedAssets.filter(
    a => !a.ignored && (a.asset_type === "dns_record" || a.asset_type === "ip_address")
  )

  const bulkBar = selectedIds.size > 0 && mutable ? (
    <div className="flex items-center gap-3">
      <span className="text-sm font-medium">{selectedIds.size} selected</span>
      {rescannable.length < selectedIds.size && (
        <span className="text-xs text-muted-foreground">{rescannable.length} rescannable</span>
      )}
      <div className="flex items-center gap-2 ml-auto">
        <Button size="sm" variant="outline"
          disabled={bulkRecheckMutation.isPending || rescannable.length === 0}
          onClick={() => bulkRecheckMutation.mutate(rescannable.map(a => a.id))}>
          {bulkRecheckMutation.isPending
            ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
            : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
          Recheck
        </Button>
        <Button size="sm" variant="outline"
          className="text-destructive hover:text-destructive hover:bg-destructive/10 border-destructive/40"
          disabled={bulkDeleteMutation.isPending}
          onClick={() => setBulkDeleteOpen(true)}>
          <Trash2 className="h-3.5 w-3.5 mr-1.5" />Delete
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>Clear</Button>
      </div>
    </div>
  ) : undefined

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <>
      <WorkspaceShell
        title="Assets"
        subtitle="Discovered public-facing assets and their correlation chain"
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={(key) => { setActiveTab(key); setSelectedIds(new Set()) }}
        toolbar={toolbar}
        bulkBar={bulkBar}
      >
        {isLoading ? (
          <div className="space-y-2">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
        ) : activeTab === "ports" ? (
          <PivotTable rows={filteredPivotPortRows} mode="ports" onAssetClick={handlePivotAssetClick} emptyMessage="No open ports discovered" />
        ) : activeTab === "services" ? (
          <PivotTable rows={filteredPivotServiceRows} mode="services" onAssetClick={handlePivotAssetClick} emptyMessage="No services detected" />
        ) : visibleRows.length === 0 ? (
          <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
            <Globe className="h-12 w-12 mx-auto mb-4 opacity-30" />
            <p className="font-medium">{assets?.length === 0 ? "No assets discovered" : "No results"}</p>
            <p className="text-sm mt-1">{assets?.length === 0 ? "Run a scan to populate the asset inventory." : "Try adjusting your filters."}</p>
          </div>
        ) : view === "card" ? (
          <div className="space-y-5">
            {sortedGroups.map(key => {
              const groupAssets = grouped.get(key)!
              const isCollapsed = collapsedGroups.has(key)
              const isExpanded  = expandedGroups.has(key)
              const truncated   = !isFiltering && !isExpanded && groupAssets.length > PREVIEW_LIMIT
              const visibleAssets = truncated ? groupAssets.slice(0, PREVIEW_LIMIT) : groupAssets
              const hiddenCount   = groupAssets.length - PREVIEW_LIMIT
              const groupSelectedCount = groupAssets.filter(a => selectedIds.has(a.id)).length
              const allGroupSelected   = groupSelectedCount === groupAssets.length
              const someGroupSelected  = groupSelectedCount > 0 && !allGroupSelected
              return (
                <div key={key} className="space-y-3">
                  {/* Group header */}
                  <div
                    className="flex items-center gap-2 cursor-pointer select-none"
                    onClick={() => setCollapsedGroups(prev => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n })}
                  >
                    <span onClick={e => e.stopPropagation()}>
                      <IndeterminateCheckbox checked={allGroupSelected} indeterminate={someGroupSelected} onChange={c => toggleGroupAssets(key, c)} />
                    </span>
                    {isCollapsed
                      ? <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                    <span className={`text-sm font-semibold ${group === "apex" ? "font-mono" : ""}`}>{groupLabel(key, group)}</span>
                    <span className="text-xs text-muted-foreground bg-muted px-1.5 py-0.5 rounded-full">{groupAssets.length}</span>
                  </div>
                  {!isCollapsed && (
                    <>
                      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                        {visibleAssets.map(asset => (
                          <AssetCard
                            key={asset.id}
                            asset={asset}
                            onOpen={() => openAsset(asset)}
                            selected={selectedIds.has(asset.id)}
                            onSelect={c => toggleOneAsset(asset.id, c)}
                          />
                        ))}
                      </div>
                      {truncated && (
                        <button
                          className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1.5 transition-colors"
                          onClick={() => setExpandedGroups(prev => new Set([...prev, key]))}
                        >
                          <ChevronDown className="h-3 w-3" />Show {hiddenCount} more record{hiddenCount !== 1 ? "s" : ""}
                        </button>
                      )}
                    </>
                  )}
                </div>
              )
            })}
          </div>
        ) : (
          <div className="rounded-lg border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="w-8" />
                  <TableHead className="w-8" />
                  <TableHead>Name</TableHead>
                  <TableHead className="w-20">Risk</TableHead>
                  <TableHead className="w-20">Type</TableHead>
                  <TableHead className="hidden md:table-cell">Content</TableHead>
                  <TableHead className="w-28">Sources</TableHead>
                  <TableHead className="hidden lg:table-cell w-48">Tags</TableHead>
                  <TableHead className="w-24 text-right pr-4">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sortedGroups.map(key => {
                  const groupAssets = grouped.get(key)!
                  const isCollapsed = collapsedGroups.has(key)
                  const isExpanded  = expandedGroups.has(key)
                  const truncated   = !isFiltering && !isExpanded && groupAssets.length > PREVIEW_LIMIT
                  const visibleAssets = truncated ? groupAssets.slice(0, PREVIEW_LIMIT) : groupAssets
                  const hiddenCount   = groupAssets.length - PREVIEW_LIMIT

                  const groupSelectedCount = groupAssets.filter(a => selectedIds.has(a.id)).length
                  const allGroupSelected   = groupSelectedCount === groupAssets.length
                  const someGroupSelected  = groupSelectedCount > 0 && !allGroupSelected

                  return (
                    <React.Fragment key={key}>
                      {/* Group header row */}
                      <TableRow
                        className="bg-muted/30 hover:bg-muted/50 cursor-pointer select-none"
                        onClick={() => setCollapsedGroups(prev => {
                          const next = new Set(prev)
                          if (next.has(key)) next.delete(key); else next.add(key)
                          return next
                        })}
                      >
                        <TableCell className="pl-4 w-8" onClick={e => e.stopPropagation()}>
                          <IndeterminateCheckbox
                            checked={allGroupSelected}
                            indeterminate={someGroupSelected}
                            onChange={checked => toggleGroupAssets(key, checked)}
                          />
                        </TableCell>
                        <TableCell className="w-8">
                          {isCollapsed
                            ? <ChevronRight className="h-4 w-4 text-muted-foreground" />
                            : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                        </TableCell>
                        <TableCell colSpan={7}>
                          <div className="flex items-center gap-2">
                            <span className={`text-sm font-semibold ${group === "apex" ? "font-mono" : ""}`}>{groupLabel(key, group)}</span>
                            <span className="text-xs text-muted-foreground bg-muted px-1.5 py-0.5 rounded-full">
                              {groupAssets.length}
                            </span>
                          </div>
                        </TableCell>
                      </TableRow>

                      {/* Asset rows */}
                      {!isCollapsed && visibleAssets.map(asset => (
                        <TableRow
                          key={asset.id}
                          className={`cursor-pointer ${asset.ignored ? "opacity-50" : ""} ${selectedIds.has(asset.id) ? "bg-muted/20" : ""}`}
                          onClick={() => openAsset(asset)}
                        >
                          <TableCell className="pl-4 w-8" onClick={e => e.stopPropagation()}>
                            <IndeterminateCheckbox
                              checked={selectedIds.has(asset.id)}
                              onChange={checked => toggleOneAsset(asset.id, checked)}
                            />
                          </TableCell>
                          <TableCell className="w-8" />
                          <TableCell className="pl-4 font-mono text-sm">
                            <span className="inline-flex items-center gap-2">
                              {displayName(asset.value)}
                              {isNew(asset) && (
                                <span className="inline-flex items-center gap-1 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                                  <Sparkles className="h-2.5 w-2.5" />New
                                </span>
                              )}
                              {isStale(asset.last_seen_at) && (
                                <span
                                  className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400"
                                  title={`Last seen ${relativeTime(asset.last_seen_at)} — not observed in recent monitoring runs`}
                                >
                                  <Clock className="h-2.5 w-2.5" />
                                  stale {daysSince(asset.last_seen_at)}d
                                </span>
                              )}
                            </span>
                          </TableCell>
                          <TableCell>
                            {asset.risk_band
                              ? <RiskBandBadge band={asset.risk_band} score={asset.risk_score} />
                              : asset.worst_severity
                                ? <SeverityBadge severity={asset.worst_severity} />
                                : <span className="text-muted-foreground text-xs">—</span>}
                          </TableCell>
                          <TableCell>
                            {asset.asset_type === "dns_record" && asset.asset_metadata.record_type
                              ? <RecordTypeBadge type={String(asset.asset_metadata.record_type)} />
                              : <AssetTypeBadge type={asset.asset_type} />}
                          </TableCell>
                          <TableCell className="hidden md:table-cell font-mono text-xs text-muted-foreground">
                            {asset.asset_type === "dns_record"
                              ? displayName(String(asset.asset_metadata.content ?? ""))
                              : (asset.parent_value ? displayName(asset.parent_value) : "—")}
                          </TableCell>
                          <TableCell><SourceBadges metadata={asset.asset_metadata} /></TableCell>
                          <TableCell className="hidden lg:table-cell">
                            <OverflowCell
                              items={asset.tags ?? []}
                              renderItem={(tag) => <TagBadge key={tag} tag={tag} />}
                              renderOverflowItem={(tag) => <TagBadge key={tag} tag={tag} />}
                              getLabel={(tag) => tag}
                              limit={2}
                            />
                          </TableCell>
                          <TableCell className="w-24 pr-2" onClick={e => e.stopPropagation()}>
                            <div className="flex items-center justify-end gap-1">
                              {!asset.ignored && (
                                <Button variant="ghost" size="sm" title="Recheck"
                                  onClick={() => scanMutation.mutate(asset.id)}
                                  disabled={scanMutation.isPending}>
                                  <RefreshCw className="h-3.5 w-3.5" />
                                </Button>
                              )}
                              <Button variant="ghost" size="sm"
                                title={asset.ignored ? "Restore asset" : "Ignore asset"}
                                className={asset.ignored ? "text-muted-foreground" : undefined}
                                onClick={() => ignoreMutation.mutate({ assetId: asset.id, ignored: !asset.ignored })}
                                disabled={ignoreMutation.isPending}>
                                {asset.ignored ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}

                      {/* Show more row */}
                      {!isCollapsed && truncated && (
                        <TableRow key={`more-${key}`} className="hover:bg-muted/30">
                          <TableCell /><TableCell />
                          <TableCell colSpan={7} className="pl-4 py-2">
                            <button
                              className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1.5 transition-colors"
                              onClick={() => setExpandedGroups(prev => new Set([...prev, key]))}
                            >
                              <ChevronDown className="h-3 w-3" />
                              Show {hiddenCount} more record{hiddenCount !== 1 ? "s" : ""}
                            </button>
                          </TableCell>
                        </TableRow>
                      )}
                    </React.Fragment>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </WorkspaceShell>

      {selectedAsset && (
        <AssetDetailSheet
          asset={selectedAsset}
          allAssets={assets ?? []}
          onClose={closeAsset}
          onScan={(id) => scanMutation.mutate(id)}
          onIgnore={(id, ignored) => ignoreMutation.mutate({ assetId: id, ignored })}
        />
      )}

      <Dialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-destructive">
              Delete {selectedIds.size} asset{selectedIds.size !== 1 ? "s" : ""}?
            </DialogTitle>
            <DialogDescription>
              This permanently removes the selected assets and any CNAME-chain descendants. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBulkDeleteOpen(false)} disabled={bulkDeleteMutation.isPending}>
              Cancel
            </Button>
            <Button variant="destructive" disabled={bulkDeleteMutation.isPending}
              onClick={() => bulkDeleteMutation.mutate(Array.from(selectedIds))}>
              {bulkDeleteMutation.isPending
                ? <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
                : <Trash2 className="h-4 w-4 mr-1.5" />}
              Delete {selectedIds.size} asset{selectedIds.size !== 1 ? "s" : ""}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
