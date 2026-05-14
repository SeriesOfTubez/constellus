import { useState } from "react"
import { useSearchParams } from "react-router-dom"
import { useFlyout } from "@/lib/flyout"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Globe, ScanLine, Filter, Trash2, Loader2, EyeOff, Eye } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Asset, type ScanRun } from "@/lib/api"

// ── Source metadata ───────────────────────────────────────────────────────────

const SOURCE_META: Record<string, { label: string; color: string; description: string }> = {
  cloudflare:          { label: "CF",   color: "bg-orange-500/15 text-orange-600 dark:text-orange-400",  description: "Cloudflare DNS connector" },
  "crt.sh":            { label: "CT",   color: "bg-blue-500/15 text-blue-600 dark:text-blue-400",        description: "Certificate Transparency (crt.sh)" },
  certspotter:         { label: "CS",   color: "bg-blue-500/15 text-blue-600 dark:text-blue-400",        description: "Certificate Transparency (certspotter)" },
  cert_transparency:   { label: "CT",   color: "bg-blue-500/15 text-blue-600 dark:text-blue-400",        description: "Certificate Transparency" },
  subfinder:           { label: "SF",   color: "bg-purple-500/15 text-purple-600 dark:text-purple-400",  description: "subfinder passive enumeration" },
  dnsrecon:            { label: "DR",   color: "bg-green-500/15 text-green-600 dark:text-green-400",     description: "dnsrecon active DNS enumeration" },
  bruteforce:          { label: "BF",   color: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400",  description: "Subdomain brute-force" },
  tenable:             { label: "TN",   color: "bg-red-500/15 text-red-600 dark:text-red-400",           description: "Tenable enrichment" },
  wiz:                 { label: "WZ",   color: "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",        description: "Wiz cloud enrichment" },
  fortimanager:        { label: "FM",   color: "bg-indigo-500/15 text-indigo-600 dark:text-indigo-400",  description: "FortiManager enrichment" },
  manual:              { label: "MN",   color: "bg-muted text-muted-foreground",                         description: "Manually added" },
}

function SourceBadges({ metadata }: { metadata: Record<string, unknown> }) {
  const sources: string[] = Array.isArray(metadata.sources)
    ? (metadata.sources as string[])
    : metadata.source
      ? [metadata.source as string]
      : []

  if (!sources.length) return null

  return (
    <div className="flex flex-wrap gap-1">
      {sources.map(src => {
        const meta = SOURCE_META[src] ?? { label: src.slice(0, 2).toUpperCase(), color: "bg-muted text-muted-foreground", description: src }
        return (
          <div key={src} className="relative group">
            <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold cursor-default ${meta.color}`}>
              {meta.label}
            </span>
            {/* Hover tooltip */}
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 hidden group-hover:block z-50 pointer-events-none">
              <div className="bg-popover border rounded-md shadow-md px-2.5 py-1.5 text-xs text-popover-foreground whitespace-nowrap">
                {meta.description}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Asset type badge ──────────────────────────────────────────────────────────

const TYPE_COLOR: Record<string, string> = {
  dns_record:     "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  ip_address:     "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  open_port:      "bg-orange-500/10 text-orange-600 dark:text-orange-400",
  service:        "bg-purple-500/10 text-purple-600 dark:text-purple-400",
  cloud_resource: "bg-sky-500/10 text-sky-600 dark:text-sky-400",
  internal_host:  "bg-rose-500/10 text-rose-600 dark:text-rose-400",
}

function AssetTypeBadge({ type }: { type: string }) {
  const cls = TYPE_COLOR[type] ?? "bg-muted text-muted-foreground"
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${cls}`}>
      {type.replace("_", " ")}
    </span>
  )
}

function MetaHints({ asset }: { asset: Asset }) {
  const m = asset.asset_metadata
  const hints: string[] = []
  if (m.record_type) hints.push(String(m.record_type))
  if (m.proxied === true) hints.push("proxied")
  if (m.content && asset.asset_type === "dns_record") hints.push(String(m.content))
  if (!hints.length) return null
  return <span className="text-xs text-muted-foreground font-mono">{hints.join(" · ")}</span>
}

// ── Asset detail sheet ────────────────────────────────────────────────────────

function AssetDetailSheet({
  asset,
  onClose,
  onScan,
  onIgnore,
}: {
  asset: Asset
  onClose: () => void
  onScan: (id: string) => void
  onIgnore: (id: string, ignored: boolean) => void
}) {
  const m = asset.asset_metadata
  const sources: string[] = Array.isArray(m.sources)
    ? (m.sources as string[])
    : m.source ? [m.source as string] : []
  const metaEntries = Object.entries(m).filter(([k]) => k !== "sources" && k !== "source")

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-[480px] sm:max-w-[480px] flex flex-col gap-0 p-0">
        <SheetHeader className="px-6 pt-6 pb-4 border-b space-y-2">
          <div className="flex items-center gap-2 flex-wrap">
            <AssetTypeBadge type={asset.asset_type} />
            {asset.ignored && <span className="text-xs text-muted-foreground italic">ignored</span>}
          </div>
          <SheetTitle className="font-mono text-sm break-all leading-relaxed">{asset.value}</SheetTitle>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="space-y-0.5">
              <p className="text-muted-foreground">Parent</p>
              <p className="font-mono break-all">{asset.parent_value ?? "—"}</p>
            </div>
            <div className="space-y-0.5">
              <p className="text-muted-foreground">Discovered</p>
              <p>{new Date(asset.discovered_at).toLocaleString()}</p>
            </div>
          </div>

          {sources.length > 0 && (
            <>
              <Separator />
              <div className="space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Sources</p>
                <div className="space-y-2">
                  {sources.map(src => {
                    const meta = SOURCE_META[src] ?? { label: src.slice(0, 2).toUpperCase(), color: "bg-muted text-muted-foreground", description: src }
                    return (
                      <div key={src} className="flex items-center gap-2">
                        <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold ${meta.color}`}>{meta.label}</span>
                        <span className="text-xs text-muted-foreground">{meta.description}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            </>
          )}

          {metaEntries.length > 0 && (
            <>
              <Separator />
              <div className="space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Metadata</p>
                <div className="rounded-md border divide-y text-xs font-mono">
                  {metaEntries.map(([k, v]) => (
                    <div key={k} className="flex items-start gap-3 px-3 py-2">
                      <span className="text-muted-foreground shrink-0 w-28">{k}</span>
                      <span className="break-all text-foreground">
                        {typeof v === "boolean" ? (v ? "true" : "false") : String(v ?? "—")}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        <div className="px-6 py-4 border-t flex gap-2">
          {!asset.ignored && (
            <Button size="sm" variant="outline" onClick={() => { onScan(asset.id); onClose() }}>
              <ScanLine className="h-3.5 w-3.5 mr-1.5" />Scan
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

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Assets() {
  const [searchParams] = useSearchParams()
  const qc = useQueryClient()
  const [search, setSearch] = useState("")
  const [typeFilter, setTypeFilter] = useState("all")
  const [scanFilter, setScanFilter] = useState(searchParams.get("scan") ?? "all")
  const [showIgnored, setShowIgnored] = useState(false)

  const { data: scans } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<ScanRun[]>("/scans/"),
  })

  const { data: assets, isLoading } = useQuery({
    queryKey: ["assets", scanFilter, showIgnored],
    queryFn: () => {
      const params = new URLSearchParams()
      if (scanFilter !== "all") params.set("scan_id", scanFilter)
      if (showIgnored) params.set("show_ignored", "true")
      return api.get<Asset[]>(`/assets/?${params}`)
    },
  })

  const scanMutation = useMutation({
    mutationFn: (assetId: string) => api.post(`/assets/${assetId}/scan`),
    onSuccess: () => { toast.success("On-demand scan queued"); qc.invalidateQueries({ queryKey: ["scans"] }) },
    onError: () => toast.error("Failed to start scan"),
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

  const deleteMutation = useMutation({
    mutationFn: (assetId: string) => api.delete(`/assets/${assetId}`),
    onSuccess: () => { toast.success("Asset deleted"); qc.invalidateQueries({ queryKey: ["assets"] }) },
    onError: () => toast.error("Failed to delete asset"),
  })

  const filtered = (assets ?? []).filter(a => {
    if (typeFilter !== "all" && a.asset_type !== typeFilter) return false
    if (search && !a.value.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  const types = [...new Set((assets ?? []).map(a => a.asset_type))].sort()

  const { selected: selectedAsset, open: openAsset, close: closeAsset } = useFlyout(filtered)

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Assets</h1>
        <p className="text-sm text-muted-foreground mt-1">Discovered public-facing assets and their correlation chain</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48 max-w-sm">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            className="pl-8 h-9 text-sm"
            placeholder="Filter by value..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <Select value={scanFilter} onValueChange={setScanFilter}>
          <SelectTrigger className="w-52 h-9 text-sm"><SelectValue placeholder="All scans" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All scans</SelectItem>
            {scans?.map(s => (
              <SelectItem key={s.id} value={s.id}>
                {s.name ?? s.scope.domains.slice(0, 2).join(", ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-40 h-9 text-sm"><SelectValue placeholder="All types" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {types.map(t => <SelectItem key={t} value={t}>{t.replace("_", " ")}</SelectItem>)}
          </SelectContent>
        </Select>

        <Button
          variant={showIgnored ? "secondary" : "outline"}
          size="sm"
          className="h-9 gap-1.5"
          onClick={() => setShowIgnored(v => !v)}
          title={showIgnored ? "Hide ignored assets" : "Show ignored assets"}
        >
          {showIgnored ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
          {showIgnored ? "Showing ignored" : "Show ignored"}
        </Button>

        <span className="text-xs text-muted-foreground ml-auto">{filtered.length} asset{filtered.length !== 1 ? "s" : ""}</span>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <Globe className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">{assets?.length === 0 ? "No assets discovered" : "No results"}</p>
          <p className="text-sm mt-1">{assets?.length === 0 ? "Run a scan to populate the asset inventory." : "Try adjusting your filters."}</p>
        </div>
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-32">Type</TableHead>
                <TableHead>Value</TableHead>
                <TableHead className="hidden md:table-cell">Parent</TableHead>
                <TableHead className="hidden lg:table-cell">Details</TableHead>
                <TableHead className="w-32">Sources</TableHead>
                <TableHead className="hidden xl:table-cell">Discovered</TableHead>
                <TableHead className="w-24" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(asset => (
                <TableRow
                  key={`${asset.id}-${asset.discovered_at}`}
                  className={`cursor-pointer ${asset.ignored ? "opacity-50" : ""}`}
                  onClick={() => openAsset(asset)}
                >
                  <TableCell><AssetTypeBadge type={asset.asset_type} /></TableCell>
                  <TableCell className="font-mono text-sm">{asset.value}</TableCell>
                  <TableCell className="hidden md:table-cell font-mono text-xs text-muted-foreground">{asset.parent_value ?? "—"}</TableCell>
                  <TableCell className="hidden lg:table-cell"><MetaHints asset={asset} /></TableCell>
                  <TableCell><SourceBadges metadata={asset.asset_metadata} /></TableCell>
                  <TableCell className="hidden xl:table-cell text-xs text-muted-foreground">{new Date(asset.discovered_at).toLocaleString()}</TableCell>
                  <TableCell onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-1">
                      {!asset.ignored && (
                        <Button variant="ghost" size="sm" onClick={() => scanMutation.mutate(asset.id)} disabled={scanMutation.isPending} title="On-demand scan">
                          <ScanLine className="h-3.5 w-3.5" />
                        </Button>
                      )}
                      <Button
                        variant="ghost" size="sm"
                        onClick={() => ignoreMutation.mutate({ assetId: asset.id, ignored: !asset.ignored })}
                        disabled={ignoreMutation.isPending}
                        title={asset.ignored ? "Restore asset" : "Ignore asset"}
                        className={asset.ignored ? "text-muted-foreground" : undefined}
                      >
                        {asset.ignored ? <Eye className="h-3.5 w-3.5" /> : <EyeOff className="h-3.5 w-3.5" />}
                      </Button>
                      <Button
                        variant="ghost" size="sm"
                        onClick={() => { if (confirm(`Delete ${asset.value}?`)) deleteMutation.mutate(asset.id) }}
                        disabled={deleteMutation.isPending}
                        title="Delete"
                        className="text-destructive hover:text-destructive"
                      >
                        {deleteMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {selectedAsset && (
        <AssetDetailSheet
          asset={selectedAsset}
          onClose={closeAsset}
          onScan={(id) => scanMutation.mutate(id)}
          onIgnore={(id, ignored) => ignoreMutation.mutate({ assetId: id, ignored })}
        />
      )}
    </div>
  )
}
