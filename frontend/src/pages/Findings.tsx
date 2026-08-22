import { useState, useEffect, useMemo, type ReactNode } from "react"
import { Link } from "react-router-dom"
import { useFlyout } from "@/lib/flyout"
import { useUrlState, useUrlFlag, useListView, useDebouncedUrlState } from "@/lib/listView"
import { ViewToggle, GroupBySelect } from "@/components/ListControls"
import { FindingCard } from "@/components/FindingCard"
import { AssetRiskCard } from "@/components/AssetRiskCard"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  AlertTriangle, Filter, Loader2, ShieldCheck, ShieldOff,
  RefreshCw, ChevronDown, ChevronRight, Clock, SquareArrowOutUpRight, Sparkles, X,
} from "lucide-react"
import { EpssRowCompact, EpssSparklineSection } from "@/components/EpssHistory"
import { ConnectedEntities } from "@/components/ConnectedEntities"
import { FindingActionsMenu } from "@/components/FindingActionsMenu"
import { VulnNarrative, VulnIntel, hasVulnIntel } from "@/components/VulnNarrative"
import { WorkspaceShell, type TabDef } from "@/components/WorkspaceShell"
import { IndeterminateCheckbox } from "@/components/ui/indeterminate-checkbox"
import { OverflowCell } from "@/components/ui/overflow-cell"
import { relativeTime, isStale, daysSince } from "@/lib/time"
import { displayName } from "@/lib/apex"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { TagBadge } from "@/components/ui/tag-badge"
import { TagEditor } from "@/components/ui/tag-editor"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { api, ApiError, type Finding, type Asset } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { canMutate } from "@/lib/roles"
import {
  SeverityBadge,
  CategoryBadge, CATEGORY_LABEL,
  StateBadge, cvssColor, EnrichmentBadges,
  RiskBandBadge, BuildingVelocityBadge, ImpactClassBadge, SsvcEvidence, ExploitTypeBadges,
  ExposureOverrideBadge, ExposureClassBadge, DetectionLayerBadge, BodSlaBadge,
  VerificationBadge, VerificationEvidencePanel,
  SourceBadges, UpstreamEvidence, findingSources, findingPort, sourceLabel,
  RISK_BAND_COLOR, RISK_BAND_SHORT, RISK_BAND_LABEL, RISK_BAND_ORDER, effectiveBand,
  IMPACT_CLASS_LABEL,
  findingTitle,
} from "@/components/finding-badges"

const NEW_FINDING_DAYS = 7

// Epic#81 Phase D — the one curated "Ownership Unverifiable" saved view.
// A sentinel activeTab value, NOT a category: per the locked IA rule
// (sub-tabs are entity types OR saved views, never attribute pivots),
// this must stay a single named view, not an enumeration of `verification`
// values as parallel tabs. Its findings are excluded from the default
// /findings/ response by design, so it needs its own query, not a
// client-side filter over the already-loaded (already-excluding) list.
const OWNERSHIP_UNVERIFIABLE_TAB_KEY = "__ownership_unverifiable"

// Impact-class grouping order (worst-ish consequence first); "__none" buckets
// findings with no impact class (non-CVE / no vector).
const IMPACT_GROUP_ORDER = ["rce", "data_exposure", "tampering", "denial_of_service", "other", "__none"]

function isNew(f: Finding): boolean {
  return (Date.now() - new Date(f.first_seen_at).getTime()) < NEW_FINDING_DAYS * 86_400_000
}

// Parses a `?since=Nd` spec (e.g. "7d") into a first-seen recency predicate.
// Unrecognised specs match everything (fail-open), so a bad URL never hides data.
function withinSince(iso: string, spec: string): boolean {
  const m = /^(\d+)d$/.exec(spec)
  if (!m) return true
  return (Date.now() - new Date(iso).getTime()) < Number(m[1]) * 86_400_000
}

// ── Tab definitions ───────────────────────────────────────────────────────────

function buildTabs(findings: Finding[] | undefined): TabDef[] {
  const counts: Record<string, number> = { all: 0 }
  for (const f of findings ?? []) {
    counts.all++
    if (f.category) counts[f.category] = (counts[f.category] ?? 0) + 1
  }
  const categoryTabs = Object.keys(counts)
    .filter(k => k !== "all" && counts[k] > 0)
    .sort((a, b) => counts[b] - counts[a]) // highest count first
    .map(k => ({ key: k, label: CATEGORY_LABEL[k] ?? k, count: counts[k] }))
  return [{ key: "all", label: "All", count: counts.all }, ...categoryTabs]
}

// ── Finding flyout helpers ────────────────────────────────────────────────────

const FLY_TRIGGER = "h-9 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-foreground text-muted-foreground text-xs font-medium px-3 transition-none"

const SEV_BORDER_CLS: Record<string, string> = {
  critical: "border-t-red-500",
  high:     "border-t-orange-500",
  medium:   "border-t-amber-500",
  low:      "border-t-blue-500",
  info:     "border-t-border",
}

// Cross-link an ownership_unverifiable/rejected finding to its sibling
// dangling_dns finding on the same origin IP (epic#81 Phase D) — the two
// findings are the two faces of the same origin condition (attribution vs.
// takeover-risk), so "why" should never be a dead end here. Small, targeted
// fetch (finding_type filter) rather than loading every finding to search
// client-side — dangling_dns findings are rare by design.
function DanglingDnsSiblingLink({ finding }: { finding: Finding }) {
  const originIp = finding.verification_evidence?.ip
  const { data: danglingFindings } = useQuery({
    queryKey: ["findings", "dangling_dns_siblings"],
    queryFn: () => api.get<Finding[]>("/findings/?finding_type=dangling_dns"),
    enabled: !!originIp,
  })
  if (!originIp) return null
  const sibling = danglingFindings?.find(f => (f.detail as Record<string, unknown> | null)?.origin_ip === originIp)
  if (!sibling) return null
  return (
    <Link
      to={`/findings/${sibling.id}`}
      className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-opacity"
      title="This origin also has a dangling-DNS finding"
    >
      <SquareArrowOutUpRight className="h-3 w-3" />
      Related dangling-DNS finding on this origin
    </Link>
  )
}

// ── Finding detail flyout ─────────────────────────────────────────────────────

function FindingDetailSheet({
  finding, onClose, onStateChange, onSuppress, onVerify,
}: {
  finding: Finding
  onClose: () => void
  onStateChange: (id: string, state: string) => void
  onSuppress: (f: Finding) => void
  onVerify: (id: string) => void
}) {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const mutable = canMutate(user?.role)
  const tagMutation = useMutation({
    mutationFn: (tags: string[]) => api.patch(`/tags/findings/${finding.id}`, { tags }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
    onError: () => toast.error("Failed to update tags"),
  })

  const detail = finding.detail ?? {}
  const tags: string[] = (detail.tags as string[]) ?? []
  const extracted: string[] = (detail.extracted_results as string[]) ?? []
  const matchedAt = detail.matched_at as string | undefined
  const curlCmd = detail.curl_command as string | undefined
  const hasEnrichment = finding.kev || finding.cvss_score != null || finding.epss_score != null || finding.cve_id || finding.cwe
  const borderCls = SEV_BORDER_CLS[finding.severity] ?? "border-t-border"

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className={`w-[540px] sm:max-w-[540px] flex flex-col gap-0 p-0 border-t-2 ${borderCls}`}>
        <SheetHeader className="px-6 pt-5 pb-3 border-b space-y-1.5 shrink-0">
          <ImpactClassBadge finding={finding} />
          <div className="flex items-center gap-2 flex-wrap">
            {finding.risk_band
              ? <Link to={`/findings?band=${finding.risk_band}`} className="hover:opacity-80 transition-opacity" title="Show findings in this risk band"><RiskBandBadge band={finding.risk_band} score={finding.risk_score} /></Link>
              : <SeverityBadge severity={finding.severity} />}
            <BuildingVelocityBadge active={finding.building_velocity} />
            <BodSlaBadge finding={finding} />
            {finding.category && (
              <Link to={`/findings?category=${encodeURIComponent(finding.category)}`} className="hover:opacity-80 transition-opacity" title="Show findings in this category">
                <CategoryBadge category={finding.category} />
              </Link>
            )}
            <ExposureClassBadge finding={finding} />
            <DetectionLayerBadge finding={finding} />
            <VerificationBadge finding={finding} />
            <ExploitTypeBadges types={finding.exploit_types} impactClass={finding.impact_class} />
            <ExposureOverrideBadge finding={finding} />
            <StateBadge state={finding.state} />
            <SourceBadges finding={finding} />
            <Link to={`/findings/${finding.id}`} className="ml-auto mr-6 text-muted-foreground hover:text-foreground" title="Open full finding view">
              <SquareArrowOutUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>
          <SheetTitle className="text-base leading-snug">{finding.title}</SheetTitle>
          <SheetDescription className="font-mono text-xs break-all">{displayName(finding.asset_value)}</SheetDescription>
        </SheetHeader>

        <Tabs defaultValue="overview" className="flex-1 flex flex-col min-h-0">
          <div className="border-b shrink-0 px-2 overflow-x-auto">
            <TabsList className="h-auto w-full justify-start gap-0 bg-transparent rounded-none p-0">
              <TabsTrigger value="overview"      className={FLY_TRIGGER}>Overview</TabsTrigger>
              {hasVulnIntel(finding) && <TabsTrigger value="intel" className={FLY_TRIGGER}>Intel</TabsTrigger>}
              <TabsTrigger value="asset"         className={FLY_TRIGGER}>Asset</TabsTrigger>
              <TabsTrigger value="relationships" className={FLY_TRIGGER}>Relationships</TabsTrigger>
              <TabsTrigger value="timeline"      className={FLY_TRIGGER}>Timeline</TabsTrigger>
              <TabsTrigger value="raw"           className={FLY_TRIGGER}>Raw</TabsTrigger>
            </TabsList>
          </div>

          <div className="flex-1 overflow-y-auto">

            {/* ── Overview ── */}
            <TabsContent value="overview" className="m-0">
              <div className="px-6 py-5 space-y-5">
                {/* About this vulnerability — what is it / what to do / proof */}
                <VulnNarrative finding={finding} />

                {/* Provenance — what produced this finding + the upstream evidence */}
                <UpstreamEvidence finding={finding} />

                {/* Shared-infra verification evidence (epic#81 Phases A/D) —
                    only renders for rejected/ownership_unverifiable findings */}
                <VerificationEvidencePanel finding={finding} />
                <DanglingDnsSiblingLink finding={finding} />

                {hasEnrichment && (
                  <div className="rounded-md border p-4 space-y-2.5">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Enrichment</p>
                    {finding.cve_id && (
                      <div className="flex items-center gap-3 text-sm">
                        <span className="text-xs text-muted-foreground w-20 shrink-0">CVE</span>
                        <span className="font-mono">{finding.cve_id}</span>
                      </div>
                    )}
                    {finding.cvss_score != null && (
                      <div className="flex items-start gap-3 text-sm">
                        <span className="text-xs text-muted-foreground w-20 shrink-0">CVSS</span>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-mono ${cvssColor(finding.cvss_score)}`}>
                            {finding.cvss_version && <span className="opacity-60 mr-1">v{finding.cvss_version}</span>}
                            {finding.cvss_score.toFixed(1)}
                          </span>
                          {finding.cvss_vector && <span className="text-xs text-muted-foreground font-mono break-all">{finding.cvss_vector}</span>}
                        </div>
                      </div>
                    )}
                    {(finding.cve_id || finding.epss_score != null) && (
                      <EpssRowCompact
                        findingId={finding.id}
                        fallbackScore={finding.epss_score}
                        fallbackPercentile={finding.epss_percentile}
                      />
                    )}
                    {finding.kev && (
                      <div className="flex items-center gap-3 text-sm">
                        <span className="text-xs text-muted-foreground w-20 shrink-0">KEV</span>
                        <Link to="/findings?kev=true" className="hover:opacity-80 transition-opacity" title="Show all KEV findings">
                          <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-bold bg-red-500 text-white border-red-600">KEV</span>
                        </Link>
                        {finding.kev_date_added && <span className="text-xs text-muted-foreground">Added {finding.kev_date_added}</span>}
                      </div>
                    )}
                    {finding.cwe && (
                      <div className="flex items-center gap-3 text-sm">
                        <span className="text-xs text-muted-foreground w-20 shrink-0">CWE</span>
                        <span className="font-mono text-xs">{finding.cwe}</span>
                      </div>
                    )}
                  </div>
                )}

                <SsvcEvidence finding={finding} />

                {finding.cve_id && (
                  <EpssSparklineSection findingId={finding.id} compact />
                )}

                {matchedAt && (
                  <div className="space-y-1.5">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Matched URL</p>
                    <p className="text-xs font-mono break-all bg-muted rounded px-3 py-2">{matchedAt}</p>
                  </div>
                )}

                {extracted.length > 0 && (
                  <div className="space-y-1.5">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Extracted</p>
                    <div className="space-y-1">
                      {extracted.map((r, i) => <p key={i} className="text-xs font-mono bg-muted rounded px-3 py-1.5 break-all">{r}</p>)}
                    </div>
                  </div>
                )}

                {curlCmd && (
                  <div className="space-y-1.5">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Curl command</p>
                    <pre className="text-xs font-mono bg-muted/60 rounded p-3 overflow-x-auto whitespace-pre-wrap break-all">{curlCmd}</pre>
                  </div>
                )}

                {tags.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Scanner tags</p>
                    <div className="flex flex-wrap gap-1">
                      {tags.map(tag => (
                        <span key={tag} className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-xs font-mono text-muted-foreground">{tag}</span>
                      ))}
                    </div>
                  </div>
                )}

                <Separator />
                <div className="space-y-2">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Tags</p>
                  <TagEditor tags={finding.tags ?? []} entityType="finding" onChange={t => tagMutation.mutate(t)} />
                </div>
              </div>
            </TabsContent>

            {/* ── Intel — exploit & reference links ── */}
            <TabsContent value="intel" className="m-0">
              <div className="px-6 py-5">
                <VulnIntel finding={finding} />
              </div>
            </TabsContent>

            {/* ── Asset ── */}
            <TabsContent value="asset" className="m-0">
              <div className="px-6 py-5 space-y-4">
                <Link
                  to={`/assets/${finding.asset_canonical_id}`}
                  className="flex items-center gap-3 rounded-md border p-3 hover:bg-muted/50 transition-colors"
                >
                  <div className="flex-1 min-w-0 space-y-0.5">
                    <p className="font-mono text-sm break-all">{displayName(finding.asset_value)}</p>
                    {finding.asset_parent_value && (
                      <p className="text-xs text-muted-foreground font-mono break-all">{displayName(finding.asset_parent_value)}</p>
                    )}
                  </div>
                  <SquareArrowOutUpRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                </Link>
                <div className="text-xs text-muted-foreground space-y-1">
                  <p>Source: <span className="text-foreground capitalize">{finding.source}</span></p>
                  <p className="break-all">Fingerprint: <span className="text-foreground font-mono">{finding.fingerprint}</span></p>
                </div>
              </div>
            </TabsContent>

            {/* ── Relationships ── */}
            <TabsContent value="relationships" className="m-0">
              <div className="px-6 py-5">
                <ConnectedEntities nodeType="finding_canonical" nodeId={finding.id} />
              </div>
            </TabsContent>

            {/* ── Timeline ── */}
            <TabsContent value="timeline" className="m-0">
              <div className="px-6 py-5">
                {[
                  { date: finding.first_seen_at, label: "First seen" },
                  finding.acknowledged_at ? { date: finding.acknowledged_at, label: "Acknowledged" } : null,
                  finding.suppressed_until ? { date: finding.suppressed_until, label: "Suppressed until" } : null,
                  finding.resolved_at ? { date: finding.resolved_at, label: "Resolved" } : null,
                  finding.last_seen_at !== finding.first_seen_at
                    ? { date: finding.last_seen_at, label: "Last seen" }
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
                  {JSON.stringify(finding.detail, null, 2)}
                </pre>
              </div>
            </TabsContent>
          </div>
        </Tabs>

        {mutable && (
          <div className="px-6 py-4 border-t flex flex-wrap gap-2 shrink-0">
            {finding.state === "open" && (
              <>
                <Button size="sm" variant="outline" onClick={() => onStateChange(finding.id, "acknowledged")}>
                  <ShieldCheck className="h-3.5 w-3.5 mr-1.5" />Acknowledge
                </Button>
                <Button size="sm" variant="outline" onClick={() => { onClose(); onSuppress(finding) }}>
                  <ShieldOff className="h-3.5 w-3.5 mr-1.5" />Suppress
                </Button>
              </>
            )}
            {(finding.state === "open" || finding.state === "acknowledged") && (
              <Button size="sm" variant="outline" onClick={() => onVerify(finding.id)}>
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" />Re-verify
              </Button>
            )}
            {finding.state === "suppressed" && (
              <Button size="sm" variant="outline" onClick={() => onStateChange(finding.id, "open")}>
                <ChevronDown className="h-3.5 w-3.5 mr-1.5 rotate-180" />Reopen
              </Button>
            )}
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}

// ── Suppress dialogs ──────────────────────────────────────────────────────────

const SUPPRESS_OPTIONS = [
  { label: "7 days",  days: 7 },
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "1 year",  days: 365 },
]

function SuppressDialog({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const qc = useQueryClient()
  const [days, setDays] = useState("30")
  const mutation = useMutation({
    mutationFn: () => {
      const until = new Date()
      until.setDate(until.getDate() + parseInt(days))
      return api.patch(`/findings/${finding.id}/state`, { state: "suppressed", suppressed_until: until.toISOString() })
    },
    onSuccess: () => { toast.success("Finding suppressed"); qc.invalidateQueries({ queryKey: ["findings"] }); onClose() },
    onError: () => toast.error("Failed to suppress finding"),
  })
  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader><DialogTitle>Suppress Finding</DialogTitle></DialogHeader>
        <div className="space-y-3 py-2">
          <p className="text-sm text-muted-foreground font-mono truncate">{finding.title}</p>
          <Select value={days} onValueChange={setDays}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{SUPPRESS_OPTIONS.map(o => <SelectItem key={o.days} value={String(o.days)}>{o.label}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={mutation.isPending} onClick={() => mutation.mutate()}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}Suppress
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function BulkSuppressDialog({ count, onConfirm, onClose }: { count: number; onConfirm: (days: number) => void; onClose: () => void }) {
  const [days, setDays] = useState("30")
  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader><DialogTitle>Suppress {count} Finding{count !== 1 ? "s" : ""}</DialogTitle></DialogHeader>
        <div className="space-y-3 py-2">
          <p className="text-sm text-muted-foreground">Suppress all {count} selected findings for:</p>
          <Select value={days} onValueChange={setDays}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{SUPPRESS_OPTIONS.map(o => <SelectItem key={o.days} value={String(o.days)}>{o.label}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => onConfirm(parseInt(days))}>Suppress</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Findings() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const mutable = canMutate(user?.role)
  // All filters are URL-backed — single source of truth, every view is a shareable
  // deep link, and inbound links (dashboard chips, asset-card band pills) and the
  // in-page controls can't drift out of sync.
  const [activeTab, setActiveTab]         = useUrlState("category", "all")
  const [search, setSearch]               = useDebouncedUrlState("q", "")
  const [bandFilter, setBandFilter]       = useUrlState("band", "all")
  const [tagFilter, setTagFilter]         = useUrlState("tag", "all")
  const [sourceFilter, setSourceFilter]   = useUrlState("source", "all")
  const [portFilter, setPortFilter]       = useUrlState("port", "all")
  const [stateFilter, setStateFilter]     = useUrlState("state", "open")
  const [assetFilter, setAssetFilter]     = useUrlState("asset", "")
  const [sinceFilter, setSinceFilter]     = useUrlState("since", "")
  const [kevFilter, setKevFilter]         = useUrlFlag("kev")
  const [exploitFilter, setExploitFilter] = useUrlFlag("exploit")
  const [impactClassFilter, setImpactClassFilter] = useUrlState("impact_class", "all")
  const [automatableFilter, setAutomatableFilter] = useUrlFlag("automatable")
  const [techImpactFilter, setTechImpactFilter]   = useUrlState("tech_impact", "all")
  const [bodFilter, setBodFilter]                 = useUrlState("bod", "all")
  const [suppressTarget, setSuppressTarget] = useState<Finding | null>(null)
  const [selectedIds, setSelectedIds]       = useState(new Set<string>())
  const [bulkSuppressOpen, setBulkSuppressOpen] = useState(false)
  const { view, setView, group, setGroup } = useListView()
  const [collapsedGroups, setCollapsedGroups] = useState(new Set<string>())
  const toggleGroup = (key: string) =>
    setCollapsedGroups(prev => { const next = new Set(prev); next.has(key) ? next.delete(key) : next.add(key); return next })

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings", stateFilter],
    queryFn: () => {
      const params = new URLSearchParams()
      if (stateFilter !== "all") params.set("state", stateFilter)
      return api.get<Finding[]>(`/findings/?${params}`)
    },
  })

  // Epic#81 Phase D saved view — separate query, since these are excluded
  // from the default list above by design (see OWNERSHIP_UNVERIFIABLE_TAB_KEY).
  // Fetched unconditionally (not gated on the tab being active) so the tab
  // itself can show a live count — cheap, since this population is narrow
  // by construction (shared_infra_verifier's own gate keeps it small).
  const { data: ownershipUnverifiableFindings } = useQuery({
    queryKey: ["findings", "ownership_unverifiable"],
    queryFn: () => api.get<Finding[]>("/findings/?verification=ownership_unverifiable"),
  })

  // Assets back the group-by-asset card view (rich AssetRiskCard per asset).
  const { data: assets } = useQuery({
    queryKey: ["assets-list"],
    queryFn: () => api.get<Asset[]>("/assets/"),
    enabled: group === "asset",
  })

  const stateMutation = useMutation({
    mutationFn: ({ id, state }: { id: string; state: string }) =>
      api.patch(`/findings/${id}/state`, { state }),
    onSuccess: (_, { state }) => {
      toast.success(state === "acknowledged" ? "Finding acknowledged" : "Finding resolved")
      qc.invalidateQueries({ queryKey: ["findings"] })
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Failed to update finding"),
  })

  const verifyMutation = useMutation({
    mutationFn: (id: string) => api.post(`/findings/${id}/verify`),
    onSuccess: () => toast.success("Verification scan queued"),
    onError: () => toast.error("Failed to queue verification"),
  })

  const bulkStateMutation = useMutation({
    mutationFn: ({ state, suppressedUntil }: { state: string; suppressedUntil?: string }) =>
      api.post<{ updated: number }>("/findings/bulk/state", {
        finding_ids: [...selectedIds],
        state,
        ...(suppressedUntil ? { suppressed_until: suppressedUntil } : {}),
      }),
    onSuccess: (data, { state }) => {
      const n = data.updated
      const verb = state === "acknowledged" ? "acknowledged" : state === "suppressed" ? "suppressed" : "reopened"
      toast.success(`${n} finding${n !== 1 ? "s" : ""} ${verb}`)
      setSelectedIds(new Set())
      qc.invalidateQueries({ queryKey: ["findings"] })
    },
    onError: (err) => toast.error(err instanceof ApiError ? err.message : "Bulk action failed"),
  })

  // Tab drives category filter; band + kev/exploit + tag + search layer on top.
  // The Ownership Unverifiable tab is a saved view, not a category — it swaps
  // the SOURCE list entirely (its own query, excluded from `findings` by
  // design) and skips the category check, since these findings aren't
  // being filtered by category, they're a different population altogether.
  // Memoized so a keystroke only re-filters — it doesn't also re-derive tabs/counts/tags below.
  const isOwnershipUnverifiableView = activeTab === OWNERSHIP_UNVERIFIABLE_TAB_KEY
  const filtered = useMemo(() => (isOwnershipUnverifiableView ? (ownershipUnverifiableFindings ?? []) : (findings ?? [])).filter(f => {
    if (!isOwnershipUnverifiableView && activeTab !== "all" && f.category !== activeTab) return false
    if (bandFilter !== "all" && effectiveBand(f) !== bandFilter) return false
    if (assetFilter && f.asset_value !== assetFilter) return false
    if (sinceFilter && !withinSince(f.first_seen_at, sinceFilter)) return false
    if (kevFilter && !(f.kev || f.vulncheck_kev)) return false
    if (exploitFilter && !f.has_exploit) return false
    if (tagFilter !== "all" && !(f.tags ?? []).includes(tagFilter)) return false
    if (sourceFilter !== "all" && !findingSources(f).includes(sourceFilter)) return false
    if (portFilter !== "all" && String(findingPort(f) ?? "") !== portFilter) return false
    if (impactClassFilter !== "all" && f.impact_class !== impactClassFilter) return false
    if (automatableFilter && f.ssvc_automatable !== true) return false
    if (techImpactFilter !== "all" && f.ssvc_technical_impact !== techImpactFilter) return false
    if (bodFilter !== "all" && f.bod_sla?.window !== bodFilter) return false
    if (search) {
      const q = search.toLowerCase()
      // Match across identity, enrichment, and SSVC so typing a CVE id, CWE,
      // "automatable", "total", or an impact word finds the right findings.
      const hay = [
        f.title, f.asset_value, displayName(f.asset_value), f.asset_parent_value ?? "",
        f.cve_id ?? "", f.cwe ?? "", f.description ?? "",
        f.impact_class ? IMPACT_CLASS_LABEL[f.impact_class] : "",
        f.ssvc_technical_impact ?? "", f.ssvc_exploitation ?? "",
        f.ssvc_automatable === true ? "automatable" : "",
        f.bod_sla?.window ?? "",
        ...findingSources(f), ...findingSources(f).map(sourceLabel),
        String(findingPort(f) ?? ""),
        ...(f.tags ?? []),
      ].join(" ").toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  }), [findings, ownershipUnverifiableFindings, isOwnershipUnverifiableView, activeTab, bandFilter, assetFilter, sinceFilter, kevFilter, exploitFilter, tagFilter, sourceFilter, portFilter, impactClassFilter, automatableFilter, techImpactFilter, bodFilter, search])

  useEffect(() => {
    setSelectedIds(new Set())
  }, [activeTab, stateFilter, bandFilter, kevFilter, exploitFilter, tagFilter, sourceFilter, portFilter, impactClassFilter, automatableFilter, techImpactFilter, bodFilter, search, assetFilter, sinceFilter])

  const allFilteredSelected = filtered.length > 0 && filtered.every(f => selectedIds.has(f.id))
  const someFilteredSelected = filtered.some(f => selectedIds.has(f.id))

  function toggleAll(checked: boolean) {
    setSelectedIds(checked ? new Set(filtered.map(f => f.id)) : new Set())
  }
  function toggleOne(id: string, checked: boolean) {
    setSelectedIds(prev => { const next = new Set(prev); if (checked) next.add(id); else next.delete(id); return next })
  }

  // These only depend on the unfiltered findings set, so they're memoized
  // separately from `filtered` — a search keystroke shouldn't re-derive them.
  const availableTags = useMemo(
    () => [...new Set((findings ?? []).flatMap(f => f.tags ?? []))].sort(),
    [findings],
  )
  // Provenance facets (#71): distinct sources + ports present in the loaded set.
  // Always fold in the active filter value so a deep-linked source/port absent
  // from the current (state-filtered) data is still visible and clearable.
  const availableSources = useMemo(() => {
    const set = new Set((findings ?? []).flatMap(findingSources))
    if (sourceFilter !== "all") set.add(sourceFilter)
    return [...set].sort()
  }, [findings, sourceFilter])
  const availablePorts = useMemo(() => {
    const set = new Set((findings ?? []).map(findingPort).filter((p): p is number => p != null))
    if (portFilter !== "all" && /^\d+$/.test(portFilter)) set.add(Number(portFilter))
    return [...set].sort((a, b) => a - b)
  }, [findings, portFilter])
  // Counts by Risk Score verdict band (the primary axis), not raw CVSS severity.
  const counts = useMemo(() => RISK_BAND_ORDER.reduce<Record<string, number>>((acc, b) => {
    acc[b] = (findings ?? []).filter(f => effectiveBand(f) === b).length
    return acc
  }, {}), [findings])

  const tabs = useMemo(() => [
    ...buildTabs(findings),
    { key: OWNERSHIP_UNVERIFIABLE_TAB_KEY, label: "Ownership Unverifiable", count: ownershipUnverifiableFindings?.length ?? 0 },
  ], [findings, ownershipUnverifiableFindings])
  const { selected: selectedFinding, open: openFinding, close: closeFinding } = useFlyout(filtered)

  // ── Grouping (client-side view transform over the filtered list) ──────────────
  type Group = { key: string; label: string; items: Finding[] }
  const worstBandIndex = (items: Finding[]) =>
    Math.min(...items.map(f => RISK_BAND_ORDER.indexOf(effectiveBand(f))).filter(i => i >= 0))
  const groups: Group[] =
    group === "band"
      ? RISK_BAND_ORDER
          .map(b => ({ key: b, label: RISK_BAND_LABEL[b], items: filtered.filter(f => effectiveBand(f) === b) }))
          .filter(g => g.items.length > 0)
      : group === "asset"
      ? [...filtered.reduce((m, f) => {
          const arr = m.get(f.asset_canonical_id) ?? []
          arr.push(f)
          return m.set(f.asset_canonical_id, arr)
        }, new Map<string, Finding[]>())]
          .map(([key, items]) => ({ key, label: displayName(items[0].asset_value), items }))
          .sort((a, b) => worstBandIndex(a.items) - worstBandIndex(b.items) || b.items.length - a.items.length)
      : group === "impact"
      ? IMPACT_GROUP_ORDER
          .map(k => ({
            key: k,
            label: k === "__none" ? "No impact class" : (IMPACT_CLASS_LABEL[k as keyof typeof IMPACT_CLASS_LABEL] ?? k),
            items: filtered.filter(f => (f.impact_class ?? "__none") === k),
          }))
          .filter(g => g.items.length > 0)
      : []

  // "See all findings for this asset" — flat card view scoped to the asset,
  // preserving the open/resolved scope but dropping band/category. Real Link
  // (push nav) so back returns to the grouped view.
  const assetScopeHref = (items: Finding[]) => {
    const p = new URLSearchParams({ asset: items[0].asset_value, view: "card" })
    if (stateFilter !== "open") p.set("state", stateFilter)
    return `/findings?${p}`
  }

  const assetMap = new Map((assets ?? []).map(a => [a.id, a]))
  // A real Asset when we have one, else a minimal synthetic so the card renders uniformly.
  const assetForGroup = (g: Group): Asset =>
    assetMap.get(g.key) ?? {
      id: g.key,
      asset_type: "asset",
      value: g.items[0].asset_value,
      parent_value: g.items[0].asset_parent_value,
      asset_metadata: {},
      first_seen_at: g.items[0].first_seen_at,
      last_seen_at: g.items[0].last_seen_at,
      ignored: false,
      tags: [],
      worst_severity: null,
      risk_band: RISK_BAND_ORDER[worstBandIndex(g.items)] ?? null,
      risk_score: g.items[0].risk_score,
      // Synthetic fallback — this group has no matching real asset row, so
      // there's nothing to report on any of these axes. "unknown" (not
      // "not_ours") since we genuinely don't know the estate here; hygiene
      // is unscored (null, never 0 — see AssetHygieneCard); scanned is
      // conservatively false rather than guessed from Finding presence.
      surface: "unknown",
      hygiene_score: null,
      hygiene_band: null,
      scanned: false,
    }

  // ── Risk verdict pills (header primary action) ───────────────────────────────

  const severityPills = findings && findings.length > 0 ? (
    <div className="flex items-center gap-1.5 flex-wrap">
      {bandFilter !== "all" && (
        <button
          onClick={() => setBandFilter("all")}
          className="rounded border px-2 py-0.5 text-xs font-semibold text-muted-foreground border-border hover:text-foreground transition-colors"
        >
          All
        </button>
      )}
      {RISK_BAND_ORDER.filter(b => counts[b] > 0).map(b => {
        const isActive = bandFilter === b
        return (
          <button key={b}
            onClick={() => setBandFilter(isActive ? "all" : b)}
            className={`rounded border px-2 py-0.5 text-xs font-semibold transition-all ${RISK_BAND_COLOR[b]} ${bandFilter !== "all" && !isActive ? "opacity-30" : ""} ${isActive ? "ring-2 ring-offset-1 ring-offset-background ring-current" : ""}`}>
            {counts[b]} {RISK_BAND_SHORT[b]}
          </button>
        )
      })}
    </div>
  ) : undefined

  // ── Toolbar ───────────────────────────────────────────────────────────────────

  const toolbar = (
    <>
      <div className="relative flex-1 min-w-48 max-w-sm">
        <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
        <Input className="pl-8 h-9 text-sm" placeholder="Search title or asset…"
          value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      <Select value={stateFilter} onValueChange={setStateFilter}>
        <SelectTrigger className="w-36 h-9 text-sm"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All states</SelectItem>
          <SelectItem value="open">Open</SelectItem>
          <SelectItem value="acknowledged">Acknowledged</SelectItem>
          <SelectItem value="suppressed">Suppressed</SelectItem>
          <SelectItem value="resolved">Resolved</SelectItem>
        </SelectContent>
      </Select>

      {availableTags.length > 0 && (
        <Select value={tagFilter} onValueChange={setTagFilter}>
          <SelectTrigger className="w-36 h-9 text-sm"><SelectValue placeholder="All tags" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All tags</SelectItem>
            {availableTags.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
          </SelectContent>
        </Select>
      )}

      {(availableSources.length > 1 || sourceFilter !== "all") && (
        <Select value={sourceFilter} onValueChange={setSourceFilter}>
          <SelectTrigger className="w-40 h-9 text-sm"><SelectValue placeholder="All sources" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All sources</SelectItem>
            {availableSources.map(s => <SelectItem key={s} value={s}>{sourceLabel(s)}</SelectItem>)}
          </SelectContent>
        </Select>
      )}

      {(availablePorts.length > 0 || portFilter !== "all") && (
        <Select value={portFilter} onValueChange={setPortFilter}>
          <SelectTrigger className="w-32 h-9 text-sm"><SelectValue placeholder="All ports" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All ports</SelectItem>
            {availablePorts.map(p => <SelectItem key={p} value={String(p)}>Port {p}</SelectItem>)}
          </SelectContent>
        </Select>
      )}

      {/* Scoped filters arriving from a deep link (asset-card pill, dashboard card) — dismissable */}
      {assetFilter && (
        <button onClick={() => setAssetFilter("")}
          className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-2 h-9 text-xs font-medium hover:opacity-80 transition-opacity">
          <span className="text-muted-foreground">Asset:</span>
          <span className="font-mono">{displayName(assetFilter)}</span> <X className="h-3 w-3" />
        </button>
      )}
      {sinceFilter && (
        <button onClick={() => setSinceFilter("")}
          className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 h-9 text-xs font-medium text-primary hover:opacity-80 transition-opacity">
          <Sparkles className="h-3 w-3" /> New ({sinceFilter}) <X className="h-3 w-3" />
        </button>
      )}

      {/* Active enrichment filters (e.g. arrived from a dashboard chip) — dismissable */}
      {kevFilter && (
        <button onClick={() => setKevFilter(false)}
          className="inline-flex items-center gap-1 rounded border border-red-500/40 bg-red-500/10 px-2 h-9 text-xs font-medium text-red-600 dark:text-red-400 hover:opacity-80 transition-opacity">
          In KEV <X className="h-3 w-3" />
        </button>
      )}
      {exploitFilter && (
        <button onClick={() => setExploitFilter(false)}
          className="inline-flex items-center gap-1 rounded border border-orange-500/40 bg-orange-500/10 px-2 h-9 text-xs font-medium text-orange-600 dark:text-orange-400 hover:opacity-80 transition-opacity">
          Public exploit <X className="h-3 w-3" />
        </button>
      )}
      {impactClassFilter !== "all" && (
        <button onClick={() => setImpactClassFilter("all")}
          className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-2 h-9 text-xs font-medium hover:opacity-80 transition-opacity">
          {IMPACT_CLASS_LABEL[impactClassFilter as keyof typeof IMPACT_CLASS_LABEL] ?? impactClassFilter} <X className="h-3 w-3" />
        </button>
      )}
      {automatableFilter && (
        <button onClick={() => setAutomatableFilter(false)}
          className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-2 h-9 text-xs font-medium hover:opacity-80 transition-opacity">
          Automatable <X className="h-3 w-3" />
        </button>
      )}
      {techImpactFilter !== "all" && (
        <button onClick={() => setTechImpactFilter("all")}
          className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-2 h-9 text-xs font-medium hover:opacity-80 transition-opacity">
          {techImpactFilter === "total" ? "Total control" : "Partial control"} <X className="h-3 w-3" />
        </button>
      )}
      {bodFilter !== "all" && (
        <button onClick={() => setBodFilter("all")}
          className="inline-flex items-center gap-1 rounded border border-border bg-muted/40 px-2 h-9 text-xs font-medium hover:opacity-80 transition-opacity">
          BOD: {bodFilter} <X className="h-3 w-3" />
        </button>
      )}

      <div className="ml-auto flex items-center gap-2">
        <span className="text-xs text-muted-foreground">
          {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
        </span>
        <GroupBySelect group={group} onChange={setGroup} />
        <ViewToggle view={view} onChange={setView} />
      </div>
    </>
  )

  // ── Bulk action bar ───────────────────────────────────────────────────────────

  const bulkBar = selectedIds.size > 0 && mutable ? (
    <div className="flex items-center gap-3">
      <span className="text-sm font-medium">{selectedIds.size} selected</span>
      <div className="flex items-center gap-2 ml-auto">
        <Button size="sm" variant="outline" disabled={bulkStateMutation.isPending}
          onClick={() => bulkStateMutation.mutate({ state: "acknowledged" })}>
          <ShieldCheck className="h-3.5 w-3.5 mr-1.5" />Acknowledge
        </Button>
        <Button size="sm" variant="outline" disabled={bulkStateMutation.isPending}
          onClick={() => setBulkSuppressOpen(true)}>
          <ShieldOff className="h-3.5 w-3.5 mr-1.5" />Suppress
        </Button>
        <Button size="sm" variant="outline" disabled={bulkStateMutation.isPending}
          onClick={() => bulkStateMutation.mutate({ state: "open" })}>
          Reopen
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>Clear</Button>
      </div>
    </div>
  ) : undefined

  // ── Row / card / grouping render helpers ─────────────────────────────────────

  const renderFindingRow = (f: Finding) => (
    <TableRow key={f.id} className="cursor-pointer" onClick={() => openFinding(f)}>
      <TableCell className="pl-4" onClick={e => e.stopPropagation()}>
        <IndeterminateCheckbox checked={selectedIds.has(f.id)} onChange={checked => toggleOne(f.id, checked)} />
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap items-center gap-1">
          {f.risk_band
            ? <RiskBandBadge band={f.risk_band} score={f.risk_score} />
            : <SeverityBadge severity={f.severity} />}
          <ImpactClassBadge finding={f} />
          <BuildingVelocityBadge active={f.building_velocity} />
        </div>
      </TableCell>
      <TableCell className="hidden sm:table-cell"><CategoryBadge category={f.category} /></TableCell>
      <TableCell>
        <div className="space-y-0.5">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-medium leading-tight">{findingTitle(f)}</p>
            {f.cve_id && <span className="font-mono text-xs text-muted-foreground shrink-0">{f.cve_id}</span>}
            <ExposureOverrideBadge finding={f} />
            {isNew(f) && (
              <span className="inline-flex items-center gap-1 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-medium text-primary">
                <Sparkles className="h-2.5 w-2.5" />New
              </span>
            )}
            {isStale(f.last_seen_at) && (
              <span
                className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:text-amber-400"
                title={`Last seen ${relativeTime(f.last_seen_at)} — not observed in recent scans`}
              >
                <Clock className="h-2.5 w-2.5" />stale {daysSince(f.last_seen_at)}d
              </span>
            )}
          </div>
          {f.description && <p className="text-xs text-muted-foreground line-clamp-1">{f.description}</p>}
        </div>
      </TableCell>
      <TableCell className="hidden md:table-cell font-mono text-xs text-muted-foreground">{displayName(f.asset_value)}</TableCell>
      <TableCell className="hidden lg:table-cell"><EnrichmentBadges finding={f} /></TableCell>
      <TableCell className="hidden xl:table-cell">
        <OverflowCell
          items={f.tags ?? []}
          renderItem={(tag) => <TagBadge key={tag} tag={tag} />}
          renderOverflowItem={(tag) => <TagBadge key={tag} tag={tag} />}
          getLabel={(tag) => tag}
          limit={2}
        />
      </TableCell>
      <TableCell className="hidden md:table-cell"><StateBadge state={f.state} /></TableCell>
      <TableCell onClick={e => e.stopPropagation()}>
        <FindingActionsMenu
          finding={f}
          onAcknowledge={() => stateMutation.mutate({ id: f.id, state: "acknowledged" })}
          onSuppress={() => setSuppressTarget(f)}
          onVerify={() => verifyMutation.mutate(f.id)}
          onReopen={() => stateMutation.mutate({ id: f.id, state: "open" })}
          verifyPending={verifyMutation.isPending}
          statePending={stateMutation.isPending}
        />
      </TableCell>
    </TableRow>
  )

  const sectionHeaderRow = (g: Group) => {
    const isCollapsed = collapsedGroups.has(g.key)
    return (
      <TableRow key={`__hdr_${g.key}`} className="bg-muted/30 border-t cursor-pointer" onClick={() => toggleGroup(g.key)}>
        <TableCell colSpan={9} className="py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            {isCollapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            {g.label} <span className="text-muted-foreground/60">· {g.items.length}</span>
          </span>
        </TableCell>
      </TableRow>
    )
  }

  const tableShell = (rows: ReactNode) => (
    <div className="rounded-lg border overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-8 pl-4">
              <IndeterminateCheckbox
                checked={allFilteredSelected}
                indeterminate={someFilteredSelected && !allFilteredSelected}
                onChange={toggleAll}
              />
            </TableHead>
            <TableHead className="w-24">Risk</TableHead>
            <TableHead className="w-28 hidden sm:table-cell">Category</TableHead>
            <TableHead className="min-w-[200px]">Title</TableHead>
            <TableHead className="hidden md:table-cell">Asset</TableHead>
            <TableHead className="hidden lg:table-cell w-36">Enrichment</TableHead>
            <TableHead className="hidden xl:table-cell w-40">Tags</TableHead>
            <TableHead className="w-28 hidden md:table-cell">State</TableHead>
            <TableHead className="w-10" />
          </TableRow>
        </TableHeader>
        <TableBody>{rows}</TableBody>
      </Table>
    </div>
  )

  const cardGrid = (items: Finding[]) => (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {items.map(f => (
        <FindingCard
          key={f.id}
          finding={f}
          onClick={() => openFinding(f)}
          selected={selectedFinding?.id === f.id}
          onAcknowledge={() => stateMutation.mutate({ id: f.id, state: "acknowledged" })}
          onSuppress={() => setSuppressTarget(f)}
          onVerify={() => verifyMutation.mutate(f.id)}
          onReopen={() => stateMutation.mutate({ id: f.id, state: "open" })}
          verifyPending={verifyMutation.isPending}
          statePending={stateMutation.isPending}
        />
      ))}
    </div>
  )

  let body: ReactNode
  if (group === "none") {
    body = view === "card" ? cardGrid(filtered) : tableShell(filtered.map(renderFindingRow))
  } else if (view === "card") {
    body = group === "asset" ? (
      // Each asset becomes a rich AssetRiskCard — the grouping IS the card.
      <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        {groups.map(g => (
          <AssetRiskCard key={g.key} asset={assetForGroup(g)} findings={g.items} href={assetScopeHref(g.items)} />
        ))}
      </div>
    ) : (
      <div className="space-y-6">
        {groups.map(g => {
          const isCollapsed = collapsedGroups.has(g.key)
          return (
            <section key={g.key} className="space-y-3">
              <button
                onClick={() => toggleGroup(g.key)}
                className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
              >
                {isCollapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                {g.label} <span className="text-muted-foreground/60">· {g.items.length}</span>
              </button>
              {!isCollapsed && cardGrid(g.items)}
            </section>
          )
        })}
      </div>
    )
  } else {
    body = tableShell(groups.flatMap(g =>
      collapsedGroups.has(g.key)
        ? [sectionHeaderRow(g)]
        : [sectionHeaderRow(g), ...g.items.map(renderFindingRow)],
    ))
  }

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <>
      <WorkspaceShell
        title="Findings"
        subtitle="Risk findings from all scans"
        tabs={tabs}
        activeTab={activeTab}
        onTabChange={(key) => { setActiveTab(key); setSelectedIds(new Set()) }}
        primaryAction={severityPills}
        toolbar={toolbar}
        bulkBar={bulkBar}
      >
        {isLoading ? (
          <div className="space-y-2">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
        ) : filtered.length === 0 ? (
          <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
            <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-30" />
            <p className="font-medium">{findings?.length === 0 ? "No findings yet" : "No results"}</p>
            <p className="text-sm mt-1">{findings?.length === 0 ? "Run a scan to discover findings." : "Try adjusting your filters."}</p>
          </div>
        ) : body}
      </WorkspaceShell>

      {suppressTarget && <SuppressDialog finding={suppressTarget} onClose={() => setSuppressTarget(null)} />}

      {bulkSuppressOpen && (
        <BulkSuppressDialog
          count={selectedIds.size}
          onClose={() => setBulkSuppressOpen(false)}
          onConfirm={days => {
            const until = new Date()
            until.setDate(until.getDate() + days)
            bulkStateMutation.mutate({ state: "suppressed", suppressedUntil: until.toISOString() })
            setBulkSuppressOpen(false)
          }}
        />
      )}

      {selectedFinding && (
        <FindingDetailSheet
          finding={selectedFinding}
          onClose={closeFinding}
          onStateChange={(id, state) => stateMutation.mutate({ id, state })}
          onSuppress={(f) => setSuppressTarget(f)}
          onVerify={(id) => verifyMutation.mutate(id)}
        />
      )}
    </>
  )
}
