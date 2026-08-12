import { useState } from "react"
import { Link, useParams } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  ChevronLeft, ShieldCheck, ShieldOff, RefreshCw, ChevronDown, Loader2, SquareArrowOutUpRight,
} from "lucide-react"

import { ConnectedEntities } from "@/components/ConnectedEntities"
import { VulnNarrative, VulnIntel, hasVulnIntel } from "@/components/VulnNarrative"
import { CvssBreakdown } from "@/components/CvssBreakdown"
import {
  SeverityBadge, CategoryBadge, StateBadge, cvssColor,
  RiskBandBadge, BuildingVelocityBadge, ImpactClassBadge, ExploitTypeBadges, EnrichmentBadges,
  ExposureClassBadge, DetectionLayerBadge, SsvcEvidence, BodSlaBadge,
  VerificationBadge, VerificationEvidencePanel,
  SourceBadges, UpstreamEvidence,
} from "@/components/finding-badges"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { TagEditor } from "@/components/ui/tag-editor"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"
import { EpssRow, EpssSparklineSection } from "@/components/EpssHistory"
import { api, type Finding } from "@/lib/api"
import { displayName } from "@/lib/apex"
import { relativeTime } from "@/lib/time"

const SUPPRESS_OPTIONS = [
  { label: "7 days",  days: 7 },
  { label: "30 days", days: 30 },
  { label: "90 days", days: 90 },
  { label: "1 year",  days: 365 },
]

// Underline tab trigger — mirrors the flyout's tab styling for a consistent contract.
const TAB = "h-9 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:shadow-none data-[state=active]:text-foreground text-muted-foreground text-sm font-medium px-3 transition-none"

export default function FindingDetail() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const [suppressOpen, setSuppressOpen] = useState(false)

  const { data: finding, isLoading, isError } = useQuery({
    queryKey: ["finding-detail", id],
    queryFn: () => api.get<Finding>(`/findings/${id}`),
    enabled: !!id,
  })

  const stateMutation = useMutation({
    mutationFn: (state: string) => api.patch(`/findings/${id}/state`, { state }),
    onSuccess: (_, state) => {
      const verb = state === "acknowledged" ? "acknowledged" : state === "open" ? "reopened" : "resolved"
      toast.success(`Finding ${verb}`)
      qc.invalidateQueries({ queryKey: ["finding-detail", id] })
      qc.invalidateQueries({ queryKey: ["findings"] })
    },
    onError: () => toast.error("Failed to update finding"),
  })

  const verifyMutation = useMutation({
    mutationFn: () => api.post(`/findings/${id}/verify`),
    onSuccess: () => toast.success("Verification scan queued"),
    onError: () => toast.error("Failed to queue verification"),
  })

  const tagMutation = useMutation({
    mutationFn: (tags: string[]) => api.patch(`/tags/findings/${id}`, { tags }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding-detail", id] }),
    onError: () => toast.error("Failed to update tags"),
  })

  if (isLoading) return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-4">
      <Skeleton className="h-6 w-32" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-64 w-full" />
    </div>
  )

  if (isError || !finding) return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-4">
      <Link to="/findings" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="h-4 w-4" />Findings
      </Link>
      <div className="rounded-md border bg-card p-6 text-sm text-muted-foreground">
        Finding not found.
      </div>
    </div>
  )

  const detail = finding.detail ?? {}
  const extracted: string[] = (detail.extracted_results as string[]) ?? []
  const matchedAt = detail.matched_at as string | undefined
  const curlCmd = detail.curl_command as string | undefined
  const detailTags: string[] = (detail.tags as string[]) ?? []

  const hasEnrichment = finding.kev || finding.cvss_score != null || finding.epss_score != null
    || finding.cve_id || finding.cwe || finding.vulncheck_kev || finding.has_exploit
    || finding.ransomware_use || finding.canary_detected || finding.is_template || finding.is_poc

  return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-6">
      <Link to="/findings" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="h-4 w-4" />Findings
      </Link>

      {/* Header */}
      <div className="space-y-3">
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
          <StateBadge state={finding.state} />
          <SourceBadges finding={finding} />
        </div>
        <h1 className="text-2xl font-semibold leading-snug">{finding.title}</h1>
        <Link
          to={`/assets/${finding.asset_canonical_id}`}
          className="inline-flex items-center gap-1 font-mono text-sm text-muted-foreground hover:text-foreground"
          title={finding.asset_value}
        >
          {displayName(finding.asset_value)}
        </Link>

        {/* Action bar */}
        <div className="flex flex-wrap gap-2 pt-1">
          {finding.state === "open" && (
            <>
              <Button size="sm" variant="outline"
                disabled={stateMutation.isPending}
                onClick={() => stateMutation.mutate("acknowledged")}>
                <ShieldCheck className="h-3.5 w-3.5 mr-1.5" />Acknowledge
              </Button>
              <Button size="sm" variant="outline" onClick={() => setSuppressOpen(true)}>
                <ShieldOff className="h-3.5 w-3.5 mr-1.5" />Suppress
              </Button>
            </>
          )}
          {finding.state === "acknowledged" && (
            <Button size="sm" variant="outline"
              disabled={stateMutation.isPending}
              onClick={() => stateMutation.mutate("open")}>
              Reopen
            </Button>
          )}
          {finding.state === "suppressed" && (
            <Button size="sm" variant="outline"
              disabled={stateMutation.isPending}
              onClick={() => stateMutation.mutate("open")}>
              <ChevronDown className="h-3.5 w-3.5 mr-1.5 rotate-180" />Reopen
            </Button>
          )}
          {(finding.state === "open" || finding.state === "acknowledged") && (
            <Button size="sm" variant="outline"
              disabled={verifyMutation.isPending}
              onClick={() => verifyMutation.mutate()}>
              {verifyMutation.isPending
                ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
              Re-verify
            </Button>
          )}
        </div>
      </div>

      {/* Tabbed detail — mirrors the flyout contract so adding metadata later is cheap */}
      <Tabs defaultValue="overview" className="w-full">
        <div className="border-b overflow-x-auto">
          <TabsList className="h-auto w-full justify-start gap-0 bg-transparent rounded-none p-0">
            <TabsTrigger value="overview"      className={TAB}>Overview</TabsTrigger>
            {hasVulnIntel(finding) && <TabsTrigger value="intel" className={TAB}>Intel</TabsTrigger>}
            <TabsTrigger value="asset"         className={TAB}>Asset</TabsTrigger>
            <TabsTrigger value="relationships" className={TAB}>Relationships</TabsTrigger>
            <TabsTrigger value="timeline"      className={TAB}>Timeline</TabsTrigger>
            <TabsTrigger value="raw"           className={TAB}>Raw</TabsTrigger>
          </TabsList>
        </div>

        {/* ── Overview — verdict story + scores ── */}
        <TabsContent value="overview" className="pt-5 space-y-6">
          <VulnNarrative finding={finding} />

          {/* Provenance — what produced this finding + the upstream evidence */}
          <UpstreamEvidence finding={finding} />
          <VerificationEvidencePanel finding={finding} />

          {hasEnrichment && (
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Enrichment</p>
              <div className="flex flex-wrap gap-1.5 pb-1"><EnrichmentBadges finding={finding} /></div>
              <div className="rounded-md border divide-y text-sm">
                {finding.cve_id && (
                  <div className="flex items-center gap-3 px-3 py-2">
                    <span className="text-muted-foreground w-24 shrink-0">CVE</span>
                    <span className="font-mono">{finding.cve_id}</span>
                  </div>
                )}
                {finding.cvss_score != null && (
                  <div className="flex items-start gap-3 px-3 py-2">
                    <span className="text-muted-foreground w-24 shrink-0">CVSS</span>
                    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-mono ${cvssColor(finding.cvss_score)}`}>
                      {finding.cvss_version && <span className="opacity-60 mr-1">v{finding.cvss_version}</span>}
                      {finding.cvss_score.toFixed(1)}
                    </span>
                  </div>
                )}
                {(finding.cve_id || finding.epss_score != null) && (
                  <EpssRow
                    findingId={finding.id}
                    fallbackScore={finding.epss_score}
                    fallbackPercentile={finding.epss_percentile}
                  />
                )}
                {finding.kev && (
                  <div className="flex items-center gap-3 px-3 py-2">
                    <span className="text-muted-foreground w-24 shrink-0">KEV</span>
                    <Link to="/findings?kev=true" className="hover:opacity-80 transition-opacity" title="Show all KEV findings">
                      <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-bold bg-red-500 text-white border-red-600">KEV</span>
                    </Link>
                    {finding.kev_date_added && (
                      <span className="text-xs text-muted-foreground">Added {finding.kev_date_added}</span>
                    )}
                  </div>
                )}
                {finding.cwe && (
                  <div className="flex items-center gap-3 px-3 py-2">
                    <span className="text-muted-foreground w-24 shrink-0">CWE</span>
                    <span className="font-mono text-xs">{finding.cwe}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          <SsvcEvidence finding={finding} />

          {finding.cve_id && (
            <EpssSparklineSection findingId={finding.id} />
          )}

          {finding.cvss_vector && (
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">CVSS breakdown</p>
              <CvssBreakdown vector={finding.cvss_vector} version={finding.cvss_version} score={finding.cvss_score} />
            </div>
          )}

          {(matchedAt || extracted.length > 0 || curlCmd) && (
            <div className="space-y-3">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Match details</p>
              {matchedAt && (
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">Matched URL</p>
                  <p className="text-xs font-mono break-all bg-muted rounded px-3 py-2">{matchedAt}</p>
                </div>
              )}
              {extracted.length > 0 && (
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">Extracted</p>
                  <div className="space-y-1">
                    {extracted.map((r, i) => (
                      <p key={i} className="text-xs font-mono bg-muted rounded px-3 py-1.5 break-all">{r}</p>
                    ))}
                  </div>
                </div>
              )}
              {curlCmd && (
                <div className="space-y-1">
                  <p className="text-xs text-muted-foreground">Curl command</p>
                  <pre className="text-xs font-mono bg-muted/60 rounded p-3 overflow-x-auto whitespace-pre-wrap break-all">{curlCmd}</pre>
                </div>
              )}
            </div>
          )}

          {detailTags.length > 0 && (
            <div className="space-y-2">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Tags from source</p>
              <div className="flex flex-wrap gap-1">
                {detailTags.map(tag => (
                  <span key={tag} className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-xs font-mono text-muted-foreground">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Tags</p>
            <TagEditor
              tags={finding.tags ?? []}
              entityType="finding"
              onChange={t => tagMutation.mutate(t)}
            />
          </div>
        </TabsContent>

        {/* ── Intel — exploit & reference links ── */}
        <TabsContent value="intel" className="pt-5">
          <VulnIntel finding={finding} />
        </TabsContent>

        {/* ── Asset ── */}
        <TabsContent value="asset" className="pt-5">
          <div className="space-y-4">
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
            <div className="text-xs text-muted-foreground space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span>Source:</span>
                <SourceBadges finding={finding} />
              </div>
              <p className="break-all">Fingerprint: <span className="text-foreground font-mono">{finding.fingerprint}</span></p>
            </div>
          </div>
        </TabsContent>

        {/* ── Relationships ── */}
        <TabsContent value="relationships" className="pt-5">
          <ConnectedEntities nodeType="finding_canonical" nodeId={finding.id} />
        </TabsContent>

        {/* ── Timeline ── */}
        <TabsContent value="timeline" className="pt-5">
          <div className="grid grid-cols-2 gap-4 text-sm text-muted-foreground">
            <div className="space-y-0.5">
              <p>Source</p>
              <p className="text-foreground capitalize">{finding.source}</p>
            </div>
            <div className="space-y-0.5">
              <p>First seen</p>
              <p className="text-foreground">{finding.first_seen_at && new Date(finding.first_seen_at).toLocaleString()}</p>
            </div>
            <div className="space-y-0.5">
              <p>Last seen</p>
              <p className="text-foreground">
                {finding.last_seen_at && new Date(finding.last_seen_at).toLocaleString()}
                {finding.last_seen_at && <span className="text-muted-foreground"> · {relativeTime(finding.last_seen_at)}</span>}
              </p>
            </div>
            {finding.acknowledged_at && (
              <div className="space-y-0.5">
                <p>Acknowledged</p>
                <p className="text-foreground">{new Date(finding.acknowledged_at).toLocaleString()}</p>
              </div>
            )}
            {finding.suppressed_until && (
              <div className="space-y-0.5">
                <p>Suppressed until</p>
                <p className="text-foreground">{new Date(finding.suppressed_until).toLocaleDateString()}</p>
              </div>
            )}
            {finding.resolved_at && (
              <div className="space-y-0.5">
                <p>Resolved</p>
                <p className="text-foreground">{new Date(finding.resolved_at).toLocaleString()}</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* ── Raw ── */}
        <TabsContent value="raw" className="pt-5">
          <pre className="text-xs font-mono bg-muted/40 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all">
            {JSON.stringify(finding.detail, null, 2)}
          </pre>
        </TabsContent>
      </Tabs>

      {suppressOpen && (
        <SuppressDialog
          finding={finding}
          onClose={() => setSuppressOpen(false)}
        />
      )}
    </div>
  )
}

function SuppressDialog({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const qc = useQueryClient()
  const [days, setDays] = useState("30")

  const mutation = useMutation({
    mutationFn: () => {
      const until = new Date()
      until.setDate(until.getDate() + parseInt(days))
      return api.patch(`/findings/${finding.id}/state`, {
        state: "suppressed",
        suppressed_until: until.toISOString(),
      })
    },
    onSuccess: () => {
      toast.success("Finding suppressed")
      qc.invalidateQueries({ queryKey: ["finding-detail", finding.id] })
      qc.invalidateQueries({ queryKey: ["findings"] })
      onClose()
    },
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
            <SelectContent>
              {SUPPRESS_OPTIONS.map(o => (
                <SelectItem key={o.days} value={String(o.days)}>{o.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={mutation.isPending} onClick={() => mutation.mutate()}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}
            Suppress
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
