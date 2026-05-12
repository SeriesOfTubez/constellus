import { useState } from "react"
import { useSearchParams } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { AlertTriangle, Filter, Loader2, ShieldCheck, ShieldOff, RefreshCw, ChevronDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { api, type Finding } from "@/lib/api"

// ── Severity ──────────────────────────────────────────────────────────────────

const SEVERITY_COLOR: Record<Finding["severity"], string> = {
  critical: "bg-red-500/15 text-red-500 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-500 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-500 border-blue-500/30",
  info:     "bg-muted text-muted-foreground border-border",
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold capitalize ${SEVERITY_COLOR[severity]}`}>
      {severity}
    </span>
  )
}

// ── Category ──────────────────────────────────────────────────────────────────

const CATEGORY_LABEL: Record<string, string> = {
  cve:                    "CVE",
  app_security:           "App Security",
  exposed_asset:          "Exposed Asset",
  information_disclosure: "Info Disclosure",
  configuration:          "Configuration",
  network_security:       "Network Security",
  outdated_software:      "Outdated Software",
  other:                  "Other",
}

const CATEGORY_COLOR: Record<string, string> = {
  cve:                    "bg-red-500/10 text-red-600 dark:text-red-400",
  app_security:           "bg-purple-500/10 text-purple-600 dark:text-purple-400",
  exposed_asset:          "bg-orange-500/10 text-orange-600 dark:text-orange-400",
  information_disclosure: "bg-yellow-500/10 text-yellow-600 dark:text-yellow-400",
  configuration:          "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  network_security:       "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400",
  outdated_software:      "bg-slate-500/10 text-slate-600 dark:text-slate-400",
  other:                  "bg-muted text-muted-foreground",
}

function CategoryBadge({ category }: { category: string | null }) {
  if (!category) return null
  const label = CATEGORY_LABEL[category] ?? category
  const color = CATEGORY_COLOR[category] ?? "bg-muted text-muted-foreground"
  return (
    <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium ${color}`}>
      {label}
    </span>
  )
}

// ── Enrichment badges ─────────────────────────────────────────────────────────

function cvssColor(score: number): string {
  if (score >= 9.0) return "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/30"
  if (score >= 7.0) return "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30"
  if (score >= 4.0) return "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-yellow-500/30"
  return "bg-blue-500/15 text-blue-500 border-blue-500/30"
}

function EnrichmentBadges({ finding }: { finding: Finding }) {
  const kevTitle = finding.kev_date_added
    ? `CISA Known Exploited Vulnerability — added ${finding.kev_date_added}`
    : "CISA Known Exploited Vulnerability"

  const cvssTitle = [
    finding.cvss_version ? `CVSS v${finding.cvss_version}` : "CVSS",
    finding.cvss_score?.toFixed(1),
    finding.cvss_vector ? `\n${finding.cvss_vector}` : "",
  ].filter(Boolean).join(" ")

  const epssTitle = finding.epss_percentile != null
    ? `EPSS: ${(finding.epss_score! * 100).toFixed(2)}% exploit probability (${(finding.epss_percentile * 100).toFixed(0)}th percentile)`
    : `EPSS: ${((finding.epss_score ?? 0) * 100).toFixed(2)}% exploit probability`

  return (
    <div className="flex items-center gap-1 flex-wrap">
      {finding.kev && (
        <span className="inline-flex items-center rounded border px-1 py-0.5 text-xs font-bold bg-red-500 text-white border-red-600" title={kevTitle}>
          KEV
        </span>
      )}
      {finding.cvss_score != null && (
        <span className={`inline-flex items-center rounded border px-1 py-0.5 text-xs font-mono ${cvssColor(finding.cvss_score)}`} title={cvssTitle}>
          {finding.cvss_version && <span className="opacity-60 mr-0.5">v{finding.cvss_version}</span>}
          {finding.cvss_score.toFixed(1)}
        </span>
      )}
      {finding.epss_score != null && (
        <span className="inline-flex items-center rounded border px-1 py-0.5 text-xs font-mono bg-muted border-border" title={epssTitle}>
          {(finding.epss_score * 100).toFixed(1)}%
        </span>
      )}
      {finding.cwe && (
        <span className="inline-flex items-center rounded border px-1 py-0.5 text-xs font-mono bg-muted/50 border-border text-muted-foreground" title={finding.cwe}>
          {finding.cwe.replace("CWE-", "CWE‑")}
        </span>
      )}
      {finding.cve_id && (
        <span className="text-xs font-mono text-muted-foreground">{finding.cve_id}</span>
      )}
    </div>
  )
}

// ── State badge ───────────────────────────────────────────────────────────────

const STATE_COLOR: Record<Finding["state"], string> = {
  open:         "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  acknowledged: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  suppressed:   "bg-muted text-muted-foreground",
  resolved:     "bg-slate-500/10 text-slate-500",
}

function StateBadge({ state }: { state: Finding["state"] }) {
  return (
    <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium capitalize ${STATE_COLOR[state]}`}>
      {state}
    </span>
  )
}

// ── Suppress dialog ───────────────────────────────────────────────────────────

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
      return api.patch(`/findings/${finding.id}/state`, {
        state: "suppressed",
        suppressed_until: until.toISOString(),
      })
    },
    onSuccess: () => {
      toast.success("Finding suppressed")
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

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Findings() {
  const [searchParams] = useSearchParams()
  const qc = useQueryClient()
  const [search, setSearch] = useState("")
  const [severityFilter, setSeverityFilter] = useState("all")
  const [categoryFilter, setCategoryFilter] = useState("all")
  const [stateFilter, setStateFilter] = useState(searchParams.get("state") ?? "open")
  const [suppressTarget, setSuppressTarget] = useState<Finding | null>(null)

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings", stateFilter],
    queryFn: () => {
      const params = new URLSearchParams()
      if (stateFilter !== "all") params.set("state", stateFilter)
      return api.get<Finding[]>(`/findings/?${params}`)
    },
  })

  const stateMutation = useMutation({
    mutationFn: ({ id, state }: { id: string; state: string }) =>
      api.patch(`/findings/${id}/state`, { state }),
    onSuccess: (_, { state }) => {
      toast.success(state === "acknowledged" ? "Finding acknowledged" : "Finding resolved")
      qc.invalidateQueries({ queryKey: ["findings"] })
    },
    onError: () => toast.error("Failed to update finding"),
  })

  const verifyMutation = useMutation({
    mutationFn: (id: string) => api.post(`/findings/${id}/verify`),
    onSuccess: () => toast.success("Verification scan queued"),
    onError: () => toast.error("Failed to queue verification"),
  })

  const filtered = (findings ?? []).filter(f => {
    if (severityFilter !== "all" && f.severity !== severityFilter) return false
    if (categoryFilter !== "all" && f.category !== categoryFilter) return false
    if (search) {
      const q = search.toLowerCase()
      if (!f.title.toLowerCase().includes(q) && !f.asset_value.toLowerCase().includes(q)) return false
    }
    return true
  })

  const categories = [...new Set((findings ?? []).map(f => f.category).filter(Boolean))].sort() as string[]

  const counts = SEVERITY_ORDER.reduce<Record<string, number>>((acc, s) => {
    acc[s] = (findings ?? []).filter(f => f.severity === s).length
    return acc
  }, {})

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Findings</h1>
          <p className="text-sm text-muted-foreground mt-1">Risk findings from all scans</p>
        </div>
        {/* Severity summary pills */}
        {findings && findings.length > 0 && (
          <div className="flex items-center gap-1.5">
            {SEVERITY_ORDER.filter(s => counts[s] > 0).map(s => (
              <button key={s} onClick={() => setSeverityFilter(severityFilter === s ? "all" : s)}
                className={`rounded border px-2 py-0.5 text-xs font-semibold capitalize transition-opacity ${SEVERITY_COLOR[s as Finding["severity"]]} ${severityFilter !== "all" && severityFilter !== s ? "opacity-30" : ""}`}>
                {counts[s]} {s}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-48 max-w-sm">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input className="pl-8 h-9 text-sm" placeholder="Search title or asset..."
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

        {categories.length > 0 && (
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger className="w-44 h-9 text-sm"><SelectValue placeholder="All categories" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All categories</SelectItem>
              {categories.map(c => <SelectItem key={c} value={c}>{CATEGORY_LABEL[c] ?? c}</SelectItem>)}
            </SelectContent>
          </Select>
        )}

        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
      ) : filtered.length === 0 ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">{findings?.length === 0 ? "No findings yet" : "No results"}</p>
          <p className="text-sm mt-1">{findings?.length === 0 ? "Run a scan to discover findings." : "Try adjusting your filters."}</p>
        </div>
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-24">Severity</TableHead>
                <TableHead className="w-36 hidden sm:table-cell">Category</TableHead>
                <TableHead>Title</TableHead>
                <TableHead className="hidden md:table-cell">Asset</TableHead>
                <TableHead className="hidden lg:table-cell w-40">Enrichment</TableHead>
                <TableHead className="w-28 hidden md:table-cell">State</TableHead>
                <TableHead className="w-28" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(f => (
                <TableRow key={`${f.id}-${f.discovered_at}`}>
                  <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                  <TableCell className="hidden sm:table-cell"><CategoryBadge category={f.category} /></TableCell>
                  <TableCell>
                    <div className="space-y-0.5">
                      <p className="text-sm font-medium leading-tight">{f.title}</p>
                      {f.description && (
                        <p className="text-xs text-muted-foreground line-clamp-1">{f.description}</p>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="hidden md:table-cell font-mono text-xs text-muted-foreground">{f.asset_value}</TableCell>
                  <TableCell className="hidden lg:table-cell"><EnrichmentBadges finding={f} /></TableCell>
                  <TableCell className="hidden md:table-cell"><StateBadge state={f.state} /></TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      {f.state === "open" && (
                        <>
                          <Button variant="ghost" size="sm" title="Acknowledge"
                            disabled={stateMutation.isPending}
                            onClick={() => stateMutation.mutate({ id: f.id, state: "acknowledged" })}>
                            <ShieldCheck className="h-3.5 w-3.5" />
                          </Button>
                          <Button variant="ghost" size="sm" title="Suppress"
                            onClick={() => setSuppressTarget(f)}>
                            <ShieldOff className="h-3.5 w-3.5" />
                          </Button>
                        </>
                      )}
                      {(f.state === "open" || f.state === "acknowledged") && (
                        <Button variant="ghost" size="sm" title="Re-verify (re-scan to check if resolved)"
                          disabled={verifyMutation.isPending}
                          onClick={() => verifyMutation.mutate(f.id)}>
                          {verifyMutation.isPending
                            ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            : <RefreshCw className="h-3.5 w-3.5" />}
                        </Button>
                      )}
                      {f.state === "suppressed" && (
                        <Button variant="ghost" size="sm" title="Reopen"
                          disabled={stateMutation.isPending}
                          onClick={() => stateMutation.mutate({ id: f.id, state: "open" })}>
                          <ChevronDown className="h-3.5 w-3.5 rotate-180" />
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {suppressTarget && (
        <SuppressDialog finding={suppressTarget} onClose={() => setSuppressTarget(null)} />
      )}
    </div>
  )
}
