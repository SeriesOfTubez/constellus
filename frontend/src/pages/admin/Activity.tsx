import { useState, useEffect, useRef } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "react-router-dom"
import { toast } from "sonner"
import {
  Activity as ActivityIcon, AlertCircle, CheckCircle2, Circle, Clock,
  Filter, Info, Loader2, RefreshCw, ScanLine, Timer, Trash2, XCircle,
} from "lucide-react"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useFlyout } from "@/lib/flyout"
import { api, type ScanKind, type ScanRun } from "@/lib/api"
import { displayName } from "@/lib/apex"

// ── Shared helpers ────────────────────────────────────────────────────────────

const STATUS_BADGE: Record<ScanRun["status"], { label: string; variant: "default" | "outline" | "success" | "warning" | "destructive" }> = {
  pending:   { label: "Pending",   variant: "outline" },
  running:   { label: "Running",   variant: "warning" },
  completed: { label: "Completed", variant: "success" },
  failed:    { label: "Failed",    variant: "destructive" },
  cancelled: { label: "Cancelled", variant: "outline" },
}

const KIND_LABEL: Record<ScanKind, string> = {
  monitoring:        "Monitoring",
  initial_discovery: "Initial discovery",
  recheck:           "Recheck",
  manual:            "Manual",
}

function duration(run: ScanRun): string {
  if (!run.started_at) return "—"
  const end = run.completed_at ? new Date(run.completed_at) : new Date()
  const secs = Math.round((end.getTime() - new Date(run.started_at).getTime()) / 1000)
  if (secs < 60) return `${secs}s`
  return `${Math.floor(secs / 60)}m ${secs % 60}s`
}

// ── Scans panel ───────────────────────────────────────────────────────────────

function ScanDetailSheet({ run, onClose }: { run: ScanRun; onClose: () => void }) {
  const navigate = useNavigate()
  const badge = STATUS_BADGE[run.status]

  const timeline = [
    { label: "Created",   value: run.created_at,   icon: Clock },
    { label: "Started",   value: run.started_at,   icon: CheckCircle2 },
    { label: "Completed", value: run.completed_at, icon: run.status === "failed" ? AlertCircle : CheckCircle2 },
  ].filter(e => e.value)

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-[480px] sm:max-w-[480px] flex flex-col gap-0 p-0">
        <SheetHeader className="px-6 pt-6 pb-4 border-b space-y-2">
          <div className="flex items-center gap-2">
            <Badge variant={badge.variant}>{badge.label}</Badge>
            <Badge variant="outline">{KIND_LABEL[run.kind]}</Badge>
            {run.status === "running" && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
          </div>
          <SheetTitle className="text-base leading-snug">
            {run.name ?? run.scope.domains.slice(0, 2).map(displayName).join(", ") ?? "Unnamed scan"}
          </SheetTitle>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: "Assets",   value: run.asset_count },
              { label: "Findings", value: run.finding_count },
              { label: "Duration", value: duration(run) },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-md border p-3 text-center">
                <p className="text-lg font-semibold">{value}</p>
                <p className="text-xs text-muted-foreground">{label}</p>
              </div>
            ))}
          </div>

          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Scope</p>
            <div className="rounded-md border divide-y text-xs font-mono max-h-48 overflow-y-auto">
              {run.scope.domains.map(d => (
                <div key={d} className="px-3 py-2 flex items-center gap-2" title={d}>
                  <ScanLine className="h-3 w-3 text-muted-foreground shrink-0" />{displayName(d)}
                </div>
              ))}
              {run.scope.ip_ranges?.map(r => (
                <div key={r} className="px-3 py-2 flex items-center gap-2">
                  <ScanLine className="h-3 w-3 text-muted-foreground shrink-0" />{r}
                </div>
              ))}
              {run.scope.domains.length === 0 && (run.scope.ip_ranges?.length ?? 0) === 0 && (
                <div className="px-3 py-2 text-muted-foreground italic">Scope resolved dynamically from targets</div>
              )}
            </div>
          </div>

          <Separator />
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Timeline</p>
            <div className="space-y-2">
              {timeline.map(({ label, value, icon: Icon }) => (
                <div key={label} className="flex items-center gap-3 text-xs">
                  <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="text-muted-foreground w-20 shrink-0">{label}</span>
                  <span>{new Date(value!).toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>

          {run.connectors_used && run.connectors_used.length > 0 && (
            <>
              <Separator />
              <div className="space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Connectors used</p>
                <div className="flex flex-wrap gap-1.5">
                  {run.connectors_used.map(c => (
                    <span key={c} className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-mono">{c}</span>
                  ))}
                </div>
              </div>
            </>
          )}

          {run.error && (
            <>
              <Separator />
              <div className="space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-destructive">Error</p>
                <pre className="text-xs font-mono bg-destructive/5 border border-destructive/20 rounded p-3 whitespace-pre-wrap break-all text-destructive">{run.error}</pre>
              </div>
            </>
          )}
        </div>

        <div className="px-6 py-4 border-t flex gap-2">
          <Button size="sm" variant="outline" onClick={() => { navigate(`/assets?scan=${run.id}`); onClose() }}>
            View assets
          </Button>
          <Button size="sm" variant="outline" onClick={() => { navigate(`/findings?scan=${run.id}`); onClose() }}>
            View findings
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  )
}

function ScanRow({ run, onDetail }: { run: ScanRun; onDetail: (run: ScanRun) => void }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const badge = STATUS_BADGE[run.status]

  const cancelMutation = useMutation({
    mutationFn: () => api.post(`/scans/${run.id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
    onError: () => toast.error("Failed to cancel scan"),
  })

  return (
    <Card className="cursor-pointer hover:border-primary/50 transition-colors" onClick={() => navigate(`/assets?scan=${run.id}`)}>
      <CardContent className="flex items-center gap-4 py-4">
        <div className="flex-1 min-w-0 space-y-0.5">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-medium truncate">{run.name ?? run.scope.domains.map(displayName).join(", ") ?? "Unnamed scan"}</p>
            <Badge variant={badge.variant}>{badge.label}</Badge>
            <Badge variant="outline" className="text-[10px]">{KIND_LABEL[run.kind]}</Badge>
            {run.status === "running" && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
          </div>
          {run.scope.domains.length > 0 && (
            <p className="text-xs text-muted-foreground">
              {run.scope.domains.slice(0, 3).map(displayName).join(", ")}{run.scope.domains.length > 3 && ` +${run.scope.domains.length - 3} more`}
            </p>
          )}
        </div>

        <div className="hidden sm:flex items-center gap-6 text-sm text-muted-foreground shrink-0">
          <div className="text-center">
            <p className="font-medium text-foreground">{run.asset_count}</p>
            <p className="text-xs">assets</p>
          </div>
          <div className="text-center">
            <p className="font-medium text-foreground">{run.finding_count}</p>
            <p className="text-xs">findings</p>
          </div>
          <div className="text-center">
            <p className="font-medium text-foreground">{duration(run)}</p>
            <p className="text-xs">duration</p>
          </div>
          <p className="text-xs whitespace-nowrap">{new Date(run.created_at).toLocaleString()}</p>
        </div>

        <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
          <Button variant="ghost" size="sm" onClick={() => onDetail(run)} title="Details">
            <Info className="h-4 w-4" />
          </Button>
          {(run.status === "pending" || run.status === "running") && (
            <Button variant="ghost" size="sm" onClick={() => cancelMutation.mutate()} disabled={cancelMutation.isPending} title="Cancel">
              <XCircle className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

function ScansPanel() {
  const qc = useQueryClient()
  const [includeRechecks, setIncludeRechecks] = useState(false)

  const { data: scans, isLoading } = useQuery({
    queryKey: ["scans", { includeRechecks }],
    queryFn: () => api.get<ScanRun[]>(`/scans/${includeRechecks ? "?include_rechecks=true" : ""}`),
    refetchInterval: (query) => {
      const data = query.state.data as ScanRun[] | undefined
      return data?.some(s => s.status === "running" || s.status === "pending") ? 3000 : false
    },
  })

  const { selected: selectedScan, open: openScan, close: closeScan } = useFlyout(scans ?? [])

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-6 py-3 border-b flex-shrink-0">
        <div className="flex items-center gap-3">
          <Label className="text-xs text-muted-foreground cursor-pointer">Include rechecks</Label>
          <Switch checked={includeRechecks} onCheckedChange={setIncludeRechecks} />
        </div>
        <Button variant="outline" size="sm" onClick={() => qc.invalidateQueries({ queryKey: ["scans"] })}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-3">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-20 w-full" />)
        ) : scans?.length === 0 ? (
          <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
            <ScanLine className="h-12 w-12 mx-auto mb-4 opacity-30" />
            <p className="font-medium">No scan activity yet</p>
            <p className="text-sm mt-1">Add a target to kick off the first discovery run.</p>
          </div>
        ) : (
          scans?.map(run => <ScanRow key={run.id} run={run} onDetail={openScan} />)
        )}
      </div>

      {selectedScan && <ScanDetailSheet run={selectedScan} onClose={closeScan} />}
    </div>
  )
}

// ── System logs panel ─────────────────────────────────────────────────────────

type LogEntry = {
  id: string
  created_at: string
  level: "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL"
  source: string
  logger_name: string
  message: string
}

const LEVEL_COLOR: Record<string, string> = {
  DEBUG:    "text-muted-foreground",
  INFO:     "text-blue-500",
  WARNING:  "text-yellow-500",
  ERROR:    "text-red-500",
  CRITICAL: "text-red-600 font-bold",
}

const LEVEL_BG: Record<string, string> = {
  DEBUG:    "",
  INFO:     "",
  WARNING:  "bg-yellow-500/5",
  ERROR:    "bg-red-500/5",
  CRITICAL: "bg-red-500/10",
}

const SOURCE_COLOR: Record<string, string> = {
  system:           "text-muted-foreground",
  scan_executor:    "text-purple-500",
  cloudflare:       "text-orange-500",
  mailtrap:         "text-blue-500",
  tenable:          "text-red-500",
  wiz:              "text-cyan-500",
  fortimanager:     "text-indigo-500",
  nuclei:           "text-green-500",
  cert_transparency:"text-blue-400",
  subfinder:        "text-purple-400",
  dnsrecon:         "text-green-400",
  bruteforce:       "text-yellow-500",
}

function fmtLogTime(iso: string) {
  const d = new Date(iso)
  const date = d.toLocaleDateString("en-CA")  // YYYY-MM-DD
  const time = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  return `${date} ${time}.${String(d.getMilliseconds()).padStart(3, "0")}`
}

function SystemLogsPanel() {
  const qc = useQueryClient()
  const [source, setSource] = useState("all")
  const [level, setLevel] = useState("all")
  const [search, setSearch] = useState("")
  const [autoRefresh, setAutoRefresh] = useState(true)
  const bottomRef = useRef<HTMLDivElement>(null)
  const [pinToBottom, setPinToBottom] = useState(true)

  const { data: sources } = useQuery({
    queryKey: ["log-sources"],
    queryFn: () => api.get<string[]>("/logs/sources"),
    staleTime: 30_000,
  })

  const { data: logSettings } = useQuery({
    queryKey: ["log-settings"],
    queryFn: () => api.get<{ retention_days: number; retention_options: number[] }>("/logs/settings"),
  })

  const retentionMutation = useMutation({
    mutationFn: (days: number) => api.put("/logs/settings", { retention_days: days }),
    onSuccess: (_, days) => {
      toast.success(`Log retention set to ${days === 1 ? "24 hours" : `${days} days`}`)
      qc.invalidateQueries({ queryKey: ["log-settings"] })
    },
    onError: () => toast.error("Failed to update retention"),
  })

  const { data: logs, isLoading, isFetching } = useQuery({
    queryKey: ["logs", source, level, search],
    queryFn: () => {
      const params = new URLSearchParams()
      if (source !== "all") params.set("source", source)
      if (level !== "all") params.set("level", level)
      if (search) params.set("search", search)
      return api.get<LogEntry[]>(`/logs/?${params}`)
    },
    refetchInterval: autoRefresh ? 5000 : false,
  })

  const clearMutation = useMutation({
    mutationFn: () => api.delete("/logs/"),
    onSuccess: () => {
      toast.success("Logs cleared")
      qc.invalidateQueries({ queryKey: ["logs"] })
      qc.invalidateQueries({ queryKey: ["log-sources"] })
    },
    onError: () => toast.error("Failed to clear logs"),
  })

  useEffect(() => {
    if (pinToBottom) bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [logs, pinToBottom])

  const reversed = [...(logs ?? [])].reverse()

  return (
    <div className="flex flex-col h-full">
      <div className="px-4 py-3 border-b space-y-3 flex-shrink-0">
        <div className="flex flex-wrap gap-2 items-center">
          <div className="relative flex-1 min-w-48 max-w-xs">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input className="pl-8 h-8 text-xs font-mono" placeholder="Search messages..."
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>

          <Select value={source} onValueChange={setSource}>
            <SelectTrigger className="w-44 h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All sources</SelectItem>
              <SelectItem value="system">System</SelectItem>
              {sources?.filter(s => s !== "system").map(s => (
                <SelectItem key={s} value={s}>{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={level} onValueChange={setLevel}>
            <SelectTrigger className="w-32 h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All levels</SelectItem>
              <SelectItem value="INFO">Info</SelectItem>
              <SelectItem value="WARNING">Warning</SelectItem>
              <SelectItem value="ERROR">Error</SelectItem>
              <SelectItem value="CRITICAL">Critical</SelectItem>
            </SelectContent>
          </Select>

          <span className="text-xs text-muted-foreground">
            {logs?.length ?? 0} entries
          </span>

          <div className="flex items-center gap-3 ml-auto">
            <div className="flex items-center gap-1.5">
              {isFetching && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
              {autoRefresh && !isFetching && (
                <Circle className="h-2 w-2 fill-emerald-500 text-emerald-500 animate-pulse" />
              )}
              <Label className="text-xs text-muted-foreground cursor-pointer">Live</Label>
              <Switch checked={autoRefresh} onCheckedChange={setAutoRefresh} />
            </div>
            <Button variant="outline" size="sm"
              onClick={() => qc.invalidateQueries({ queryKey: ["logs"] })}>
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
            {logSettings && (
              <div className="flex items-center gap-1.5">
                <Timer className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                <span className="text-xs text-muted-foreground whitespace-nowrap">Retain for</span>
                <Select
                  value={String(logSettings.retention_days)}
                  onValueChange={v => retentionMutation.mutate(Number(v))}
                >
                  <SelectTrigger className="h-8 w-28 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {logSettings.retention_options.map(d => (
                      <SelectItem key={d} value={String(d)}>
                        {d === 1 ? "24 hours" : `${d} days`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <Button variant="outline" size="sm"
              className="text-destructive hover:text-destructive"
              disabled={clearMutation.isPending}
              onClick={() => { if (confirm("Clear all logs?")) clearMutation.mutate() }}>
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto font-mono text-xs bg-[#0a0a0a]"
        onScroll={e => {
          const el = e.currentTarget
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
          setPinToBottom(atBottom)
        }}>
        {isLoading ? (
          <div className="p-4 text-muted-foreground">Loading…</div>
        ) : reversed.length === 0 ? (
          <div className="p-4 text-muted-foreground">No log entries yet.</div>
        ) : (
          reversed.map(entry => (
            <div key={entry.id}
              className={`flex gap-3 px-4 py-0.5 hover:bg-white/5 border-b border-white/5 ${LEVEL_BG[entry.level] ?? ""}`}>
              <span className="text-[11px] text-muted-foreground shrink-0 w-44 tabular-nums">
                {fmtLogTime(entry.created_at)}
              </span>
              <span className={`shrink-0 w-16 ${LEVEL_COLOR[entry.level] ?? "text-foreground"}`}>
                {entry.level}
              </span>
              <span className={`shrink-0 w-28 truncate ${SOURCE_COLOR[entry.source] ?? "text-muted-foreground"}`}>
                {entry.source}
              </span>
              <span className="text-foreground/90 break-all">{entry.message}</span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function Activity() {
  const [tab, setTab] = useState<"scans" | "logs">("scans")

  return (
    <Tabs value={tab} onValueChange={(v) => setTab(v as "scans" | "logs")} className="flex flex-col h-screen">
      <div className="flex flex-col px-6 pt-4 pb-3 border-b flex-shrink-0 gap-3">
        <AdminBreadcrumb page="Activity" />
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <ActivityIcon className="h-5 w-5 text-muted-foreground" />
            <div>
              <h1 className="text-xl font-semibold leading-tight">Activity</h1>
              <p className="text-xs text-muted-foreground">Scan runs and system logs</p>
            </div>
          </div>
          <TabsList>
            <TabsTrigger value="scans">Scans</TabsTrigger>
            <TabsTrigger value="logs">System logs</TabsTrigger>
          </TabsList>
        </div>
      </div>

      <TabsContent value="scans" className="flex-1 overflow-hidden min-h-0 m-0 data-[state=inactive]:hidden" forceMount>
        <ScansPanel />
      </TabsContent>
      <TabsContent value="logs" className="flex-1 overflow-hidden min-h-0 m-0 data-[state=inactive]:hidden" forceMount>
        <SystemLogsPanel />
      </TabsContent>
    </Tabs>
  )
}
