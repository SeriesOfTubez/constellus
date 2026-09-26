import { useEffect, useMemo, useState } from "react"
import { Link } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Building2, Loader2, SquareArrowOutUpRight } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type EntityIngestRun, type OrgEntity } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { relativeTime } from "@/lib/time"

const RUN_BADGE: Record<EntityIngestRun["status"], "default" | "secondary" | "destructive" | "outline"> = {
  queued: "outline",
  running: "secondary",
  succeeded: "default",
  failed: "destructive",
}

// The few counters worth a glance; the full `result` is on the row's title.
function runSummary(run: EntityIngestRun): string {
  const r = run.result
  if (!r) return ""
  const n = (k: string) => (typeof r[k] === "number" ? (r[k] as number) : 0)
  const parts = [
    `${n("annual_reports_seen")} 10-Ks`,
    `${n("events_inserted")} new 8-K events`,
    `${n("subsidiaries_proposed")} subsidiaries proposed`,
    `${n("sections_stored")} footnote sections`,
    `${n("website_candidates_proposed")} candidate domains`,
  ]
  const denied = Array.isArray(r.denied) ? r.denied : []
  if (denied.length) parts.push(`denied by posture: ${denied.join(", ")}`)
  return parts.join(" · ")
}

export default function Entities() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.role === "admin"

  const [cik, setCik] = useState("")
  const [search, setSearch] = useState("")
  const [showAll, setShowAll] = useState(false)

  const { data: entities, isLoading } = useQuery({
    queryKey: ["entities"],
    queryFn: () => api.get<OrgEntity[]>("/entities/"),
  })

  const { data: runs } = useQuery({
    queryKey: ["entity-ingest-runs"],
    queryFn: () => api.get<EntityIngestRun[]>("/entities/edgar-ingest/runs?limit=10"),
    // Poll only while something is in flight.
    refetchInterval: q =>
      (q.state.data ?? []).some(r => r.status === "queued" || r.status === "running") ? 3000 : false,
  })

  const ingestMutation = useMutation({
    mutationFn: (value: string) => api.post<{ run_id: string }>("/entities/edgar-ingest", { cik: value }),
    onSuccess: () => {
      toast.success("Ingest started")
      setCik("")
      qc.invalidateQueries({ queryKey: ["entity-ingest-runs"] })
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to start ingest"),
  })

  // A finished run may have created entities; refresh the list once per
  // change in the set of finished runs, not on every poll.
  const finishedKey = (runs ?? []).filter(r => r.finished_at).map(r => r.id).join(",")
  useEffect(() => {
    if (finishedKey) qc.invalidateQueries({ queryKey: ["entities"] })
  }, [finishedKey, qc])

  // EX-21 creates one entity per listed subsidiary, so the unfiltered list is
  // mostly subsidiaries and former names. Filers (a CIK) are the default view.
  const visible = useMemo(() => {
    const q = search.trim().toLowerCase()
    return (entities ?? [])
      .filter(e => showAll || e.cik)
      .filter(e => !q || e.legal_name.toLowerCase().includes(q) || (e.cik ?? "").includes(q))
      .sort((a, b) => a.legal_name.localeCompare(b.legal_name))
  }, [entities, search, showAll])

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Entities</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Companies mapped from SEC filings, with their corporate family, filings and candidate domains.
        </p>
      </div>

      {isAdmin && (
        <div className="rounded-lg border bg-card p-4 space-y-3">
          <form
            className="flex items-end gap-2"
            onSubmit={e => {
              e.preventDefault()
              if (cik.trim()) ingestMutation.mutate(cik.trim())
            }}
          >
            <div className="space-y-1">
              <Label htmlFor="map-cik">Map a company</Label>
              <Input
                id="map-cik" placeholder="SEC CIK (digits)" value={cik} inputMode="numeric"
                onChange={e => setCik(e.target.value)} className="w-56"
              />
            </div>
            <Button type="submit" disabled={!cik.trim() || ingestMutation.isPending}>
              {ingestMutation.isPending && <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />}
              Map
            </Button>
          </form>
          <p className="text-xs text-muted-foreground">
            Reads the company's SEC EDGAR filings only. Nothing is sent to the company itself.
          </p>
        </div>
      )}

      {!!runs?.length && (
        <div className="space-y-2">
          <h2 className="text-sm font-medium">Recent ingests</h2>
          <div className="rounded-lg border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>CIK</TableHead>
                  <TableHead>Company</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Outcome</TableHead>
                  <TableHead>Requested</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runs.map(run => (
                  <TableRow key={run.id} data-testid="ingest-run">
                    <TableCell className="font-mono text-xs">{run.cik}</TableCell>
                    <TableCell>
                      {run.entity_id ? (
                        <Link to={`/entities/${run.entity_id}`} className="hover:text-primary">{run.entity_name}</Link>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant={RUN_BADGE[run.status]}>
                        {run.status === "running" && <Loader2 className="h-3 w-3 mr-1 animate-spin" />}
                        {run.status}
                      </Badge>
                    </TableCell>
                    <TableCell
                      className="text-xs text-muted-foreground max-w-md"
                      title={run.result ? JSON.stringify(run.result, null, 1) : undefined}
                    >
                      {run.status === "failed" ? <span className="text-destructive">{run.error}</span> : runSummary(run)}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{relativeTime(run.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      )}

      <div className="flex items-center gap-4">
        <Input placeholder="Filter by name or CIK" value={search} onChange={e => setSearch(e.target.value)} className="max-w-xs" />
        <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <Switch checked={showAll} onCheckedChange={setShowAll} />
          Include subsidiaries and former names
        </label>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
      ) : !visible.length ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <Building2 className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">No entities</p>
          <p className="text-sm mt-1">{isAdmin ? "Map a company by its CIK to start." : "An admin maps companies by CIK."}</p>
        </div>
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Name</TableHead>
                <TableHead>CIK</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map(e => (
                <TableRow key={e.id}>
                  <TableCell className="font-medium">
                    <Link to={`/entities/${e.id}`} className="hover:text-primary">{e.legal_name}</Link>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{e.cik ?? "—"}</TableCell>
                  <TableCell>
                    <Link to={`/entities/${e.id}`} title="Open entity" className="text-muted-foreground hover:text-primary">
                      <SquareArrowOutUpRight className="h-3.5 w-3.5" />
                    </Link>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
