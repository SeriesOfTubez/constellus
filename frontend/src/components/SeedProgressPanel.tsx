// planning#232 / #277 S2c — live progress of the EDGAR ingest queued for a new
// organization, plus the AI acquisition read it chains. Presentational only:
// the caller supplies the surrounding buttons.
import { useQuery } from "@tanstack/react-query"
import { CheckCircle2, Loader2, XCircle } from "lucide-react"
import { api, type EntityIngestRun } from "@/lib/api"
import { followupOf, isActive, seedProgress } from "@/lib/companySeed"

export interface SeedProgressSeeded {
  entity_id: string
  entity_name: string
  cik: string | null
  run_id: string | null
  /** "not_requested" never reaches this panel: there is no run to follow. */
  ingest: "queued" | "already_running"
}

export function SeedProgressPanel({ seeded }: { seeded: SeedProgressSeeded }) {
  const runId = seeded.run_id
  const { data: run, isError: runError } = useQuery({
    queryKey: ["onboarding-ingest-run", runId],
    queryFn: () => api.get<EntityIngestRun>(`/entities/edgar-ingest/runs/${runId}`),
    enabled: seeded.ingest === "queued" && !!runId,
    refetchInterval: (q) => (isActive(q.state.data?.status) ? 2000 : false),
  })
  const followup = followupOf(run?.result)
  const readRunId = followup?.status === "queued" ? followup.run_id : undefined

  const { data: reads, isError: readsError } = useQuery({
    queryKey: ["onboarding-read-runs", seeded.entity_id],
    queryFn: () => api.get<EntityIngestRun[]>(`/entities/${seeded.entity_id}/acquisition-read/runs?limit=5`),
    enabled: !!readRunId,
    refetchInterval: (q) => {
      const r = (q.state.data ?? []).find((x) => x.id === readRunId)
      return isActive(r?.status) ? 2000 : false
    },
  })
  const readRun = (reads ?? []).find((r) => r.id === readRunId)

  const p = seedProgress({
    ingest: seeded.ingest,
    ingestStatus: run?.status,
    ingestError: run?.error,
    followup,
    readStatus: readRun?.status,
    readError: readRun?.error,
  })

  const Icon =
    p.phase === "failed" ? XCircle : p.phase === "done" || p.phase === "already_running" ? CheckCircle2 : Loader2
  const spinning = p.phase === "ingest" || p.phase === "read"

  return (
    <div className="rounded-lg border p-4 space-y-2 text-sm">
      <p className="font-medium">
        {seeded.entity_name}
        {seeded.cik && <span className="font-mono text-xs text-muted-foreground"> CIK {seeded.cik}</span>}
      </p>
      <div className="flex items-center gap-2">
        <Icon className={`h-4 w-4 ${spinning ? "animate-spin" : ""} ${p.phase === "failed" ? "text-destructive" : ""}`} />
        <span>{p.ingestLabel}</span>
      </div>
      {p.readLabel && <p className="text-muted-foreground pl-6">{p.readLabel}</p>}
      {p.hint && <p className="text-xs text-muted-foreground pl-6">{p.hint}</p>}
      {(runError || readsError) && (
        <p className="text-xs text-destructive pl-6" role="alert">
          Couldn't check progress. The organization page shows the latest state.
        </p>
      )}
    </div>
  )
}
