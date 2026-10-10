import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Loader2, RefreshCw, Sparkles } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { api } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { relativeTime } from "@/lib/time"

// planning#226 — AI write-up for a Critical/High finding.
//
// Everything below renders model output as plain text: no markdown, no
// links, no images. Banners and titles in the model's input are
// attacker-controlled, so its output is treated the same way.

type ContextStatement = { statement: string; source_field: string; value: string }

type Writeup = {
  id: string
  created_at: string
  finished_at: string | null
  model: string | null
  summary: string | null
  context: ContextStatement[]
  fix_steps: string[]
  priority_note: string | null
  statements_returned: number | null
  statements_dropped: number | null
  priority_note_dropped: boolean | null
  forced_strict: boolean
  cost_usd: number | null
}

export type AiWriteupState = {
  eligible: boolean
  writeup: Writeup | null
  inputs_changed: boolean | null
  pending: { id: string; status: string; created_at: string } | null
  last_failure: { error: string | null; finished_at: string | null } | null
}

const SECTION = "text-[10px] font-semibold uppercase tracking-widest text-muted-foreground"

export function AiWriteupPanel({ findingId }: { findingId: string }) {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const canGenerate = user?.role === "admin"
  const key = ["finding-ai-writeup", findingId]

  const { data, isLoading } = useQuery({
    queryKey: key,
    queryFn: () => api.get<AiWriteupState>(`/findings/${findingId}/ai-writeup`),
    refetchInterval: q => (q.state.data?.pending ? 3000 : false),
  })

  const generate = useMutation({
    mutationFn: (force: boolean) =>
      api.post<AiWriteupState & { cached: boolean }>(`/findings/${findingId}/ai-writeup${force ? "?force=true" : ""}`),
    onSuccess: res => {
      qc.setQueryData(key, res)
      if (res.cached) toast.info("Inputs unchanged; showing the existing write-up")
      else qc.invalidateQueries({ queryKey: key })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  if (isLoading || !data) return <Skeleton className="h-32 w-full" />
  if (!data.eligible) {
    return <p className="text-sm text-muted-foreground">AI write-ups are generated for Critical and High findings only.</p>
  }

  const w = data.writeup
  const busy = !!data.pending || generate.isPending
  const failureIsLatest = data.last_failure && !data.pending

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <p className={SECTION}>Remediation (AI)</p>
          {w ? (
            <p className="text-xs text-muted-foreground">
              {w.model ?? "unknown model"} · {relativeTime(w.finished_at ?? w.created_at)}
              {w.cost_usd != null && <> · ${w.cost_usd.toFixed(4)}</>}
              {w.forced_strict && <> · strict data policy</>}
            </p>
          ) : (
            <p className="text-xs text-muted-foreground">No write-up yet.</p>
          )}
        </div>
        {canGenerate && (
          <Button size="sm" variant="outline" disabled={busy} onClick={() => generate.mutate(!!w)}>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : w ? <RefreshCw className="h-3.5 w-3.5" /> : <Sparkles className="h-3.5 w-3.5" />}
            <span className="ml-1.5">{data.pending ? "Generating…" : w ? "Regenerate" : "Generate"}</span>
          </Button>
        )}
      </div>

      {!canGenerate && !w && (
        <p className="text-sm text-muted-foreground">An admin can generate a write-up for this finding.</p>
      )}
      {failureIsLatest && (
        <p className="text-sm text-destructive">Last attempt failed: {data.last_failure!.error ?? "unknown error"}</p>
      )}
      {w && data.inputs_changed && (
        <p className="text-xs text-muted-foreground">
          What Constellus knows about this finding has changed since this write-up was made.
        </p>
      )}

      {w && (
        <>
          {w.summary && <p className="text-sm whitespace-pre-wrap">{w.summary}</p>}

          {w.priority_note && (
            <div className="rounded-md border px-3 py-2 space-y-0.5">
              <p className="text-xs font-medium">Priority note (AI)</p>
              <p className="text-sm whitespace-pre-wrap">{w.priority_note}</p>
              <p className="text-[11px] text-muted-foreground">Never changes severity or score.</p>
            </div>
          )}

          <div className="space-y-2">
            <p className={SECTION}>About this asset</p>
            {w.context.length === 0 ? (
              <p className="text-sm text-muted-foreground">No statement could be tied to a field Constellus holds.</p>
            ) : (
              <ul className="space-y-2">
                {w.context.map((c, i) => (
                  <li key={i} className="text-sm space-y-0.5">
                    <p className="whitespace-pre-wrap">{c.statement}</p>
                    <p className="text-[11px] font-mono text-muted-foreground break-all">source: {c.source_field}</p>
                  </li>
                ))}
              </ul>
            )}
            {!!w.statements_dropped && (
              <p className="text-[11px] text-muted-foreground">
                {w.statements_dropped} of {w.statements_returned} statements dropped: they cited a field that is not in what Constellus holds.
              </p>
            )}
          </div>

          {w.fix_steps.length > 0 && (
            <div className="space-y-2">
              <p className={SECTION}>General guidance</p>
              <p className="text-[11px] text-muted-foreground">Typical remediation for this kind of issue, not a fact about this asset.</p>
              <ol className="list-decimal pl-5 space-y-1 text-sm">
                {w.fix_steps.map((s, i) => <li key={i} className="whitespace-pre-wrap">{s}</li>)}
              </ol>
            </div>
          )}
        </>
      )}
    </div>
  )
}
