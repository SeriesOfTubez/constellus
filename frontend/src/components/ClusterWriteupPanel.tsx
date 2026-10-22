import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Loader2, RefreshCw, Sparkles } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { api, clusterWriteupPath, type ClusterKey, type ClusterWriteupState } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { relativeTime } from "@/lib/time"

// planning#233 slice 2b — AI write-up for a cross-asset finding cluster.
// Same rule as the per-finding panel: all model output is plain text.

const SECTION = "text-[10px] font-semibold uppercase tracking-widest text-muted-foreground"

export function ClusterWriteupBody({
  data, canGenerate, busy, onGenerate, assetCount,
}: {
  data: ClusterWriteupState
  canGenerate: boolean
  busy: boolean
  onGenerate: (force: boolean) => void
  assetCount?: number
}) {
  if (data.hidden) {
    return <p className="text-sm text-muted-foreground">A write-up exists but covers findings you can't view.</p>
  }
  const w = data.writeup
  if (!data.eligible && !w) {
    return <p className="text-sm text-muted-foreground">{data.ineligible_reason ?? "AI write-ups are not available for this issue."}</p>
  }
  const pending = !!data.pending
  const failureIsLatest = data.last_failure && !pending
  const covers = assetCount != null ? `all ${assetCount} asset${assetCount === 1 ? "" : "s"}` : "every asset"

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <p className={SECTION}>AI-generated write-up of this issue</p>
          {w ? (
            <p className="text-xs text-muted-foreground">
              {w.auto ? "Generated automatically" : "Generated on demand"} · {relativeTime(w.finished_at ?? w.created_at)}
              {" · "}{w.model ?? "unknown model"}
              {" · "}covers {w.asset_count} asset{w.asset_count === 1 ? "" : "s"}, {w.finding_count} finding{w.finding_count === 1 ? "" : "s"}
              {w.cost_usd != null && <> · ${w.cost_usd.toFixed(4)}</>}
              {w.forced_strict && <> · Strict data policy</>}
            </p>
          ) : (
            <p className="text-xs text-muted-foreground">No write-up yet. It covers {covers} in this issue.</p>
          )}
        </div>
        {canGenerate && !w && !pending && (
          <Button size="sm" variant="outline" disabled={busy} onClick={() => onGenerate(false)}>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
            <span className="ml-1.5">Write up this issue with AI</span>
          </Button>
        )}
      </div>

      {pending && (
        <p className="text-sm text-muted-foreground inline-flex items-center gap-1.5">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Generating…
        </p>
      )}
      {!canGenerate && !w && !pending && (
        <p className="text-sm text-muted-foreground">An admin can generate a write-up for this issue.</p>
      )}
      {failureIsLatest && (
        <div className="flex items-center gap-3">
          <p className="text-sm text-destructive">Last attempt failed: {data.last_failure!.error}</p>
          {canGenerate && (
            <Button size="sm" variant="outline" disabled={busy} onClick={() => onGenerate(!!w)}>
              <RefreshCw className="h-3.5 w-3.5" /><span className="ml-1.5">Retry</span>
            </Button>
          )}
        </div>
      )}
      {w && data.inputs_changed && (
        <div className="flex items-center gap-3">
          <p className="text-xs text-amber-600 dark:text-amber-400">Membership changed since this write-up</p>
          {canGenerate && !pending && (
            <Button size="sm" variant="outline" disabled={busy} onClick={() => onGenerate(true)}>
              <RefreshCw className="h-3.5 w-3.5" /><span className="ml-1.5">Regenerate</span>
            </Button>
          )}
        </div>
      )}

      {w && (
        <>
          {w.summary ? (
            <p className="text-sm whitespace-pre-wrap">{w.summary}</p>
          ) : w.summary_dropped ? (
            <p className="text-sm italic text-muted-foreground">Summary withheld: it named an asset outside this issue</p>
          ) : null}

          {w.priority_note && (
            <div className="rounded-md border px-3 py-2 space-y-0.5">
              <p className="text-xs font-medium">Priority note (AI)</p>
              <p className="text-sm whitespace-pre-wrap">{w.priority_note}</p>
              <p className="text-[11px] text-muted-foreground">Never changes severity or score.</p>
            </div>
          )}

          <div className="space-y-2">
            <p className={SECTION}>About this issue</p>
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
              <p className="text-[11px] text-muted-foreground">Typical remediation for this kind of issue, not a fact about these assets.</p>
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

export function ClusterWriteupPanel({ cluster }: { cluster: ClusterKey & { asset_count?: number } }) {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const canGenerate = user?.role === "admin"
  const key = ["cluster-ai-writeup", cluster.finding_type, cluster.source, cluster.fingerprint]

  const { data, isLoading } = useQuery({
    queryKey: key,
    queryFn: () => api.get<ClusterWriteupState>(clusterWriteupPath(cluster)),
    refetchInterval: q => (q.state.data?.pending ? 3000 : false),
  })

  const generate = useMutation({
    mutationFn: (force: boolean) =>
      api.post<ClusterWriteupState & { cached: boolean }>(clusterWriteupPath(cluster, force)),
    onSuccess: res => {
      qc.setQueryData(key, res)
      if (res.cached) toast.info("Inputs unchanged; showing the existing write-up")
      else qc.invalidateQueries({ queryKey: key })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  if (isLoading || !data) return <Skeleton className="h-24 w-full" />
  return (
    <ClusterWriteupBody
      data={data}
      canGenerate={canGenerate}
      busy={generate.isPending}
      onGenerate={f => generate.mutate(f)}
      assetCount={cluster.asset_count}
    />
  )
}
