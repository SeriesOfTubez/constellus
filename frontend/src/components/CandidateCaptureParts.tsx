// Page capture section of the scope-candidate flyout (planning#280 S5c slice a).
//
// A capture row is a record of a visit, never a finding: statuses use neutral
// badge variants only. "Pruned" (file removed, row kept) and "omitted" (never
// stored) are different facts and stay distinct everywhere.
import { useEffect, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { api } from "@/lib/api"
import { useCan } from "@/lib/permissions"
import { relativeTime } from "@/lib/time"
import type { PageCapture } from "@/lib/organizations"
import { DECIDE, errorDetail } from "@/components/OrgCandidateParts"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"

export function captureImageState(c: PageCapture): "available" | "pruned" | "omitted" | "none" {
  if (c.has_image) return "available"
  if (c.image_pruned_at) return "pruned"
  if (c.image_omitted_reason) return "omitted"
  return "none"
}

// Slice b adds archived snapshots as a second source.
export function captureSource(_c: PageCapture): "live" {
  return "live"
}

export async function loadCaptureImage(candidateId: string, captureId: string): Promise<string> {
  const b = await api.getBlob(`/organizations/candidates/${candidateId}/captures/${captureId}/image`)
  // A blob: URL is SAME-ORIGIN with the app, so its type decides what the browser
  // does with the bytes. Force image/webp client-side rather than trusting
  // whatever content-type the response carried (same reasoning as lib/evidence.ts).
  const blob = new Blob([await b.arrayBuffer()], { type: "image/webp" })
  return URL.createObjectURL(blob)
}

export function CaptureImage({ candidateId, captureId, domain }: { candidateId: string; captureId: string; domain: string }) {
  const [url, setUrl] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let cancelled = false
    let made: string | null = null
    loadCaptureImage(candidateId, captureId).then(
      u => {
        if (cancelled) { URL.revokeObjectURL(u); return }
        made = u
        setUrl(u)
      },
      () => { if (!cancelled) setFailed(true) },
    )
    return () => {
      cancelled = true
      if (made) URL.revokeObjectURL(made)
    }
  }, [candidateId, captureId])
  if (failed) return <p className="text-xs text-muted-foreground">Screenshot unavailable</p>
  if (!url) return <Skeleton className="h-40 w-full" />
  return <img src={url} alt={`Screenshot of ${domain}`} className="w-full rounded border" />
}

const STATUS_BADGE: Record<string, { variant: "secondary" | "success" | "outline"; label: string }> = {
  queued: { variant: "secondary", label: "Queued" },
  done: { variant: "success", label: "Done" },
  failed: { variant: "outline", label: "Failed" },
}

function hopText(h: unknown): string {
  if (h && typeof h === "object") {
    const o = h as { url?: unknown; status?: unknown }
    const url = typeof o.url === "string" ? o.url : ""
    const st = typeof o.status === "number" ? `${o.status} ` : ""
    if (url || st) return `${st}${url}`.trim()
  }
  return typeof h === "string" ? h : JSON.stringify(h)
}

function ScreenshotLine({ c, candidateId }: { c: PageCapture; candidateId: string }) {
  const [open, setOpen] = useState(false)
  const state = captureImageState(c)
  if (state === "available") {
    const kib = c.image_bytes != null ? Math.max(1, Math.round(c.image_bytes / 1024)) : null
    return (
      <details className="text-xs" onToggle={e => setOpen((e.currentTarget as HTMLDetailsElement).open)}>
        <summary className="cursor-pointer text-muted-foreground">
          {kib != null ? `Screenshot (${kib} KiB)` : "Screenshot (size unknown)"}
        </summary>
        {open && <div className="mt-1.5"><CaptureImage candidateId={candidateId} captureId={c.id} domain={c.domain} /></div>}
      </details>
    )
  }
  if (state === "pruned") {
    return <p className="text-xs text-muted-foreground">Screenshot file pruned {relativeTime(c.image_pruned_at!)}; capture details kept.</p>
  }
  if (state === "omitted") {
    return <p className="text-xs text-muted-foreground">Screenshot not stored: {c.image_omitted_reason}</p>
  }
  return c.status === "queued" ? null : <p className="text-xs text-muted-foreground">No screenshot</p>
}

export function CaptureList({ captures, candidateId }: { captures: PageCapture[]; candidateId: string }) {
  if (captures.length === 0) return <p className="text-xs text-muted-foreground">No captures yet.</p>
  return (
    <ul className="space-y-2">
      {captures.map(c => {
        const badge = STATUS_BADGE[c.status] ?? { variant: "outline" as const, label: c.status }
        const chain = c.redirect_chain ?? []
        return (
          <li key={c.id} className="rounded-md border p-2.5 space-y-1">
            <div className="flex items-center gap-2">
              <Badge variant={badge.variant}>{badge.label}</Badge>
              <Badge variant="outline">{captureSource(c) === "live" ? "Live" : ""}</Badge>
              <span className="text-xs text-muted-foreground" title={c.requested_at}>{relativeTime(c.requested_at)}</span>
            </div>
            {c.status === "failed" && (
              <p className="text-xs text-muted-foreground">
                {c.failure_reason}{c.error ? ` · ${c.error}` : ""}
              </p>
            )}
            {c.status === "done" && (
              <div className="space-y-1 text-xs">
                {c.title && <p className="text-sm">{c.title}</p>}
                <p className="break-all font-mono text-muted-foreground">
                  {c.requested_url}
                  {c.final_url && c.final_url !== c.requested_url && <> → {c.final_url}</>}
                </p>
                <p className="text-muted-foreground">
                  {c.http_status != null && <>HTTP {c.http_status} · </>}
                  {chain.length} redirect {chain.length === 1 ? "hop" : "hops"}
                  {c.pinned_ip && <> · pinned {c.pinned_ip}</>}
                </p>
                <p className="text-muted-foreground">
                  {c.request_count} requests via proxy{c.proxy_log_truncated && " (log truncated)"}
                </p>
                {chain.length > 0 && (
                  <details className="text-xs">
                    <summary className="cursor-pointer text-muted-foreground">Redirect chain</summary>
                    <ol className="mt-1 space-y-0.5 break-all font-mono">
                      {chain.map((h, i) => <li key={i}>{hopText(h)}</li>)}
                    </ol>
                  </details>
                )}
                {c.cert_san_dns && c.cert_san_dns.length > 0 && (
                  <details className="text-xs">
                    <summary className="cursor-pointer text-muted-foreground">Certificate names ({c.cert_san_dns.length})</summary>
                    <ul className="mt-1 space-y-0.5 break-all font-mono">
                      {c.cert_san_dns.map(n => <li key={n}>{n}</li>)}
                    </ul>
                  </details>
                )}
              </div>
            )}
            <ScreenshotLine c={c} candidateId={candidateId} />
          </li>
        )
      })}
    </ul>
  )
}

export function CandidateCaptures({ candidateId, candidateStatus }: { candidateId: string; candidateStatus: string }) {
  const can = useCan()
  const qc = useQueryClient()
  const key = ["candidate-captures", candidateId]
  const q = useQuery({
    queryKey: key,
    queryFn: () => api.get<PageCapture[]>(`/organizations/candidates/${candidateId}/captures`),
    refetchInterval: query => (query.state.data?.some(c => c.status === "queued") ? 5000 : false),
  })
  const m = useMutation({
    mutationFn: () => api.post<PageCapture>(`/organizations/candidates/${candidateId}/captures`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: key })
      toast.success("Capture queued")
    },
    onError: e => toast.error(errorDetail(e)),
  })
  const anyQueued = q.data?.some(c => c.status === "queued") ?? false
  const canCapture = can(DECIDE) && candidateStatus === "open"
  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">Page capture</h3>
        {canCapture && (
          <Button size="sm" variant="outline" disabled={m.isPending || anyQueued} onClick={() => m.mutate()}>
            Re-capture
          </Button>
        )}
      </div>
      {canCapture && (
        <p className="text-xs text-muted-foreground">Manual re-capture ignores the revisit window; posture rules still apply.</p>
      )}
      {q.isLoading ? <Skeleton className="h-16 w-full" />
        : q.isError ? <p className="text-xs text-muted-foreground">{errorDetail(q.error)}</p>
        : <CaptureList captures={q.data ?? []} candidateId={candidateId} />}
    </section>
  )
}
