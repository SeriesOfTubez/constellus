import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { GenerateControl } from "@/components/reports/GenerateControl"
import { ReportView } from "@/components/reports/ReportView"
import { api, ApiError, type Engagement } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import {
  canGenerateReports, downloadMarkdown, reportsApi,
  type ReportListItem, type ReportStatus,
} from "@/lib/reports"

const STATUS_BADGE: Record<ReportStatus, "default" | "secondary" | "destructive" | "outline"> = {
  queued: "outline",
  running: "secondary",
  done: "default",
  failed: "destructive",
}

function ReportSheet({ id, engagementName, canManage, onClose }: {
  id: string; engagementName: string; canManage: boolean; onClose: () => void
}) {
  const qc = useQueryClient()
  const { data: report, isLoading, isError } = useQuery({
    queryKey: ["report", id],
    queryFn: () => reportsApi.get(id),
    refetchInterval: q => {
      const s = q.state.data?.status
      return s === "queued" || s === "running" ? 3000 : false
    },
  })
  const del = useMutation({
    mutationFn: () => reportsApi.remove(id),
    onSuccess: () => {
      toast.success("Report deleted")
      qc.invalidateQueries({ queryKey: ["reports"] })
      onClose()
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to delete report"),
  })

  return (
    <Sheet open onOpenChange={o => !o && onClose()}>
      <SheetContent className="w-[640px] sm:max-w-[640px] overflow-y-auto">
        <SheetHeader><SheetTitle className="sr-only">Report</SheetTitle></SheetHeader>
        {isLoading && <Skeleton className="h-40 w-full" />}
        {isError && <p className="text-sm text-destructive">Could not load this report.</p>}
        {report && (
          <ReportView
            report={report}
            engagementName={engagementName}
            onDownload={() =>
              downloadMarkdown(report.id).catch(() => toast.error("Download failed"))}
            onDelete={canManage ? () => {
              if (window.confirm("Delete this report? This cannot be undone.")) del.mutate()
            } : undefined}
          />
        )}
      </SheetContent>
    </Sheet>
  )
}

export default function Reports() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const canManage = canGenerateReports(user?.role)
  const [chosen, setChosen] = useState<string>("")
  const [openId, setOpenId] = useState<string | null>(null)
  const [genError, setGenError] = useState<string | null>(null)

  const { data: engagements, isLoading: engLoading } = useQuery({
    queryKey: ["engagements"],
    queryFn: () => api.get<Engagement[]>("/engagements/"),
  })
  const engagementId = chosen || engagements?.[0]?.id || ""
  const engagementName = engagements?.find(e => e.id === engagementId)?.name ?? ""

  const { data: reports, isLoading } = useQuery({
    queryKey: ["reports", engagementId],
    queryFn: () => reportsApi.list(engagementId),
    enabled: !!engagementId,
    refetchInterval: q =>
      (q.state.data ?? []).some(r => r.status === "queued" || r.status === "running") ? 3000 : false,
  })
  const busy = (reports ?? []).some(r => r.status === "queued" || r.status === "running")

  const generate = useMutation({
    mutationFn: () => reportsApi.create(engagementId),
    onMutate: () => setGenError(null),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports", engagementId] }),
    onError: (e: unknown) => setGenError(
      e instanceof ApiError && e.message ? e.message : "Could not start the report."),
  })

  return (
    <div className="p-6 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Reports</h1>
        <div className="flex items-center gap-3">
          {!!engagements?.length && (
            <Select value={engagementId} onValueChange={v => { setChosen(v); setGenError(null) }}>
              <SelectTrigger className="w-64"><SelectValue placeholder="Engagement" /></SelectTrigger>
              <SelectContent>
                {engagements.map(e => <SelectItem key={e.id} value={e.id}>{e.name}</SelectItem>)}
              </SelectContent>
            </Select>
          )}
          {!!engagementId && (
            <GenerateControl role={user?.role} busy={busy || generate.isPending} onClick={() => generate.mutate()} />
          )}
        </div>
      </div>

      {genError && <p className="text-sm text-destructive" role="alert">{genError}</p>}

      {engLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : !engagements?.length ? (
        <p className="text-sm text-muted-foreground">No engagements yet</p>
      ) : isLoading ? (
        <Skeleton className="h-24 w-full" />
      ) : !reports?.length ? (
        <p className="text-sm text-muted-foreground">No reports recorded for this engagement.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Created</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Statements kept / dropped</TableHead>
              <TableHead className="text-right">Cost</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {reports.map((r: ReportListItem) => (
              <TableRow key={r.id} className="cursor-pointer" onClick={() => setOpenId(r.id)}>
                <TableCell>{new Date(r.created_at).toLocaleString()}</TableCell>
                <TableCell><Badge variant={STATUS_BADGE[r.status]}>{r.status}</Badge></TableCell>
                <TableCell>{r.statements_returned} / {r.statements_dropped}</TableCell>
                <TableCell className="text-right tabular-nums">
                  {r.cost_usd != null ? `$${r.cost_usd.toFixed(4)}` : "-"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {openId && (
        <ReportSheet id={openId} engagementName={engagementName} canManage={canManage} onClose={() => setOpenId(null)} />
      )}
    </div>
  )
}
