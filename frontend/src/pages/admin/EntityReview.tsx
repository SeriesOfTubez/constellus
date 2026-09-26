import { useMemo } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Check, GitBranch, Loader2, SquareArrowOutUpRight, X } from "lucide-react"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type EntityRelationQueueItem, type OrgEntity } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { openEvidence } from "@/lib/evidence"

const RELATION_LABEL: Record<string, string> = {
  acquired: "acquired",
  subsidiary_of: "subsidiary of",
  dba: "d/b/a",
  formerly_named: "formerly named",
}

export default function EntityReview() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.role === "admin"

  const { data: relations, isLoading } = useQuery({
    queryKey: ["entity-relations", "proposed"],
    queryFn: () => api.get<EntityRelationQueueItem[]>("/entities/relations?status=proposed"),
  })

  const { data: entities } = useQuery({
    queryKey: ["entities"],
    queryFn: () => api.get<OrgEntity[]>("/entities/"),
  })

  const nameById = useMemo(() => {
    const m = new Map<string, string>()
    for (const e of entities ?? []) m.set(e.id, e.legal_name)
    return m
  }, [entities])

  const decisionMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: "confirmed" | "rejected" }) =>
      api.post(`/entities/relations/${id}/decision`, { status }),
    onSuccess: () => {
      toast.success("Decision recorded")
      qc.invalidateQueries({ queryKey: ["entity-relations"] })
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to record decision"),
  })

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <AdminBreadcrumb page="Entity Review" />
      <div>
        <h1 className="text-2xl font-semibold">Entity Review</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Proposed corporate-entity relationships awaiting a decision. An AI-sourced ("AI" badge)
          relation can never auto-confirm — it always lands here.
        </p>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
      ) : !relations?.length ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <GitBranch className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">Nothing awaiting review</p>
          <p className="text-sm mt-1">Proposed relationships from any source will appear here.</p>
        </div>
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Subject</TableHead>
                <TableHead>Relation</TableHead>
                <TableHead>Object</TableHead>
                <TableHead>Event date</TableHead>
                <TableHead>Observer</TableHead>
                <TableHead>Quote</TableHead>
                <TableHead>Evidence</TableHead>
                {isAdmin && <TableHead className="w-32">Decision</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {relations.map(r => (
                <TableRow key={r.id}>
                  <TableCell className="font-medium">{nameById.get(r.subject_id) ?? r.subject_id}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{RELATION_LABEL[r.relation] ?? r.relation}</TableCell>
                  <TableCell className="font-medium">{nameById.get(r.object_id) ?? r.object_id}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {r.event_date ?? "—"} {r.event_date_precision !== "unknown" && `(${r.event_date_precision})`}
                  </TableCell>
                  <TableCell>
                    <span className="text-sm">{r.observer_name ?? "—"}</span>
                    {r.observer_trust === "inferred" && (
                      <Badge variant="outline" className="ml-1.5">AI</Badge>
                    )}
                  </TableCell>
                  <TableCell className="max-w-xs truncate text-xs text-muted-foreground" title={r.quote}>
                    {r.quote}
                  </TableCell>
                  <TableCell>
                    <button
                      onClick={() => openEvidence(r.evidence_id)}
                      className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-primary transition-colors"
                      title="Open evidence"
                    >
                      <SquareArrowOutUpRight className="h-3.5 w-3.5" />
                    </button>
                  </TableCell>
                  {isAdmin && (
                    <TableCell>
                      <div className="flex gap-1">
                        <Button
                          size="sm" variant="outline"
                          disabled={decisionMutation.isPending}
                          onClick={() => decisionMutation.mutate({ id: r.id, status: "confirmed" })}
                          title="Confirm"
                        >
                          {decisionMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
                        </Button>
                        <Button
                          size="sm" variant="outline"
                          disabled={decisionMutation.isPending}
                          onClick={() => decisionMutation.mutate({ id: r.id, status: "rejected" })}
                          title="Reject"
                        >
                          <X className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  )
}
