import { useState } from "react"
import { Link, useParams, useNavigate } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ChevronLeft, Loader2, SquareArrowOutUpRight, Trash2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Engagement } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { displayName } from "@/lib/apex"

const POSTURE_LABEL: Record<string, string> = {
  pre_close: "Pre-close",
  day_0: "Day 0",
  integrated: "Integrated",
  abandoned: "Abandoned",
}

// The legal moves from each posture (mirrors backend/app/api/engagements.py's
// `_TRANSITIONS` — the server is the single source of truth and refuses
// anything not shown here; this list only decides which buttons render).
const LEGAL_MOVES: Record<string, string[]> = {
  pre_close: ["day_0", "abandoned"],
  day_0: ["pre_close", "integrated", "abandoned"],
  integrated: ["pre_close", "abandoned"],
  abandoned: [],
}
// Moves that need an authorisation reference (the widening transition).
const NEEDS_REF = new Set(["pre_close->day_0"])

export default function EngagementDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.role === "admin"

  const [transitionTo, setTransitionTo] = useState<string | null>(null)
  const [reference, setReference] = useState("")
  const [deleteOpen, setDeleteOpen] = useState(false)

  const { data: engagement, isLoading, isError } = useQuery({
    queryKey: ["engagement-detail", id],
    queryFn: () => api.get<Engagement>(`/engagements/${id}`),
    enabled: !!id,
  })

  const transitionMutation = useMutation({
    mutationFn: (body: { to: string; authorisation_reference?: string }) =>
      api.post<Engagement>(`/engagements/${id}/transition`, body),
    onSuccess: () => {
      toast.success("Posture updated")
      qc.invalidateQueries({ queryKey: ["engagement-detail", id] })
      qc.invalidateQueries({ queryKey: ["engagements"] })
      setTransitionTo(null)
      setReference("")
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Transition failed"),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/engagements/${id}`),
    onSuccess: () => {
      toast.success("Engagement removed")
      qc.invalidateQueries({ queryKey: ["engagements"] })
      navigate("/admin/engagements")
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to remove engagement"),
  })

  if (isLoading) return (
    <div className="max-w-3xl mx-auto px-6 py-8 space-y-4">
      <Skeleton className="h-6 w-32" />
      <Skeleton className="h-24 w-full" />
    </div>
  )

  if (isError || !engagement) return (
    <div className="max-w-3xl mx-auto px-6 py-8 space-y-4">
      <Link to="/admin/engagements" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="h-4 w-4" />Engagements
      </Link>
      <div className="rounded-md border bg-card p-6 text-sm text-muted-foreground">Engagement not found.</div>
    </div>
  )

  function requestTransition(to: string) {
    const key = `${engagement!.posture}->${to}`
    if (NEEDS_REF.has(key)) {
      setTransitionTo(to)
    } else {
      transitionMutation.mutate({ to })
    }
  }

  return (
    <div className="max-w-3xl mx-auto px-6 py-8 space-y-6">
      <Link to="/admin/engagements" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="h-4 w-4" />Engagements
      </Link>

      <div className="space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="outline">{POSTURE_LABEL[engagement.posture] ?? engagement.posture}</Badge>
        </div>
        <h1 className="text-xl font-semibold break-all">{engagement.name}</h1>
      </div>

      {isAdmin && (
        <div className="flex flex-wrap gap-2">
          {LEGAL_MOVES[engagement.posture].map(to => (
            <Button
              key={to}
              size="sm"
              variant="outline"
              disabled={transitionMutation.isPending}
              onClick={() => requestTransition(to)}
            >
              Move to {POSTURE_LABEL[to] ?? to}
            </Button>
          ))}
          <Button
            size="sm"
            variant="outline"
            className="text-destructive hover:text-destructive hover:bg-destructive/10"
            disabled={deleteMutation.isPending || engagement.member_targets.length > 0}
            title={engagement.member_targets.length > 0 ? "Detach member targets first" : undefined}
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="h-3.5 w-3.5 mr-1.5" />Remove
          </Button>
        </div>
      )}

      <Separator />

      <div className="grid grid-cols-2 gap-4 text-sm">
        <div className="space-y-0.5">
          <p className="text-xs text-muted-foreground">Posture changed</p>
          <p>{new Date(engagement.posture_changed_at).toLocaleString()}</p>
        </div>
        <div className="space-y-0.5">
          <p className="text-xs text-muted-foreground">Created</p>
          <p>{new Date(engagement.created_at).toLocaleString()}</p>
        </div>
        <div className="col-span-2 space-y-0.5">
          <p className="text-xs text-muted-foreground">Authorisation record</p>
          {engagement.authorised_at ? (
            <p>
              {engagement.authorised_by ?? "unknown"} on {new Date(engagement.authorised_at).toLocaleString()}
              {engagement.authorisation_reference && (
                <span className="block text-muted-foreground mt-0.5 break-all">
                  {engagement.authorisation_reference}
                </span>
              )}
            </p>
          ) : (
            <p className="text-muted-foreground">Not authorised — posture restricts traffic to passive-only.</p>
          )}
        </div>
      </div>

      <Separator />

      <div className="space-y-2">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Member targets ({engagement.member_targets.length})
        </p>
        {engagement.member_targets.length === 0 ? (
          <p className="text-sm text-muted-foreground">No targets linked yet.</p>
        ) : (
          <div className="rounded-md border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Value</TableHead>
                  <TableHead className="w-20">Type</TableHead>
                  <TableHead className="w-10" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {engagement.member_targets.map(t => (
                  <TableRow key={t.id}>
                    <TableCell className="font-mono text-sm">{displayName(t.value)}</TableCell>
                    <TableCell className="text-xs uppercase text-muted-foreground">{t.type}</TableCell>
                    <TableCell>
                      <Link
                        to={`/targets/${t.id}`}
                        className="inline-flex items-center text-muted-foreground hover:text-primary transition-colors"
                        title="Open full view"
                      >
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

      {/* Widening-transition reference dialog */}
      <Dialog open={transitionTo !== null} onOpenChange={(o) => !o && setTransitionTo(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Move to {transitionTo ? (POSTURE_LABEL[transitionTo] ?? transitionTo) : ""}</DialogTitle>
            <DialogDescription>
              This widens traffic beyond passive-only. An authorisation reference is required.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5 py-1">
            <Label className="text-sm">Authorisation reference</Label>
            <Input
              value={reference}
              onChange={e => setReference(e.target.value)}
              placeholder="e.g. link to the authorising document"
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTransitionTo(null)}>Cancel</Button>
            <Button
              disabled={!reference.trim() || transitionMutation.isPending}
              onClick={() => transitionMutation.mutate({ to: transitionTo!, authorisation_reference: reference.trim() })}
            >
              {transitionMutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-destructive">Remove {engagement.name}</DialogTitle>
            <DialogDescription>This cannot be undone.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteOpen(false)}>Cancel</Button>
            <Button variant="destructive" disabled={deleteMutation.isPending} onClick={() => deleteMutation.mutate()}>
              {deleteMutation.isPending
                ? <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
                : <Trash2 className="h-4 w-4 mr-1.5" />}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
