import { useState, type MouseEvent } from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Undo2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { api } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import {
  ENVS, ENV_LABELS, KINDS, KIND_LABELS,
  type Env, type Kind, type WebEndpointState,
} from "@/lib/webClassification"

const REASON_MAX = 500

/** Admin-only correction controls. Gated on role === "admin" exactly: the
 *  backend refuses everyone else, and integration_admin (who passes
 *  canMutate) must not be offered a control that would 403. */
export function WebClassificationControls({ assetId, state }: { assetId: string; state: WebEndpointState }) {
  const user = useAuthStore(s => s.user)
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)

  const currentKind: Kind = state.source === "none" || !state.kind ? "application" : state.kind
  const currentEnv: Env = state.source === "none" || !state.environment ? "unknown" : state.environment
  const [kind, setKind] = useState<Kind>(currentKind)
  const [env, setEnv] = useState<Env>(currentEnv)
  const [reason, setReason] = useState("")

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["web-classifications"] })
    qc.invalidateQueries({ queryKey: ["web-endpoints"] })
  }
  const base = `/assets/${assetId}/web-endpoints/${state.port}/classification`

  const save = useMutation({
    mutationFn: () => api.put<WebEndpointState>(base, {
      kind, environment: env, ...(reason.trim() ? { reason: reason.trim() } : {}),
    }),
    onSuccess: () => {
      toast.success("Classification corrected")
      setOpen(false)
      invalidate()
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const revert = useMutation({
    mutationFn: () => api.delete<WebEndpointState>(base),
    onSuccess: () => {
      toast.success("Correction removed")
      invalidate()
    },
    onError: (e: Error) => toast.error(e.message),
  })

  if (user?.role !== "admin") return null

  function openDialog(e: MouseEvent) {
    e.stopPropagation()
    setKind(currentKind)
    setEnv(currentEnv)
    setReason(state.override?.reason ?? "")
    setOpen(true)
  }

  return (
    <span className="inline-flex items-center gap-1" onClick={e => e.stopPropagation()}>
      <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={openDialog}>
        Wrong? Correct it
      </Button>
      {state.source === "user" && (
        <Button
          variant="ghost" size="sm" className="h-6 text-xs gap-1"
          disabled={revert.isPending}
          onClick={e => { e.stopPropagation(); revert.mutate() }}
        >
          <Undo2 className="h-3 w-3" />Revert to AI
        </Button>
      )}
      <Dialog open={open} onOpenChange={setOpen}>
        {/* Portaled content still bubbles React events to the clickable row. */}
        <DialogContent className="sm:max-w-md" onClick={e => e.stopPropagation()}>
          <DialogHeader>
            <DialogTitle>Correct classification (port {state.port})</DialogTitle>
            <DialogDescription>
              Your value replaces the AI's until you remove it.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {state.ai_suggests && (
              <Button
                variant="outline" size="sm" className="h-7 text-xs"
                onClick={e => {
                  e.stopPropagation()
                  setKind(state.ai_suggests!.kind)
                  setEnv(state.ai_suggests!.environment)
                }}
              >
                Use AI's value
              </Button>
            )}
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Kind</Label>
              <Select value={kind} onValueChange={v => setKind(v as Kind)}>
                <SelectTrigger className="h-9 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {KINDS.map(k => <SelectItem key={k} value={k}>{KIND_LABELS[k]}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Environment</Label>
              <Select value={env} onValueChange={v => setEnv(v as Env)}>
                <SelectTrigger className="h-9 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ENVS.map(v => <SelectItem key={v} value={v}>{ENV_LABELS[v]}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label className="text-xs text-muted-foreground">Reason (optional)</Label>
              <Textarea
                maxLength={REASON_MAX}
                value={reason}
                onChange={e => setReason(e.target.value)}
                className="text-sm"
              />
              <p className="text-right text-[10px] text-muted-foreground tabular-nums">
                {reason.length}/{REASON_MAX}
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={e => { e.stopPropagation(); setOpen(false) }} disabled={save.isPending}>
              Cancel
            </Button>
            <Button onClick={e => { e.stopPropagation(); save.mutate() }} disabled={save.isPending}>
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </span>
  )
}
