import { useState } from "react"
import { Link, useParams, useNavigate } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ChevronLeft, ShieldCheck, RefreshCw, Trash2, SquareArrowOutUpRight } from "lucide-react"

import { ConnectedEntities } from "@/components/ConnectedEntities"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type AggressivenessTier, type Engagement, type Target } from "@/lib/api"
import { displayName } from "@/lib/apex"
import { relativeTime, relativeFuture } from "@/lib/time"

const POSTURE_LABEL: Record<string, string> = {
  pre_close: "Pre-close",
  day_0: "Day 0",
  integrated: "Integrated",
  abandoned: "Abandoned",
}
// A target's own engagement is never `abandoned`-eligible to ATTACH to
// (the API 409s it — engagements.py: "abandoned is terminal, nothing
// joins it"), so the picker excludes it. Detaching FROM one is still
// allowed (it just widens, like any other restricting-posture detach).
const RESTRICTING_POSTURES = new Set(["pre_close", "abandoned"])

const TIER_LABEL: Record<AggressivenessTier, string> = {
  stealth: "Stealth",
  polite: "Polite",
  standard: "Standard",
  aggressive: "Aggressive",
}
const TIERS: AggressivenessTier[] = ["stealth", "polite", "standard", "aggressive"]
const INHERIT_VALUE = "__inherit__"

const TYPE_COLOR: Record<Target["type"], string> = {
  domain: "bg-blue-500/10 text-blue-600 dark:text-blue-400",
  ip:     "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  cidr:   "bg-amber-500/10 text-amber-700 dark:text-amber-400",
}

function TypeBadge({ type }: { type: Target["type"] }) {
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase ${TYPE_COLOR[type]}`}>
      {type}
    </span>
  )
}

function sourceLabel(target: Target): string {
  if (target.connector_id) return target.connector_id
  if (target.verification_method === "txt_record") return "Manual (TXT-verified)"
  if (target.verification_method === "manual_acknowledgement") return "Manual (acknowledged)"
  return "Manual"
}

type EngagementPatchBody = { engagement_id?: string; clear_engagement?: boolean; authorisation_reference?: string }

/** planning#211 — "Mark as M&A (pre-close)" / detach / show-current-engagement
 * control. Kept deliberately small (#193's "dead simple" bar): a picker
 * dialog for attaching (existing non-abandoned engagement, or type a name
 * to create one), a single "Remove from engagement" action for detaching,
 * and — only when detaching WIDENS (the current engagement restricts) — an
 * inline reference field, since that's the one case the API actually
 * requires it for (422 otherwise, surfaced via `onUpdate`'s own error
 * handling in the caller). */
function EngagementControl({
  target,
  isPending,
  onUpdate,
}: {
  target: Target
  isPending: boolean
  onUpdate: (body: EngagementPatchBody) => void
}) {
  const [pickerOpen, setPickerOpen] = useState(false)
  const [pickerMode, setPickerMode] = useState<"existing" | "new">("existing")
  const [pickedId, setPickedId] = useState("")
  const [newName, setNewName] = useState("")
  const [detachRef, setDetachRef] = useState("")
  const [detachOpen, setDetachOpen] = useState(false)
  const qc = useQueryClient()

  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: () => api.get<Engagement[]>("/engagements/"),
    enabled: pickerOpen,
  })
  const attachable = (engagements ?? []).filter(e => e.posture !== "abandoned" && e.id !== target.engagement?.id)

  const createMutation = useMutation({
    mutationFn: (name: string) => api.post<Engagement>("/engagements/", { name }),
    onSuccess: (created) => {
      qc.invalidateQueries({ queryKey: ["engagements"] })
      onUpdate({ engagement_id: created.id })
      setPickerOpen(false)
      setNewName("")
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to create engagement"),
  })

  const widensToDetach = !!target.engagement && RESTRICTING_POSTURES.has(target.engagement.posture)

  const pickedEngagement = attachable.find(e => e.id === pickedId)
  const confirmLabel =
    pickerMode === "new"
      ? "Create and mark as pre-close"
      : !pickedEngagement
        ? "Add to engagement"
        : pickedEngagement.posture === "pre_close"
          ? "Mark as pre-close"
          : `Add to ${POSTURE_LABEL[pickedEngagement.posture] ?? pickedEngagement.posture} engagement`

  function attach() {
    if (pickerMode === "existing") {
      if (!pickedId) return
      onUpdate({ engagement_id: pickedId })
      setPickerOpen(false)
      setPickedId("")
    } else {
      if (!newName.trim()) return
      createMutation.mutate(newName.trim())
    }
  }

  function detach() {
    if (widensToDetach) {
      if (!detachRef.trim()) return
      onUpdate({ clear_engagement: true, authorisation_reference: detachRef.trim() })
      setDetachOpen(false)
      setDetachRef("")
    } else {
      onUpdate({ clear_engagement: true })
    }
  }

  if (target.engagement) {
    return (
      <div className="space-y-1.5">
        <div className="flex items-center gap-2 h-8">
          <Link
            to={`/admin/engagements/${target.engagement.id}`}
            className="inline-flex items-center gap-1 font-medium hover:underline group"
          >
            {target.engagement.name}
            <SquareArrowOutUpRight className="h-3 w-3 text-muted-foreground group-hover:text-primary transition-colors" />
          </Link>
          <Badge variant="outline">{POSTURE_LABEL[target.engagement.posture] ?? target.engagement.posture}</Badge>
        </div>
        {widensToDetach ? (
          <Button size="sm" variant="outline" disabled={isPending} onClick={() => setDetachOpen(true)}>
            Remove from engagement
          </Button>
        ) : (
          <Button size="sm" variant="outline" disabled={isPending} onClick={detach}>
            Remove from engagement
          </Button>
        )}

        <Dialog open={detachOpen} onOpenChange={setDetachOpen}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Remove from {target.engagement.name}</DialogTitle>
              <DialogDescription>
                This target's engagement currently restricts traffic to passive-only. Removing it widens what this
                system may do — an authorisation reference is required.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-1.5 py-1">
              <Label className="text-sm">Authorisation reference</Label>
              <Input
                value={detachRef}
                onChange={e => setDetachRef(e.target.value)}
                placeholder="e.g. link to the authorising document"
                autoFocus
              />
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDetachOpen(false)}>Cancel</Button>
              <Button disabled={!detachRef.trim() || isPending} onClick={detach}>Remove</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    )
  }

  return (
    <div className="h-8 flex items-center">
      <Button size="sm" variant="outline" disabled={isPending} onClick={() => setPickerOpen(true)}>
        Add to M&A engagement
      </Button>

      <Dialog open={pickerOpen} onOpenChange={setPickerOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add to M&A engagement</DialogTitle>
            <DialogDescription>
              Choose an existing engagement, or create a new one. New engagements start in pre-close and restrict
              all active probing and DNS enumeration until authorised further.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex gap-2 text-sm">
              <Button size="sm" variant={pickerMode === "existing" ? "default" : "outline"} onClick={() => setPickerMode("existing")}>
                Existing
              </Button>
              <Button size="sm" variant={pickerMode === "new" ? "default" : "outline"} onClick={() => setPickerMode("new")}>
                New
              </Button>
            </div>
            {pickerMode === "existing" ? (
              <Select value={pickedId} onValueChange={setPickedId}>
                <SelectTrigger className="h-8 text-sm w-full">
                  <SelectValue placeholder={attachable.length ? "Choose an engagement" : "No engagements yet"} />
                </SelectTrigger>
                <SelectContent>
                  {attachable.map(e => (
                    <SelectItem key={e.id} value={e.id}>
                      {e.name} ({POSTURE_LABEL[e.posture] ?? e.posture})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            ) : (
              <Input
                placeholder="Engagement name"
                value={newName}
                onChange={e => setNewName(e.target.value)}
                autoFocus
              />
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPickerOpen(false)}>Cancel</Button>
            <Button
              disabled={isPending || createMutation.isPending || (pickerMode === "existing" ? !pickedId : !newName.trim())}
              onClick={attach}
            >
              {confirmLabel}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

export default function TargetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()

  const { data: target, isLoading, isError } = useQuery({
    queryKey: ["target-detail", id],
    queryFn: () => api.get<Target>(`/targets/${id}`),
    enabled: !!id,
  })

  const verifyMutation = useMutation({
    mutationFn: () => api.post(`/targets/${id}/verify`),
    onSuccess: () => {
      toast.success("Target verified")
      qc.invalidateQueries({ queryKey: ["target-detail", id] })
      qc.invalidateQueries({ queryKey: ["targets"] })
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Verification failed"),
  })

  const recheckMutation = useMutation({
    mutationFn: () => api.post("/targets/bulk/recheck", { target_ids: [id] }),
    onSuccess: () => {
      toast.success("Recheck queued")
      qc.invalidateQueries({ queryKey: ["scans"] })
    },
    onError: () => toast.error("Failed to queue recheck"),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/targets/${id}`),
    onSuccess: () => {
      toast.success("Target removed")
      qc.invalidateQueries({ queryKey: ["targets"] })
      navigate("/admin/targets")
    },
    onError: () => toast.error("Failed to remove target"),
  })

  const aggressivenessMutation = useMutation({
    mutationFn: (next: AggressivenessTier | null) =>
      api.patch(`/targets/${id}`, next === null
        ? { clear_aggressiveness: true }
        : { aggressiveness: next }),
    onSuccess: () => {
      toast.success("Aggressiveness updated")
      qc.invalidateQueries({ queryKey: ["target-detail", id] })
      qc.invalidateQueries({ queryKey: ["targets"] })
    },
    onError: () => toast.error("Failed to update aggressiveness"),
  })

  // planning#211 — engagement membership. Mirrors aggressivenessMutation
  // above: same endpoint, same invalidation pair. Errors surface the API's
  // own text (403 "requires ADMIN" / 422 "authorisation_reference is
  // required" / 409 "abandoned") rather than a generic message, since
  // those are the actual reasons an operator needs to see.
  const engagementMutation = useMutation({
    mutationFn: (body: { engagement_id?: string; clear_engagement?: boolean; authorisation_reference?: string }) =>
      api.patch(`/targets/${id}`, body),
    onSuccess: () => {
      toast.success("Engagement membership updated")
      qc.invalidateQueries({ queryKey: ["target-detail", id] })
      qc.invalidateQueries({ queryKey: ["targets"] })
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to update engagement membership"),
  })

  if (isLoading) return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-4">
      <Skeleton className="h-6 w-32" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-64 w-full" />
    </div>
  )

  if (isError || !target) return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-4">
      <Link to="/admin/targets" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="h-4 w-4" />Targets
      </Link>
      <div className="rounded-md border bg-card p-6 text-sm text-muted-foreground">
        Target not found.
      </div>
    </div>
  )

  const isMutating = verifyMutation.isPending || recheckMutation.isPending || deleteMutation.isPending

  return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-6">
      <Link to="/admin/targets" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="h-4 w-4" />Targets
      </Link>

      {/* Header */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 flex-wrap">
          <TypeBadge type={target.type} />
          {target.verified ? (
            <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
              <ShieldCheck className="h-3 w-3" />verified
            </span>
          ) : (
            <span className="inline-flex items-center rounded bg-amber-500/15 px-1.5 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-400">
              unverified
            </span>
          )}
          {target.passive_only && <Badge variant="warning">Passive-only</Badge>}
        </div>
        <h1 className="font-mono text-xl break-all leading-tight" title={target.value}>{displayName(target.value)}</h1>

        {/* Action bar */}
        <div className="flex flex-wrap gap-2 pt-1">
          {target.type === "domain" && !target.verified && (
            <Button size="sm" variant="outline" disabled={isMutating} onClick={() => verifyMutation.mutate()}>
              <ShieldCheck className="h-3.5 w-3.5 mr-1.5" />Verify TXT
            </Button>
          )}
          <Button size="sm" variant="outline" disabled={isMutating} onClick={() => recheckMutation.mutate()}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />Recheck
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={isMutating}
            onClick={() => {
              if (confirm(`Remove target ${displayName(target.value)}? Assets only this target referenced will be removed. Assets shared with other targets are kept.`)) {
                deleteMutation.mutate()
              }
            }}
            className="text-destructive hover:text-destructive hover:bg-destructive/10"
          >
            <Trash2 className="h-3.5 w-3.5 mr-1.5" />Remove
          </Button>
        </div>
      </div>

      <Separator />

      {/* Metadata grid */}
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div className="space-y-0.5">
          <p className="text-xs text-muted-foreground">Source</p>
          <p>{sourceLabel(target)}</p>
        </div>
        <div className="space-y-0.5">
          <p className="text-xs text-muted-foreground">Added</p>
          <p>
            {new Date(target.created_at).toLocaleString()}
            <span className="text-muted-foreground"> · {relativeTime(target.created_at)}</span>
          </p>
        </div>
        <div className="space-y-0.5">
          <p className="text-xs text-muted-foreground">Last scanned</p>
          <p title={target.last_scanned_at ? new Date(target.last_scanned_at).toLocaleString() : undefined}>
            {target.last_scanned_at ? relativeTime(target.last_scanned_at) : "never"}
          </p>
        </div>
        <div className="space-y-0.5">
          <p className="text-xs text-muted-foreground">Next scan</p>
          <p title={target.next_scan_at ? new Date(target.next_scan_at).toLocaleString() : undefined}>
            {target.next_scan_at ? relativeFuture(target.next_scan_at) : "—"}
          </p>
        </div>
        {target.verified_at && (
          <div className="space-y-0.5">
            <p className="text-xs text-muted-foreground">Verified at</p>
            <p>{new Date(target.verified_at).toLocaleString()}</p>
          </div>
        )}
        {target.verification_method && (
          <div className="space-y-0.5">
            <p className="text-xs text-muted-foreground">Verification</p>
            <p className="capitalize">{target.verification_method.replace(/_/g, " ")}</p>
          </div>
        )}
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">Aggressiveness</p>
          <Select
            value={target.aggressiveness ?? INHERIT_VALUE}
            onValueChange={(v) =>
              aggressivenessMutation.mutate(v === INHERIT_VALUE ? null : (v as AggressivenessTier))
            }
            disabled={aggressivenessMutation.isPending}
          >
            <SelectTrigger className="h-8 text-sm w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={INHERIT_VALUE}>
                Inherit (currently {TIER_LABEL[target.effective_aggressiveness]})
              </SelectItem>
              {TIERS.map(t => (
                <SelectItem key={t} value={t}>{TIER_LABEL[t]}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="col-span-2 space-y-1">
          <p className="text-xs text-muted-foreground">Engagement</p>
          <EngagementControl
            target={target}
            isPending={engagementMutation.isPending}
            onUpdate={(body) => engagementMutation.mutate(body)}
          />
        </div>
        {target.notes && (
          <div className="col-span-2 space-y-0.5">
            <p className="text-xs text-muted-foreground">Notes</p>
            <p>{target.notes}</p>
          </div>
        )}
      </div>

      {/* WHOIS */}
      {(target.whois_org || target.whois_asn) && (
        <>
          <Separator />
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">WHOIS</p>
            <div className="rounded-md border divide-y text-sm">
              {target.whois_org && (
                <div className="flex items-start gap-3 px-3 py-2">
                  <span className="text-muted-foreground shrink-0 w-28">Organisation</span>
                  <span className="text-foreground break-all">{target.whois_org}</span>
                </div>
              )}
              {target.whois_asn && (
                <div className="flex items-start gap-3 px-3 py-2">
                  <span className="text-muted-foreground shrink-0 w-28">ASN</span>
                  <span className="font-mono text-foreground">{target.whois_asn}</span>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* TXT verification helper (when domain target is still pending) */}
      {target.type === "domain" && !target.verified && (
        <>
          <Separator />
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">TXT verification</p>
            <p className="text-sm text-muted-foreground">
              Add this TXT record to <span className="font-mono text-foreground">_constellus-verify.{target.value}</span> and press
              <span className="font-medium text-foreground"> Verify TXT</span> above.
            </p>
            <pre className="text-xs font-mono bg-muted rounded px-3 py-2 break-all">{target.token}</pre>
          </div>
        </>
      )}

      <Separator />

      {/* Connected entities */}
      <ConnectedEntities nodeType="target" nodeId={target.id} />
    </div>
  )
}
