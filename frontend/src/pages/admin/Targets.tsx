import { useEffect, useRef, useState } from "react"
import { Link } from "react-router-dom"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useFlyout } from "@/lib/flyout"
import { toast } from "sonner"
import { ShieldCheck, Plus, Trash2, Loader2, Globe, Server, Network, AlertTriangle, RefreshCw, Clock, Gauge } from "lucide-react"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { relativeTime, relativeFuture } from "@/lib/time"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Skeleton } from "@/components/ui/skeleton"
import { Label } from "@/components/ui/label"
import { api, type AggressivenessTier, type Target } from "@/lib/api"
import { displayName } from "@/lib/apex"
import { TagBadge } from "@/components/ui/tag-badge"
import { TagEditor } from "@/components/ui/tag-editor"
import { OverflowCell } from "@/components/ui/overflow-cell"

const TIER_LABEL: Record<AggressivenessTier, string> = {
  stealth: "Stealth",
  polite: "Polite",
  standard: "Standard",
  aggressive: "Aggressive",
}
const TIERS: AggressivenessTier[] = ["stealth", "polite", "standard", "aggressive"]

const TYPE_META: Record<Target["type"], { label: string; icon: React.ElementType; color: string }> = {
  domain: { label: "Domain", icon: Globe,   color: "bg-blue-500/10 text-blue-600 dark:text-blue-400" },
  ip:     { label: "IP",     icon: Server,  color: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" },
  cidr:   { label: "CIDR",   icon: Network, color: "bg-purple-500/10 text-purple-600 dark:text-purple-400" },
}

function TypeBadge({ type }: { type: Target["type"] }) {
  const { label, color } = TYPE_META[type]
  return <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${color}`}>{label}</span>
}

function TargetDeleteDialog({
  title,
  description,
  confirmPhrase,
  confirmLabel,
  onConfirm,
  onCancel,
  isPending,
}: {
  title: string
  description: React.ReactNode
  confirmPhrase: string
  confirmLabel: string
  onConfirm: () => void
  onCancel: () => void
  isPending: boolean
}) {
  const [typed, setTyped] = useState("")
  const isValid = typed === confirmPhrase

  return (
    <Dialog open onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-destructive">{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <div className="space-y-1.5 py-1">
          <Label className="text-sm">
            Type <span className="font-mono font-semibold">{confirmPhrase}</span> to acknowledge
          </Label>
          <Input
            value={typed}
            onChange={e => setTyped(e.target.value)}
            placeholder={confirmPhrase}
            className="font-mono"
            autoFocus
            onKeyDown={e => { if (e.key === "Enter" && isValid && !isPending) onConfirm() }}
          />
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={isPending}>Cancel</Button>
          <Button variant="destructive" disabled={!isValid || isPending} onClick={onConfirm}>
            {isPending
              ? <Loader2 className="h-4 w-4 animate-spin mr-1.5" />
              : <Trash2 className="h-4 w-4 mr-1.5" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function IndeterminateCheckbox({
  checked,
  indeterminate,
  onChange,
}: {
  checked: boolean
  indeterminate?: boolean
  onChange: (checked: boolean) => void
}) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = !!indeterminate
  }, [indeterminate])
  return (
    <input
      ref={ref}
      type="checkbox"
      checked={checked}
      onChange={e => onChange(e.target.checked)}
      className="h-4 w-4 rounded border border-border cursor-pointer accent-primary"
    />
  )
}

function sourceLabel(t: Target): string {
  if (t.connector_id) return `Connector: ${t.connector_id}`
  return "Manual"
}

function WhoisInfo({ target }: { target: Target }) {
  if (!target.whois_org && !target.whois_asn) return null
  return (
    <div className="rounded-md border bg-muted/40 p-3 text-xs space-y-1">
      <p className="font-medium text-muted-foreground">WHOIS</p>
      {target.whois_org && <div>Organisation: <span className="text-foreground">{target.whois_org}</span></div>}
      {target.whois_asn && <div>ASN: <span className="text-foreground font-mono">{target.whois_asn}</span></div>}
    </div>
  )
}

export default function Targets() {
  const qc = useQueryClient()
  const [addOpen, setAddOpen] = useState(false)
  const [newValue, setNewValue] = useState("")
  const [selectedIds, setSelectedIds] = useState(new Set<string>())
  const [pendingDelete, setPendingDelete] = useState<Target | null>(null)
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false)
  const { data: targets, isLoading } = useQuery({
    queryKey: ["targets"],
    queryFn: () => api.get<Target[]>("/targets/"),
  })

  const { data: monitoring } = useQuery({
    queryKey: ["monitoring-status"],
    queryFn: () => api.get<{
      last_run_at: string | null
      last_run_id: string | null
      next_run_at: string | null
    }>("/system/monitoring-status"),
    refetchInterval: 60_000,
  })

  const { selected: detailTarget, open: openTarget, close: closeTarget } = useFlyout(targets ?? [])

  const addMutation = useMutation({
    mutationFn: (value: string) => api.post<Target>("/targets/", { value }),
    onSuccess: (created) => {
      toast.success(`${created.value} added`)
      qc.invalidateQueries({ queryKey: ["targets"] })
      setAddOpen(false)
      setNewValue("")
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/targets/${id}`),
    onSuccess: () => {
      toast.success("Target removed")
      qc.invalidateQueries({ queryKey: ["targets"] })
      setPendingDelete(null)
      closeTarget()
    },
    onError: () => toast.error("Failed to remove target"),
  })

  const tagMutation = useMutation({
    mutationFn: ({ id, tags }: { id: string; tags: string[] }) =>
      api.patch(`/tags/targets/${id}`, { tags }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
    onError: () => toast.error("Failed to update tags"),
  })

  const bulkRecheckMutation = useMutation({
    mutationFn: (targetIds: string[]) =>
      api.post<{ scan_id: string; target_count: number }>("/targets/bulk/recheck", { target_ids: targetIds }),
    onSuccess: (r) => {
      toast.success(`Recheck queued for ${r.target_count} target${r.target_count !== 1 ? "s" : ""}`)
      setSelectedIds(new Set())
      qc.invalidateQueries({ queryKey: ["scans"] })
    },
    onError: () => toast.error("Failed to queue recheck"),
  })

  const bulkAggressivenessMutation = useMutation({
    mutationFn: ({ ids, tier }: { ids: string[]; tier: AggressivenessTier | null }) =>
      api.post<{ updated: number; aggressiveness: AggressivenessTier | null }>(
        "/targets/bulk/aggressiveness",
        tier === null
          ? { target_ids: ids, clear: true }
          : { target_ids: ids, aggressiveness: tier },
      ),
    onSuccess: (r) => {
      const label = r.aggressiveness ? TIER_LABEL[r.aggressiveness] : "Inherit"
      toast.success(`Aggressiveness set to ${label} on ${r.updated} target${r.updated !== 1 ? "s" : ""}`)
      setSelectedIds(new Set())
      qc.invalidateQueries({ queryKey: ["targets"] })
    },
    onError: () => toast.error("Failed to update aggressiveness"),
  })

  const bulkDeleteMutation = useMutation({
    mutationFn: (targetIds: string[]) =>
      api.delete<{ deleted: number }>("/targets/bulk", { target_ids: targetIds }),
    onSuccess: (r) => {
      toast.success(`${r.deleted} target${r.deleted !== 1 ? "s" : ""} removed`)
      setSelectedIds(new Set())
      setBulkDeleteOpen(false)
      qc.invalidateQueries({ queryKey: ["targets"] })
    },
    onError: () => toast.error("Failed to remove targets"),
  })

  function toggleOne(id: string, checked: boolean) {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (checked) next.add(id)
      else next.delete(id)
      return next
    })
  }

  function toggleAll(checked: boolean) {
    setSelectedIds(checked ? new Set((targets ?? []).map(t => t.id)) : new Set())
  }

  const allSelected = !!targets?.length && targets.every(t => selectedIds.has(t.id))
  const someSelected = !!targets?.some(t => selectedIds.has(t.id)) && !allSelected

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <AdminBreadcrumb page="Targets" />
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Targets</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Domains, IPs, and CIDRs in scope for monitoring.
          </p>
        </div>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />Add Target
        </Button>
      </div>

      {monitoring && (monitoring.last_run_at || monitoring.next_run_at) && (
        <div className="flex flex-wrap items-center gap-4 rounded-md border bg-muted/30 px-4 py-2 text-xs">
          <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
          <div>
            <span className="text-muted-foreground">Last monitoring run: </span>
            {monitoring.last_run_at && monitoring.last_run_id ? (
              <Link to={`/admin/activity?id=${monitoring.last_run_id}`} className="font-medium hover:underline">
                {relativeTime(monitoring.last_run_at)}
              </Link>
            ) : (
              <span className="font-medium">
                {monitoring.last_run_at ? relativeTime(monitoring.last_run_at) : "never"}
              </span>
            )}
          </div>
          <div>
            <span className="text-muted-foreground">Next: </span>
            <span className="font-medium">
              {monitoring.next_run_at ? relativeFuture(monitoring.next_run_at) : "—"}
            </span>
          </div>
        </div>
      )}

      {/* Bulk action bar */}
      {selectedIds.size > 0 && (
        <div className="flex items-center gap-3 rounded-md border bg-muted/40 px-4 py-2">
          <span className="text-sm font-medium">{selectedIds.size} selected</span>
          <div className="flex items-center gap-2 ml-auto">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button size="sm" variant="outline" disabled={bulkAggressivenessMutation.isPending}>
                  {bulkAggressivenessMutation.isPending
                    ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                    : <Gauge className="h-3.5 w-3.5 mr-1.5" />}
                  Set aggressiveness
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {TIERS.map(t => (
                  <DropdownMenuItem
                    key={t}
                    onClick={() => bulkAggressivenessMutation.mutate({ ids: [...selectedIds], tier: t })}
                  >
                    {TIER_LABEL[t]}
                  </DropdownMenuItem>
                ))}
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={() => bulkAggressivenessMutation.mutate({ ids: [...selectedIds], tier: null })}
                >
                  Inherit (clear override)
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <Button size="sm" variant="outline"
              disabled={bulkRecheckMutation.isPending}
              onClick={() => bulkRecheckMutation.mutate([...selectedIds])}>
              {bulkRecheckMutation.isPending
                ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
              Recheck
            </Button>
            <Button size="sm" variant="outline"
              className="text-destructive hover:text-destructive"
              disabled={bulkDeleteMutation.isPending}
              onClick={() => setBulkDeleteOpen(true)}>
              <Trash2 className="h-3.5 w-3.5 mr-1.5" />
              Remove
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelectedIds(new Set())}>
              Clear
            </Button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
      ) : !targets?.length ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <ShieldCheck className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">No targets yet</p>
          <p className="text-sm mt-1">Add a domain, IP, or CIDR — or configure a DNS connector to auto-populate.</p>
        </div>
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-10">
                  <IndeterminateCheckbox
                    checked={allSelected}
                    indeterminate={someSelected}
                    onChange={toggleAll}
                  />
                </TableHead>
                <TableHead className="w-24">Type</TableHead>
                <TableHead>Value</TableHead>
                <TableHead className="hidden md:table-cell">Source</TableHead>
                <TableHead className="hidden lg:table-cell">Last scanned</TableHead>
                <TableHead className="hidden lg:table-cell">Next scan</TableHead>
                <TableHead className="hidden xl:table-cell">Tags</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {targets.map(t => (
                <TableRow key={t.id}
                  className={`cursor-pointer ${selectedIds.has(t.id) ? "bg-muted/20" : ""}`}
                  onClick={() => openTarget(t)}>
                  <TableCell onClick={e => e.stopPropagation()}>
                    <IndeterminateCheckbox
                      checked={selectedIds.has(t.id)}
                      onChange={(checked) => toggleOne(t.id, checked)}
                    />
                  </TableCell>
                  <TableCell><TypeBadge type={t.type} /></TableCell>
                  <TableCell className="font-mono text-sm" title={t.value}>
                    <div className="flex items-center gap-2">
                      <span>{displayName(t.value)}</span>
                      {t.aggressiveness && (
                        <span
                          className="inline-flex items-center rounded-md border px-1.5 py-0 text-[10px] font-medium uppercase text-muted-foreground"
                          title={`Aggressiveness override: ${t.aggressiveness}`}
                        >
                          {t.aggressiveness}
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">
                    {sourceLabel(t)}
                  </TableCell>
                  <TableCell
                    className="hidden lg:table-cell text-xs text-muted-foreground"
                    title={t.last_scanned_at ? new Date(t.last_scanned_at).toLocaleString() : "Never scanned"}
                  >
                    {t.last_scanned_at ? relativeTime(t.last_scanned_at) : "never"}
                  </TableCell>
                  <TableCell
                    className="hidden lg:table-cell text-xs text-muted-foreground"
                    title={t.next_scan_at ? new Date(t.next_scan_at).toLocaleString() : "No schedule"}
                  >
                    {t.next_scan_at ? relativeFuture(t.next_scan_at) : "—"}
                  </TableCell>
                  <TableCell className="hidden xl:table-cell">
                    <OverflowCell
                      items={t.tags ?? []}
                      renderItem={(tag) => <TagBadge key={tag} tag={tag} />}
                      renderOverflowItem={(tag) => <TagBadge key={tag} tag={tag} />}
                      getLabel={(tag) => tag}
                      limit={2}
                    />
                  </TableCell>
                  <TableCell onClick={e => e.stopPropagation()}>
                    <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive"
                      disabled={deleteMutation.isPending}
                      onClick={() => setPendingDelete(t)}
                      title="Remove">
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Add target dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add Target</DialogTitle>
            <DialogDescription>Enter a domain, IP address, or CIDR block.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <Input
              placeholder="example.com, 1.2.3.4, or 1.2.3.0/24"
              value={newValue}
              onChange={e => setNewValue(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter" && newValue) addMutation.mutate(newValue) }}
              className="font-mono"
              autoFocus
            />
            <div className="flex items-start gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/5 px-3 py-2 text-xs text-yellow-700 dark:text-yellow-400">
              <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
              <p>Only add targets that you own or are authorised to scan and monitor.</p>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button disabled={!newValue || addMutation.isPending} onClick={() => addMutation.mutate(newValue)}>
              {addMutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Detail sheet */}
      {detailTarget && (
        <Sheet open onOpenChange={(o) => !o && closeTarget()}>
          <SheetContent className="w-[440px] sm:max-w-[440px] flex flex-col gap-0 p-0">
            <SheetHeader className="px-6 pt-6 pb-4 border-b space-y-2">
              <TypeBadge type={detailTarget.type} />
              <SheetTitle className="font-mono text-sm break-all" title={detailTarget.value}>{displayName(detailTarget.value)}</SheetTitle>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
              <div className="grid grid-cols-2 gap-4 text-xs">
                <div className="space-y-0.5">
                  <p className="text-muted-foreground">Source</p>
                  <p>{sourceLabel(detailTarget)}</p>
                </div>
                <div className="space-y-0.5">
                  <p className="text-muted-foreground">Added</p>
                  <p>{new Date(detailTarget.created_at).toLocaleString()}</p>
                </div>
                <div className="space-y-0.5">
                  <p className="text-muted-foreground">Last scanned</p>
                  <p title={detailTarget.last_scanned_at ? new Date(detailTarget.last_scanned_at).toLocaleString() : undefined}>
                    {detailTarget.last_scanned_at ? relativeTime(detailTarget.last_scanned_at) : "never"}
                  </p>
                </div>
                <div className="space-y-0.5">
                  <p className="text-muted-foreground">Next scan</p>
                  <p title={detailTarget.next_scan_at ? new Date(detailTarget.next_scan_at).toLocaleString() : undefined}>
                    {detailTarget.next_scan_at ? relativeFuture(detailTarget.next_scan_at) : "—"}
                  </p>
                </div>
                {detailTarget.notes && (
                  <div className="col-span-2 space-y-0.5">
                    <p className="text-muted-foreground">Notes</p>
                    <p>{detailTarget.notes}</p>
                  </div>
                )}
              </div>

              {(detailTarget.whois_org || detailTarget.whois_asn) && (
                <>
                  <Separator />
                  <WhoisInfo target={detailTarget} />
                </>
              )}

              <Separator />
              <div className="space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Tags</p>
                <TagEditor
                  tags={detailTarget.tags ?? []}
                  entityType="target"
                  onChange={tags => tagMutation.mutate({ id: detailTarget.id, tags })}
                />
              </div>
            </div>

            <div className="px-6 py-4 border-t flex gap-2">
              <Button size="sm" variant="destructive" disabled={deleteMutation.isPending}
                onClick={() => setPendingDelete(detailTarget)}>
                <Trash2 className="h-3.5 w-3.5 mr-1.5" />
                Remove
              </Button>
            </div>
          </SheetContent>
        </Sheet>
      )}

      {pendingDelete && (
        <TargetDeleteDialog
          title={`Remove ${displayName(pendingDelete.value)}`}
          description="This removes the target and the assets only this target referenced. Assets shared with other targets are kept. CNAME-chain descendants of removed assets are swept too."
          confirmPhrase={displayName(pendingDelete.value)}
          confirmLabel="Remove target"
          onConfirm={() => deleteMutation.mutate(pendingDelete.id)}
          onCancel={() => setPendingDelete(null)}
          isPending={deleteMutation.isPending}
        />
      )}

      {bulkDeleteOpen && (
        <TargetDeleteDialog
          title={`Remove ${selectedIds.size} target${selectedIds.size !== 1 ? "s" : ""}`}
          description={`This removes ${selectedIds.size} target${selectedIds.size !== 1 ? "s" : ""} and the assets only those targets referenced. Assets shared with other targets are kept.`}
          confirmPhrase="confirm"
          confirmLabel={`Remove ${selectedIds.size}`}
          onConfirm={() => bulkDeleteMutation.mutate([...selectedIds])}
          onCancel={() => setBulkDeleteOpen(false)}
          isPending={bulkDeleteMutation.isPending}
        />
      )}
    </div>
  )
}
