import { useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useNavigate } from "react-router-dom"
import { useFlyout } from "@/lib/flyout"
import { toast } from "sonner"
import { Plus, Loader2, ScanLine, RefreshCw, XCircle, CheckSquare, Square, Pencil, Trash2, Info, Clock, CheckCircle2, AlertCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type AvailableDomain, type ScanRun } from "@/lib/api"

type ScanOptions = {
  cert_transparency: boolean
  subfinder: boolean
  dnsrecon: boolean
  bruteforce: boolean
  bruteforce_wordlist: string
}

const STATUS_BADGE: Record<ScanRun["status"], { label: string; variant: "default" | "outline" | "success" | "warning" | "destructive" }> = {
  pending:   { label: "Pending",   variant: "outline" },
  running:   { label: "Running",   variant: "warning" },
  completed: { label: "Completed", variant: "success" },
  failed:    { label: "Failed",    variant: "destructive" },
  cancelled: { label: "Cancelled", variant: "outline" },
}

function duration(run: ScanRun): string {
  if (!run.started_at) return "—"
  const end = run.completed_at ? new Date(run.completed_at) : new Date()
  const secs = Math.round((end.getTime() - new Date(run.started_at).getTime()) / 1000)
  if (secs < 60) return `${secs}s`
  return `${Math.floor(secs / 60)}m ${secs % 60}s`
}

function NewScanDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [name, setName] = useState("")
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(new Set())
  const [manualDomains, setManualDomains] = useState("")
  const [ipRanges, setIpRanges] = useState("")
  const [showOptions, setShowOptions] = useState(false)
  const [options, setOptions] = useState<ScanOptions>({
    cert_transparency: true,
    subfinder: true,
    dnsrecon: false,
    bruteforce: false,
    bruteforce_wordlist: "small",
  })

  function setOption<K extends keyof ScanOptions>(key: K, value: ScanOptions[K]) {
    setOptions(o => ({ ...o, [key]: value }))
  }

  const { data: availableDomains, isLoading: loadingDomains } = useQuery({
    queryKey: ["connector-domains"],
    queryFn: () => api.get<AvailableDomain[]>("/connectors/domains"),
    enabled: open,
  })

  const connectorGroups = (availableDomains ?? []).reduce<Record<string, AvailableDomain[]>>((acc, d) => {
    acc[d.connector_name] = [...(acc[d.connector_name] ?? []), d]
    return acc
  }, {})

  function toggleDomain(domain: string) {
    setSelectedDomains(prev => {
      const next = new Set(prev)
      next.has(domain) ? next.delete(domain) : next.add(domain)
      return next
    })
  }

  function toggleAll(domains: AvailableDomain[]) {
    const allSelected = domains.every(d => selectedDomains.has(d.domain))
    setSelectedDomains(prev => {
      const next = new Set(prev)
      domains.forEach(d => allSelected ? next.delete(d.domain) : next.add(d.domain))
      return next
    })
  }

  const uniqueDomains = [...new Set([
    ...Array.from(selectedDomains),
    ...manualDomains.split("\n").map(d => d.trim()).filter(Boolean),
  ])]

  const mutation = useMutation({
    mutationFn: () => api.post<ScanRun>("/scans/", {
      name: name.trim() || null,
      scope: {
        domains: uniqueDomains,
        ip_ranges: ipRanges.split("\n").map(r => r.trim()).filter(Boolean),
      },
      options,
    }),
    onSuccess: (run) => {
      toast.success("Scan started")
      qc.invalidateQueries({ queryKey: ["scans"] })
      handleClose()
      navigate(`/assets?scan=${run.id}`)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  function handleClose() {
    if (mutation.isPending) return
    setName(""); setSelectedDomains(new Set()); setManualDomains(""); setIpRanges("")
    setOptions({ cert_transparency: true, subfinder: true, dnsrecon: false, bruteforce: false, bruteforce_wordlist: "small" })
    setShowOptions(false)
    onClose()
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="sm:max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader><DialogTitle>New scan</DialogTitle></DialogHeader>
        <div className="space-y-5 py-2">
          <div className="space-y-1.5">
            <Label>Name <span className="text-muted-foreground text-xs">(optional)</span></Label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Weekly full scan" />
          </div>

          {(loadingDomains || (availableDomains && availableDomains.length > 0)) && (
            <>
              <div className="space-y-2">
                <Label>Verified targets</Label>
                {loadingDomains ? (
                  <div className="space-y-1.5">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-7 w-full" />)}</div>
                ) : (
                  <div className="rounded-md border divide-y">
                    {Object.entries(connectorGroups).map(([connectorName, domains]) => (
                      <div key={connectorName} className="p-2 space-y-1">
                        <div className="flex items-center justify-between px-1">
                          <span className="text-xs font-medium text-muted-foreground">{connectorName}</span>
                          <button type="button" onClick={() => toggleAll(domains)} className="text-xs text-primary hover:underline">
                            {domains.every(d => selectedDomains.has(d.domain)) ? "Deselect all" : "Select all"}
                          </button>
                        </div>
                        {domains.map(d => (
                          <label key={d.domain} onClick={() => toggleDomain(d.domain)} className="flex items-center gap-2.5 rounded px-1 py-1 cursor-pointer hover:bg-accent">
                            {selectedDomains.has(d.domain)
                              ? <CheckSquare className="h-4 w-4 text-primary shrink-0" />
                              : <Square className="h-4 w-4 text-muted-foreground shrink-0" />}
                            <span className="text-sm font-mono">{d.domain}</span>
                          </label>
                        ))}
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <Separator />
            </>
          )}

          <div className="space-y-1.5">
            <Label>Additional domains <span className="text-muted-foreground text-xs">(one per line)</span></Label>
            <Textarea value={manualDomains} onChange={e => setManualDomains(e.target.value)} placeholder={"example.com\nother.com"} rows={3} className="font-mono text-sm" />
          </div>

          <div className="space-y-1.5">
            <Label>IP ranges <span className="text-muted-foreground text-xs">(optional, CIDR, one per line)</span></Label>
            <Textarea value={ipRanges} onChange={e => setIpRanges(e.target.value)} placeholder="1.2.3.0/24" rows={2} className="font-mono text-sm" />
          </div>

          <Separator />
          <div className="space-y-2">
            <button type="button" onClick={() => setShowOptions(v => !v)} className="flex items-center gap-1.5 text-sm font-medium hover:text-primary transition-colors">
              <span>Discovery options</span>
              <span className="text-muted-foreground text-xs">{showOptions ? "▲" : "▼"}</span>
            </button>
            {showOptions && (
              <div className="rounded-md border divide-y text-sm">
                {([
                  { key: "cert_transparency", label: "Certificate Transparency", desc: "Query crt.sh for historical SSL certs (passive)" },
                  { key: "subfinder",          label: "subfinder",               desc: "Aggregate 40+ passive sources via Docker (passive)" },
                  { key: "dnsrecon",           label: "dnsrecon",                desc: "Active DNS enumeration — queries target nameservers" },
                  { key: "bruteforce",         label: "Subdomain brute-force",   desc: "Resolve common subdomain names via DNS" },
                ] as const).map(({ key, label, desc }) => (
                  <div key={key} className="flex items-center justify-between gap-4 px-3 py-2.5">
                    <div>
                      <p className="font-medium">{label}</p>
                      <p className="text-xs text-muted-foreground">{desc}</p>
                    </div>
                    <Switch checked={options[key]} onCheckedChange={v => setOption(key, v)} />
                  </div>
                ))}
                {options.bruteforce && (
                  <div className="flex items-center justify-between gap-4 px-3 py-2.5">
                    <div>
                      <p className="font-medium">Wordlist size</p>
                      <p className="text-xs text-muted-foreground">small ~60 · medium ~120 · large ~200+</p>
                    </div>
                    <Select value={options.bruteforce_wordlist} onValueChange={v => setOption("bruteforce_wordlist", v)}>
                      <SelectTrigger className="w-28 h-8 text-sm"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="small">Small</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="large">Large</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                )}
              </div>
            )}
          </div>

          {uniqueDomains.length > 0 && (
            <p className="text-xs text-muted-foreground">{uniqueDomains.length} domain{uniqueDomains.length !== 1 ? "s" : ""} in scope</p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={handleClose} disabled={mutation.isPending}>Cancel</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending || uniqueDomains.length === 0}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Start scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function EditScanDialog({ run, onClose }: { run: ScanRun; onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState(run.name ?? "")
  const mutation = useMutation({
    mutationFn: () => api.patch(`/scans/${run.id}`, { name: name.trim() || null }),
    onSuccess: () => { toast.success("Scan updated"); qc.invalidateQueries({ queryKey: ["scans"] }); onClose() },
    onError: () => toast.error("Failed to update scan"),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader><DialogTitle>Edit scan</DialogTitle></DialogHeader>
        <div className="py-2 space-y-2">
          <Label>Name</Label>
          <Input value={name} onChange={e => setName(e.target.value)} placeholder="Scan name" autoFocus />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => mutation.mutate()} disabled={mutation.isPending}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Scan detail sheet ─────────────────────────────────────────────────────────

function ScanDetailSheet({ run, onClose }: { run: ScanRun; onClose: () => void }) {
  const navigate = useNavigate()
  const badge = STATUS_BADGE[run.status]

  const timeline = [
    { label: "Created",   value: run.created_at,   icon: Clock },
    { label: "Started",   value: run.started_at,   icon: CheckCircle2 },
    { label: "Completed", value: run.completed_at,  icon: run.status === "failed" ? AlertCircle : CheckCircle2 },
  ].filter(e => e.value)

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-[480px] sm:max-w-[480px] flex flex-col gap-0 p-0">
        <SheetHeader className="px-6 pt-6 pb-4 border-b space-y-2">
          <div className="flex items-center gap-2">
            <Badge variant={badge.variant}>{badge.label}</Badge>
            {run.status === "running" && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
          </div>
          <SheetTitle className="text-base leading-snug">
            {run.name ?? run.scope.domains.slice(0, 2).join(", ") ?? "Unnamed scan"}
          </SheetTitle>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: "Assets",   value: run.asset_count },
              { label: "Findings", value: run.finding_count },
              { label: "Duration", value: duration(run) },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-md border p-3 text-center">
                <p className="text-lg font-semibold">{value}</p>
                <p className="text-xs text-muted-foreground">{label}</p>
              </div>
            ))}
          </div>

          {/* Scope */}
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Scope</p>
            <div className="rounded-md border divide-y text-xs font-mono">
              {run.scope.domains.map(d => (
                <div key={d} className="px-3 py-2 flex items-center gap-2">
                  <ScanLine className="h-3 w-3 text-muted-foreground shrink-0" />{d}
                </div>
              ))}
              {run.scope.ip_ranges?.map(r => (
                <div key={r} className="px-3 py-2 flex items-center gap-2">
                  <ScanLine className="h-3 w-3 text-muted-foreground shrink-0" />{r}
                </div>
              ))}
            </div>
          </div>

          {/* Timeline */}
          <Separator />
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Timeline</p>
            <div className="space-y-2">
              {timeline.map(({ label, value, icon: Icon }) => (
                <div key={label} className="flex items-center gap-3 text-xs">
                  <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="text-muted-foreground w-20 shrink-0">{label}</span>
                  <span>{new Date(value!).toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Connectors */}
          {run.connectors_used && run.connectors_used.length > 0 && (
            <>
              <Separator />
              <div className="space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Connectors used</p>
                <div className="flex flex-wrap gap-1.5">
                  {run.connectors_used.map(c => (
                    <span key={c} className="inline-flex items-center rounded-md bg-muted px-2 py-0.5 text-xs font-mono">{c}</span>
                  ))}
                </div>
              </div>
            </>
          )}

          {/* Error */}
          {run.error && (
            <>
              <Separator />
              <div className="space-y-2">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-destructive">Error</p>
                <pre className="text-xs font-mono bg-destructive/5 border border-destructive/20 rounded p-3 whitespace-pre-wrap break-all text-destructive">{run.error}</pre>
              </div>
            </>
          )}
        </div>

        <div className="px-6 py-4 border-t flex gap-2">
          <Button size="sm" variant="outline" onClick={() => { navigate(`/assets?scan=${run.id}`); onClose() }}>
            View assets
          </Button>
          <Button size="sm" variant="outline" onClick={() => { navigate(`/findings?scan=${run.id}`); onClose() }}>
            View findings
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  )
}

function ScanRow({ run, onDetail }: { run: ScanRun; onDetail: (run: ScanRun) => void }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const badge = STATUS_BADGE[run.status]
  const [editing, setEditing] = useState(false)

  const cancelMutation = useMutation({
    mutationFn: () => api.post(`/scans/${run.id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
    onError: () => toast.error("Failed to cancel scan"),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/scans/${run.id}`),
    onSuccess: () => { toast.success("Scan deleted"); qc.invalidateQueries({ queryKey: ["scans"] }) },
    onError: () => toast.error("Failed to delete scan"),
  })

  return (
    <>
      <Card className="cursor-pointer hover:border-primary/50 transition-colors" onClick={() => navigate(`/assets?scan=${run.id}`)}>
        <CardContent className="flex items-center gap-4 py-4">
          <div className="flex-1 min-w-0 space-y-0.5">
            <div className="flex items-center gap-2">
              <p className="text-sm font-medium truncate">{run.name ?? run.scope.domains.join(", ") ?? "Unnamed scan"}</p>
              <Badge variant={badge.variant}>{badge.label}</Badge>
              {run.status === "running" && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
            </div>
            <p className="text-xs text-muted-foreground">
              {run.scope.domains.slice(0, 3).join(", ")}{run.scope.domains.length > 3 && ` +${run.scope.domains.length - 3} more`}
            </p>
          </div>

          <div className="hidden sm:flex items-center gap-6 text-sm text-muted-foreground shrink-0">
            <div className="text-center">
              <p className="font-medium text-foreground">{run.asset_count}</p>
              <p className="text-xs">assets</p>
            </div>
            <div className="text-center">
              <p className="font-medium text-foreground">{run.finding_count}</p>
              <p className="text-xs">findings</p>
            </div>
            <div className="text-center">
              <p className="font-medium text-foreground">{duration(run)}</p>
              <p className="text-xs">duration</p>
            </div>
            <p className="text-xs">{new Date(run.created_at).toLocaleString()}</p>
          </div>

          <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
            <Button variant="ghost" size="sm" onClick={() => onDetail(run)} title="Details">
              <Info className="h-4 w-4" />
            </Button>
            {(run.status === "pending" || run.status === "running") && (
              <Button variant="ghost" size="sm" onClick={() => cancelMutation.mutate()} disabled={cancelMutation.isPending} title="Cancel">
                <XCircle className="h-4 w-4" />
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={() => setEditing(true)} title="Edit">
              <Pencil className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost" size="sm"
              onClick={() => { if (confirm("Delete this scan and all its assets and findings?")) deleteMutation.mutate() }}
              disabled={deleteMutation.isPending || run.status === "running"}
              title="Delete"
              className="text-destructive hover:text-destructive"
            >
              {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            </Button>
          </div>
        </CardContent>
      </Card>
      {editing && <EditScanDialog run={run} onClose={() => setEditing(false)} />}
    </>
  )
}

export default function Scans() {
  const [newScanOpen, setNewScanOpen] = useState(false)
  const qc = useQueryClient()

  const { data: scans, isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<ScanRun[]>("/scans/"),
    refetchInterval: (query) => {
      const data = query.state.data as ScanRun[] | undefined
      return data?.some(s => s.status === "running" || s.status === "pending") ? 3000 : false
    },
  })

  const { selected: selectedScan, open: openScan, close: closeScan } = useFlyout(scans ?? [])

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Scans</h1>
          <p className="text-sm text-muted-foreground mt-1">Manage and monitor attack surface scans</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => qc.invalidateQueries({ queryKey: ["scans"] })}>
            <RefreshCw className="h-4 w-4" />
          </Button>
          <Button size="sm" onClick={() => setNewScanOpen(true)}>
            <Plus className="h-4 w-4" /> New scan
          </Button>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-20 w-full" />)}</div>
      ) : scans?.length === 0 ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <ScanLine className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">No scans yet</p>
          <p className="text-sm mt-1">Start a scan to discover your attack surface.</p>
          <Button className="mt-4" onClick={() => setNewScanOpen(true)}><Plus className="h-4 w-4" /> New scan</Button>
        </div>
      ) : (
        <div className="space-y-3">{scans?.map(run => <ScanRow key={run.id} run={run} onDetail={openScan} />)}</div>
      )}

      <NewScanDialog open={newScanOpen} onClose={() => setNewScanOpen(false)} />

      {selectedScan && (
        <ScanDetailSheet run={selectedScan} onClose={closeScan} />
      )}
    </div>
  )
}
