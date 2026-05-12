import { useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ShieldCheck, ShieldAlert, Plus, Trash2, RefreshCw, Copy, Loader2, Globe, Server, Network } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type Target } from "@/lib/api"

const TXT_PREFIX = "_constellus-verify"

const TYPE_META: Record<Target["type"], { label: string; icon: React.ElementType; color: string }> = {
  domain: { label: "Domain", icon: Globe,   color: "bg-blue-500/10 text-blue-600 dark:text-blue-400" },
  ip:     { label: "IP",     icon: Server,  color: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400" },
  cidr:   { label: "CIDR",  icon: Network, color: "bg-purple-500/10 text-purple-600 dark:text-purple-400" },
}

function TypeBadge({ type }: { type: Target["type"] }) {
  const { label, color } = TYPE_META[type]
  return <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${color}`}>{label}</span>
}

function StatusBadge({ target }: { target: Target }) {
  if (target.verified) {
    const label = target.verification_method === "connector"
      ? `Connector`
      : target.verification_method === "acknowledged"
      ? "Acknowledged"
      : "Verified"
    return (
      <Badge className="bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-0 gap-1">
        <ShieldCheck className="h-3 w-3" />{label}
      </Badge>
    )
  }
  return (
    <Badge className="bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-0 gap-1">
      <ShieldAlert className="h-3 w-3" />Pending
    </Badge>
  )
}

function CopyButton({ text }: { text: string }) {
  return (
    <button onClick={() => { navigator.clipboard.writeText(text); toast.success("Copied") }}
      className="text-muted-foreground hover:text-foreground transition-colors ml-1">
      <Copy className="h-3 w-3 inline" />
    </button>
  )
}

function DomainVerifyInstructions({ target }: { target: Target }) {
  const record = `${TXT_PREFIX}.${target.value}`
  return (
    <div className="rounded-md border bg-muted/40 p-3 space-y-2 text-xs font-mono">
      <p className="font-sans text-xs font-medium text-muted-foreground">Add this DNS TXT record:</p>
      <div>Name: <span className="text-foreground">{record}</span><CopyButton text={record} /></div>
      <div>Value: <span className="text-primary">{target.token}</span><CopyButton text={target.token} /></div>
    </div>
  )
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
  const [detailTarget, setDetailTarget] = useState<Target | null>(null)

  const { data: targets, isLoading } = useQuery({
    queryKey: ["targets"],
    queryFn: () => api.get<Target[]>("/targets/"),
  })

  const addMutation = useMutation({
    mutationFn: (value: string) => api.post<Target>("/targets/", { value }),
    onSuccess: (created) => {
      toast.success(`${created.value} added`)
      qc.invalidateQueries({ queryKey: ["targets"] })
      setAddOpen(false)
      setNewValue("")
      if (!created.verified) setDetailTarget(created)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const verifyMutation = useMutation({
    mutationFn: (id: string) => api.post<Target>(`/targets/${id}/verify`),
    onSuccess: (updated) => {
      toast.success(`${updated.value} verified`)
      qc.invalidateQueries({ queryKey: ["targets"] })
      setDetailTarget(updated)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const acknowledgeMutation = useMutation({
    mutationFn: (id: string) => api.post<Target>(`/targets/${id}/acknowledge`, { confirmed: true }),
    onSuccess: (updated) => {
      toast.success(`${updated.value} acknowledged`)
      qc.invalidateQueries({ queryKey: ["targets"] })
      setDetailTarget(updated)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/targets/${id}`),
    onSuccess: () => {
      toast.success("Target removed")
      qc.invalidateQueries({ queryKey: ["targets"] })
      setDetailTarget(null)
    },
    onError: () => toast.error("Failed to remove target"),
  })

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Targets</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Domains, IPs, and CIDRs in scope for scanning. Active tools only run against verified targets.
          </p>
        </div>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />Add Target
        </Button>
      </div>

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
                <TableHead className="w-24">Type</TableHead>
                <TableHead>Value</TableHead>
                <TableHead className="w-36">Status</TableHead>
                <TableHead className="hidden md:table-cell">Source</TableHead>
                <TableHead className="hidden lg:table-cell">Verified</TableHead>
                <TableHead className="w-20" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {targets.map(t => (
                <TableRow key={t.id} className="cursor-pointer" onClick={() => !t.verified || t.type !== "domain" ? setDetailTarget(t) : undefined}>
                  <TableCell><TypeBadge type={t.type} /></TableCell>
                  <TableCell className="font-mono text-sm">{t.value}</TableCell>
                  <TableCell><StatusBadge target={t} /></TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">
                    {t.connector_id ? `Connector: ${t.connector_id}` : t.verification_method === "acknowledged" ? "Acknowledged" : "Manual"}
                  </TableCell>
                  <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                    {t.verified_at ? new Date(t.verified_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-1">
                      {!t.verified && (
                        <Button variant="ghost" size="sm" title={t.type === "domain" ? "Check TXT record" : "Acknowledge"}
                          disabled={verifyMutation.isPending || acknowledgeMutation.isPending}
                          onClick={() => setDetailTarget(t)}>
                          <RefreshCw className="h-3.5 w-3.5" />
                        </Button>
                      )}
                      <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive"
                        disabled={deleteMutation.isPending}
                        onClick={() => { if (confirm(`Remove ${t.value}?`)) deleteMutation.mutate(t.id) }}
                        title="Remove">
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
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
          <Input
            placeholder="example.com, 1.2.3.4, or 1.2.3.0/24"
            value={newValue}
            onChange={e => setNewValue(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && newValue) addMutation.mutate(newValue) }}
            className="font-mono"
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button disabled={!newValue || addMutation.isPending} onClick={() => addMutation.mutate(newValue)}>
              {addMutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Detail / verification dialog */}
      {detailTarget && (
        <Dialog open onOpenChange={() => setDetailTarget(null)}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle className="font-mono flex items-center gap-2">
                <TypeBadge type={detailTarget.type} />
                {detailTarget.value}
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-1">
              <StatusBadge target={detailTarget} />

              <WhoisInfo target={detailTarget} />

              {!detailTarget.verified && detailTarget.type === "domain" && (
                <div className="space-y-3">
                  <DomainVerifyInstructions target={detailTarget} />
                  <p className="text-xs text-muted-foreground">DNS propagation can take a few minutes after publishing.</p>
                  <Button className="w-full" disabled={verifyMutation.isPending}
                    onClick={() => verifyMutation.mutate(detailTarget.id)}>
                    {verifyMutation.isPending
                      ? <><Loader2 className="h-4 w-4 animate-spin mr-1.5" />Checking…</>
                      : <><RefreshCw className="h-4 w-4 mr-1.5" />Check Verification</>}
                  </Button>
                </div>
              )}

              {!detailTarget.verified && detailTarget.type !== "domain" && (
                <div className="space-y-3">
                  <div className="rounded-md border border-yellow-500/30 bg-yellow-500/5 p-3 text-sm text-yellow-600 dark:text-yellow-400">
                    By acknowledging this target you confirm you own or are authorised to scan it.
                    This confirmation is logged with your user account.
                  </div>
                  <Button className="w-full" disabled={acknowledgeMutation.isPending}
                    onClick={() => acknowledgeMutation.mutate(detailTarget.id)}>
                    {acknowledgeMutation.isPending
                      ? <><Loader2 className="h-4 w-4 animate-spin mr-1.5" />Saving…</>
                      : "I confirm — authorise scanning"}
                  </Button>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  )
}
