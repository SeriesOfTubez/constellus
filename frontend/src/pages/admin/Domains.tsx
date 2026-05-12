import { useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ShieldCheck, ShieldAlert, Plus, Trash2, RefreshCw, Copy, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type DomainVerification } from "@/lib/api"

const TXT_PREFIX = "_constellus-verify"

function StatusBadge({ verified, method }: { verified: boolean; method: string | null }) {
  if (verified) {
    const label = method === "connector" ? "Connector" : "TXT record"
    return (
      <Badge className="bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-0 gap-1">
        <ShieldCheck className="h-3 w-3" />
        {label}
      </Badge>
    )
  }
  return (
    <Badge className="bg-yellow-500/15 text-yellow-600 dark:text-yellow-400 border-0 gap-1">
      <ShieldAlert className="h-3 w-3" />
      Pending
    </Badge>
  )
}

function TxtInstructions({ domain, token }: { domain: string; token: string }) {
  const record = `${TXT_PREFIX}.${domain}`
  const copy = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success("Copied to clipboard")
  }
  return (
    <div className="rounded-md border bg-muted/40 p-3 space-y-2 text-xs font-mono">
      <p className="text-muted-foreground font-sans text-xs font-medium">Add this DNS TXT record to verify ownership:</p>
      <div className="flex items-center gap-2">
        <span className="text-foreground">{record}</span>
        <button onClick={() => copy(record)} className="text-muted-foreground hover:text-foreground transition-colors">
          <Copy className="h-3 w-3" />
        </button>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-primary">{token}</span>
        <button onClick={() => copy(token)} className="text-muted-foreground hover:text-foreground transition-colors">
          <Copy className="h-3 w-3" />
        </button>
      </div>
    </div>
  )
}

export default function Domains() {
  const qc = useQueryClient()
  const [addOpen, setAddOpen] = useState(false)
  const [newDomain, setNewDomain] = useState("")
  const [detailDomain, setDetailDomain] = useState<DomainVerification | null>(null)

  const { data: domains, isLoading } = useQuery({
    queryKey: ["domains"],
    queryFn: () => api.get<DomainVerification[]>("/domains/"),
  })

  const addMutation = useMutation({
    mutationFn: (domain: string) => api.post<DomainVerification>("/domains/", { domain }),
    onSuccess: (created) => {
      toast.success(`Domain ${created.domain} added`)
      qc.invalidateQueries({ queryKey: ["domains"] })
      setAddOpen(false)
      setNewDomain("")
      setDetailDomain(created)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const verifyMutation = useMutation({
    mutationFn: (id: string) => api.post<DomainVerification>(`/domains/${id}/verify`),
    onSuccess: (updated) => {
      toast.success(`${updated.domain} verified`)
      qc.invalidateQueries({ queryKey: ["domains"] })
      setDetailDomain(updated)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/domains/${id}`),
    onSuccess: () => {
      toast.success("Domain removed")
      qc.invalidateQueries({ queryKey: ["domains"] })
      setDetailDomain(null)
    },
    onError: () => toast.error("Failed to remove domain"),
  })

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Domain Verification</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Active scanning tools (subfinder, dnsrecon, brute-force, Nuclei) only run against verified domains.
            Connector-sourced domains are auto-verified.
          </p>
        </div>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />
          Add Domain
        </Button>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
      ) : !domains?.length ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <ShieldCheck className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">No domains yet</p>
          <p className="text-sm mt-1">Add a domain manually or configure a DNS connector to auto-populate.</p>
        </div>
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Domain</TableHead>
                <TableHead className="w-40">Status</TableHead>
                <TableHead className="hidden md:table-cell">Verified at</TableHead>
                <TableHead className="hidden lg:table-cell">Added</TableHead>
                <TableHead className="w-28" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {domains.map(d => (
                <TableRow key={d.id} className="cursor-pointer" onClick={() => setDetailDomain(d)}>
                  <TableCell className="font-mono text-sm">{d.domain}</TableCell>
                  <TableCell><StatusBadge verified={d.verified} method={d.method} /></TableCell>
                  <TableCell className="hidden md:table-cell text-xs text-muted-foreground">
                    {d.verified_at ? new Date(d.verified_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell className="hidden lg:table-cell text-xs text-muted-foreground">
                    {new Date(d.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-1">
                      {!d.verified && (
                        <Button
                          variant="ghost" size="sm"
                          disabled={verifyMutation.isPending}
                          onClick={() => verifyMutation.mutate(d.id)}
                          title="Check TXT record"
                        >
                          {verifyMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                        </Button>
                      )}
                      <Button
                        variant="ghost" size="sm"
                        className="text-destructive hover:text-destructive"
                        disabled={deleteMutation.isPending}
                        onClick={() => { if (confirm(`Remove ${d.domain}?`)) deleteMutation.mutate(d.id) }}
                        title="Remove"
                      >
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

      {/* Add domain dialog */}
      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add Domain</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <Input
              placeholder="example.com"
              value={newDomain}
              onChange={e => setNewDomain(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter" && newDomain) addMutation.mutate(newDomain) }}
            />
            <p className="text-xs text-muted-foreground">
              After adding, you'll receive a DNS TXT record to publish for verification.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button
              disabled={!newDomain || addMutation.isPending}
              onClick={() => addMutation.mutate(newDomain)}
            >
              {addMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Detail / instructions dialog */}
      {detailDomain && (
        <Dialog open onOpenChange={() => setDetailDomain(null)}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle className="font-mono">{detailDomain.domain}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-1">
              <div className="flex items-center gap-2">
                <StatusBadge verified={detailDomain.verified} method={detailDomain.method} />
                {detailDomain.verified_at && (
                  <span className="text-xs text-muted-foreground">
                    Verified {new Date(detailDomain.verified_at).toLocaleString()}
                  </span>
                )}
              </div>

              {!detailDomain.verified && (
                <div className="space-y-3">
                  <TxtInstructions domain={detailDomain.domain} token={detailDomain.token} />
                  <p className="text-xs text-muted-foreground">
                    After publishing the TXT record, click <strong>Check Verification</strong>.
                    DNS propagation can take a few minutes.
                  </p>
                  <Button
                    className="w-full"
                    disabled={verifyMutation.isPending}
                    onClick={() => verifyMutation.mutate(detailDomain.id)}
                  >
                    {verifyMutation.isPending
                      ? <><Loader2 className="h-4 w-4 animate-spin mr-1.5" />Checking…</>
                      : <><RefreshCw className="h-4 w-4 mr-1.5" />Check Verification</>
                    }
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
