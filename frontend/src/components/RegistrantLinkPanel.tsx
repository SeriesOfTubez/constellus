// planning#236 S1 — link a CIK-less acquired company to its SEC registrant.
// A person confirms the link (never automatic); the backend then runs the
// EDGAR ingest and the AI acquisition read on it. No SEC request is sent
// until the admin presses Search or Preview.
import { useEffect, useState } from "react"
import { Link } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link2, Loader2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  api,
  ApiError,
  type EntityIngestRun,
  type OrgEntity,
  type RegistrantCandidate,
  type RegistrantDeal,
  type RegistrantLinkContext,
  type RegistrantUnlinkResult,
} from "@/lib/api"

const RUN_BADGE: Record<EntityIngestRun["status"], "default" | "secondary" | "destructive" | "outline"> = {
  queued: "secondary",
  running: "secondary",
  succeeded: "default",
  failed: "destructive",
}

type Followup = { status: string; reason?: string; run_id?: string } | undefined

const year = (d: string | null) => (d ? d.slice(0, 4) : null)

function dealDate(d: RegistrantDeal): string {
  if (!d.event_date) return "date unknown"
  if (d.precision === "year") return d.event_date.slice(0, 4)
  if (d.precision === "month") return d.event_date.slice(0, 7)
  return d.event_date
}

// A hint for the reviewer, never a verdict: does the registrant's filing
// span cover any confirmed deal date?
function spansNoDeal(c: RegistrantCandidate, deals: RegistrantDeal[]): boolean {
  const first = Number(year(c.first_filing))
  const last = Number(year(c.last_filing))
  const dealYears = deals.map(d => Number(year(d.event_date))).filter(y => y > 0)
  if (!first || !last || dealYears.length === 0) return false
  return dealYears.every(y => y < first || y > last + 1)
}

function takenDetail(e: unknown): { entity_id: string; legal_name: string } | null {
  if (!(e instanceof ApiError) || e.status !== 409) return null
  const d = e.detail
  if (d && typeof d === "object" && "entity_id" in d && "legal_name" in d) {
    return { entity_id: String(d.entity_id), legal_name: String(d.legal_name) }
  }
  return null
}

export function RegistrantLinkPanel({ entity, isAdmin }: { entity: OrgEntity; isAdmin: boolean }) {
  const qc = useQueryClient()
  const id = entity.id

  const { data: ctx } = useQuery({
    queryKey: ["entity-registrant-link", id],
    queryFn: () => api.get<RegistrantLinkContext>(`/entities/${id}/registrant-link`),
  })
  const linked = !!entity.registrant_linked_at || !!ctx?.linked

  const { data: runs } = useQuery({
    queryKey: ["entity-registrant-ingest", entity.cik],
    queryFn: () => api.get<EntityIngestRun[]>(`/entities/edgar-ingest/runs?cik=${entity.cik}&limit=1`),
    enabled: linked && !!entity.cik,
    refetchInterval: q =>
      (q.state.data ?? []).some(r => r.status === "queued" || r.status === "running") ? 3000 : false,
  })
  const run = linked ? runs?.[0] : undefined
  const followup = (run?.result as Record<string, unknown> | null | undefined)?.acquisition_read as Followup

  const refreshPage = () => {
    for (const key of [
      ["entities"], ["entity-edges", id], ["entity-listings", id], ["entity-events", id], ["entity-sections", id],
      ["entity-candidates", id], ["entity-destination", id], ["entity-acquisition-reads", id],
      ["entity-registrant-link", id], ["entity-registrant-ingest"],
    ]) qc.invalidateQueries({ queryKey: key })
  }

  // The link's ingest creates relations, sections and domains: refresh once
  // when it finishes.
  const finishedRunId = run?.finished_at ? run.id : ""
  useEffect(() => {
    if (!finishedRunId) return
    for (const key of [["entity-edges", id], ["entity-listings", id], ["entity-events", id], ["entity-sections", id],
      ["entity-candidates", id], ["entity-acquisition-reads", id], ["entities"]]) qc.invalidateQueries({ queryKey: key })
  }, [finishedRunId, id, qc])

  // ── link dialog state ──
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [contains, setContains] = useState(false)
  const [cikInput, setCikInput] = useState("")
  const [results, setResults] = useState<RegistrantCandidate[] | null>(null)
  const [selected, setSelected] = useState<RegistrantCandidate | null>(null)

  const lookup = useMutation({
    mutationFn: (params: string) =>
      api.get<RegistrantCandidate[]>(`/entities/${id}/registrant-candidates?${params}`),
    onSuccess: rows => { setResults(rows); setSelected(null) },
  })
  const linkMutation = useMutation({
    mutationFn: (cik: string) => api.post(`/entities/${id}/registrant-link`, { cik }),
    onSuccess: () => { setOpen(false); refreshPage() },
  })

  // ── unlink dialog state ──
  const [unlinkOpen, setUnlinkOpen] = useState(false)
  const [unlinked, setUnlinked] = useState<RegistrantUnlinkResult | null>(null)
  const unlinkMutation = useMutation({
    mutationFn: () => api.delete<RegistrantUnlinkResult>(`/entities/${id}/registrant-link`),
    onSuccess: r => { setUnlinkOpen(false); setUnlinked(r); refreshPage() },
  })

  const openLink = () => {
    setQuery(ctx?.suggested_query ?? "")
    setContains(false)
    setCikInput("")
    setResults(null)
    setSelected(null)
    lookup.reset()
    linkMutation.reset()
    setOpen(true)
  }

  const deals = ctx?.deals ?? []
  const taken = takenDetail(linkMutation.error)

  if (linked) {
    return (
      <div className="rounded-lg border bg-card p-3 space-y-1.5 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span>
            Linked to SEC registrant · CIK <span className="font-mono">{entity.cik}</span>
            {entity.registrant_linked_at && (
              <span className="text-muted-foreground"> · linked {new Date(entity.registrant_linked_at).toLocaleDateString()}</span>
            )}
          </span>
          {isAdmin && (
            <Button size="sm" variant="outline" className="h-7" onClick={() => { unlinkMutation.reset(); setUnlinkOpen(true) }}>
              Unlink…
            </Button>
          )}
        </div>
        {run && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-muted-foreground">SEC ingest</span>
            <Badge variant={RUN_BADGE[run.status]}>{run.status}</Badge>
            {run.error && <span className="text-destructive">{run.error}</span>}
            {followup?.status === "queued" && <span className="text-muted-foreground">AI acquisition read queued</span>}
            {followup?.status === "skipped" && (
              <span className="text-muted-foreground">AI acquisition read skipped: {followup.reason}</span>
            )}
          </div>
        )}

        <Dialog open={unlinkOpen} onOpenChange={setUnlinkOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Unlink SEC registrant?</DialogTitle>
              <DialogDescription>
                This removes the CIK from this company. Everything the link's runs proposed and nobody decided yet is
                rejected (kept for the record), and the stored filings are removed so a later AI read cannot re-read
                them. If a person already confirmed or accepted something from this registrant, unlinking is refused
                until that decision is undone.
              </DialogDescription>
            </DialogHeader>
            {unlinkMutation.error && (
              <p className="text-sm text-destructive" role="alert">{(unlinkMutation.error as Error).message}</p>
            )}
            <DialogFooter>
              <Button variant="outline" onClick={() => setUnlinkOpen(false)}>Cancel</Button>
              <Button variant="destructive" disabled={unlinkMutation.isPending} onClick={() => unlinkMutation.mutate()}>
                {unlinkMutation.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
                Unlink
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    )
  }

  if (!ctx?.eligible || !isAdmin) {
    return unlinked ? (
      <p className="text-sm text-muted-foreground">
        Unlinked. Rejected {unlinked.relations_rejected} relation(s) and {unlinked.candidates_rejected} domain(s);
        removed {unlinked.filing_events + unlinked.filing_sections + unlinked.subsidiary_listings} filing record(s).
      </p>
    ) : null
  }

  return (
    <div className="text-sm space-y-1">
      {unlinked && (
        <p className="text-muted-foreground">
          Unlinked. Rejected {unlinked.relations_rejected} relation(s) and {unlinked.candidates_rejected} domain(s);
          removed {unlinked.filing_events + unlinked.filing_sections + unlinked.subsidiary_listings} filing record(s).
        </p>
      )}
      <Button size="sm" variant="outline" className="h-8" onClick={openLink}>
        <Link2 className="h-3.5 w-3.5 mr-1.5" />
        Link to SEC registrant…
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle>Link to an SEC registrant</DialogTitle>
            <DialogDescription>
              If this acquired company was ever an SEC registrant, its own filings carry its website, its subsidiaries
              and its own acquisitions. Find it below and confirm. Name matches are often wrong: check the filing years
              against the deal date.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-0.5 text-sm">
            {deals.map(d => (
              <p key={`${d.acquirer_id}-${d.event_date}`} className="text-muted-foreground">
                Acquired by <span className="text-foreground">{d.acquirer_name}</span> · {dealDate(d)}
              </p>
            ))}
          </div>

          {selected ? (
            <div className="space-y-3 text-sm">
              <p>
                Confirm: <span className="font-medium">{entity.legal_name}</span> is SEC registrant{" "}
                <span className="font-medium">{selected.name}</span> (CIK <span className="font-mono">{selected.cik}</span>).
              </p>
              <p className="text-muted-foreground">
                This runs the SEC ingest on this registrant, then the AI acquisition read. What they find is proposed
                for review; nothing enters scope automatically.
              </p>
              {taken ? (
                <p className="text-destructive" role="alert">
                  That CIK is already on{" "}
                  <Link to={`/entities/${taken.entity_id}`} className="underline">{taken.legal_name}</Link>.
                </p>
              ) : linkMutation.error && (
                <p className="text-destructive" role="alert">{(linkMutation.error as Error).message}</p>
              )}
              <DialogFooter>
                <Button variant="outline" onClick={() => { linkMutation.reset(); setSelected(null) }}>Back</Button>
                <Button disabled={linkMutation.isPending} onClick={() => linkMutation.mutate(selected.cik)}>
                  {linkMutation.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
                  Confirm link
                </Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-3">
              <form
                className="flex flex-wrap items-end gap-3"
                onSubmit={e => {
                  e.preventDefault()
                  if (query.trim()) lookup.mutate(`q=${encodeURIComponent(query.trim())}&contains=${contains}`)
                }}
              >
                <div className="space-y-1 flex-1 min-w-[16rem]">
                  <Label htmlFor="registrant-query">Company name</Label>
                  <Input id="registrant-query" value={query} maxLength={100} onChange={e => setQuery(e.target.value)} />
                </div>
                <div className="flex items-center gap-2 pb-2">
                  <Switch id="registrant-contains" checked={contains} onCheckedChange={setContains} />
                  <Label htmlFor="registrant-contains" className="font-normal">Match anywhere in the name</Label>
                </div>
                <Button type="submit" disabled={!query.trim() || lookup.isPending}>
                  {lookup.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
                  Search
                </Button>
              </form>
              <form
                className="flex flex-wrap items-end gap-3"
                onSubmit={e => {
                  e.preventDefault()
                  if (cikInput) lookup.mutate(`cik=${cikInput}`)
                }}
              >
                <div className="space-y-1">
                  <Label htmlFor="registrant-cik">Or enter a CIK</Label>
                  <Input
                    id="registrant-cik" className="w-40 font-mono" inputMode="numeric" maxLength={10} value={cikInput}
                    onChange={e => setCikInput(e.target.value.replace(/\D/g, ""))}
                  />
                </div>
                <Button type="submit" variant="outline" disabled={!cikInput || lookup.isPending}>Preview</Button>
              </form>

              {lookup.error && <p className="text-sm text-destructive" role="alert">{(lookup.error as Error).message}</p>}
              {results && results.length === 0 && (
                <p className="text-sm text-muted-foreground">
                  No registrant found. Try a shorter name, match anywhere in the name, or enter a CIK.
                </p>
              )}
              {results && results.length > 0 && (
                <div className="max-h-[50vh] overflow-y-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Registrant</TableHead>
                        <TableHead>CIK</TableHead>
                        <TableHead>Inc.</TableHead>
                        <TableHead>Industry</TableHead>
                        <TableHead>Filed</TableHead>
                        <TableHead>10-Ks</TableHead>
                        <TableHead className="w-40" />
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {results.map(c => (
                        <TableRow key={c.cik}>
                          <TableCell>
                            <div className="font-medium">{c.name}</div>
                            {c.former_names.map((f, i) => (
                              <div key={i} className="text-xs text-muted-foreground">
                                formerly {f.name} ({year(f.from) ?? "?"}–{year(f.to) ?? "?"})
                              </div>
                            ))}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{c.cik}</TableCell>
                          <TableCell>{c.state_of_incorporation ?? "—"}</TableCell>
                          <TableCell className="text-xs">
                            {c.sic ? `${c.sic}${c.sic_description ? ` · ${c.sic_description}` : ""}` : "—"}
                          </TableCell>
                          <TableCell className="text-xs">
                            {c.first_filing ? `${year(c.first_filing)}–${year(c.last_filing)}` : "—"}
                            {spansNoDeal(c, deals) && (
                              <div className="text-muted-foreground">filings don't span the deal date</div>
                            )}
                          </TableCell>
                          <TableCell className="text-xs">
                            {c.annual_reports}
                            {c.annual_reports > 0 && ` · ${year(c.first_annual_report)}–${year(c.last_annual_report)}`}
                            {c.annual_reports_partial && <span className="text-muted-foreground"> (recent filings only)</span>}
                          </TableCell>
                          <TableCell>
                            {c.taken_by_id ? (
                              <span className="text-xs text-muted-foreground">
                                Already on{" "}
                                <Link to={`/entities/${c.taken_by_id}`} className="underline">{c.taken_by_name}</Link>
                              </span>
                            ) : (
                              <Button size="sm" variant="outline" onClick={() => { linkMutation.reset(); setSelected(c) }}>
                                Select
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
