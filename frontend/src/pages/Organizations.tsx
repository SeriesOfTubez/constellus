import { Fragment, useEffect, useMemo, useState } from "react"
import { Link, Navigate, useParams, useSearchParams } from "react-router-dom"
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Building2, ChevronDown, ChevronRight, Plus } from "lucide-react"
import { api, ApiError } from "@/lib/api"
import { useFlyout } from "@/lib/flyout"
import { useDebouncedUrlState, useUrlState } from "@/lib/listView"
import { useCan, usePermissionsSync } from "@/lib/permissions"
import { relativeTime } from "@/lib/time"
import {
  type CandidateDetail, type CandidatePage, type CandidateRow, type OrgDetailSummary, type OrgGroupMode,
  type OrganizationSummary, type Segment, type SignalType, type TreeNode,
  GROUP_OPTIONS, SEGMENTS, SEGMENT_LABEL, STRENGTH_LABEL, TIER_LEGEND,
  candidateParams, confirmedNodes, destinationText, groupRows, headerSubtitle, orgPill, segmentCount, treeRows,
} from "@/lib/organizations"
import { WorkspaceShell } from "@/components/WorkspaceShell"
import {
  AssetsCell, CandidateFlyoutContent, DECIDE, OrganizationCell, SignalsCell, StateCell, errorDetail,
} from "@/components/OrgCandidateParts"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Skeleton } from "@/components/ui/skeleton"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { IndeterminateCheckbox } from "@/components/ui/indeterminate-checkbox"
import { cn } from "@/lib/utils"

const PROPOSE = "entities.propose_candidate"
const PAGE = 200

function isNotFound(e: unknown) { return e instanceof ApiError && e.status === 404 }

// ── left panel ──────────────────────────────────────────────────────────────

function RootList({ orgs, activeId }: { orgs: OrganizationSummary[]; activeId?: string }) {
  if (orgs.length === 0) {
    return (
      <div className="p-4 text-sm text-muted-foreground space-y-1">
        <p className="font-medium text-foreground">No organizations yet</p>
        <p>An organization is added from its primary domain.</p>
      </div>
    )
  }
  return (
    <ul className="p-2 space-y-1">
      {orgs.map(o => (
        <li key={o.id}>
          <Link
            to={`/organizations/${o.id}`}
            className={cn("block rounded-md px-3 py-2 text-sm hover:bg-accent", o.id === activeId && "bg-primary/15 text-primary")}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium truncate">{o.name}</span>
              <span className="rounded-full border px-1.5 text-[10px] text-muted-foreground shrink-0">{orgPill(o)}</span>
            </div>
            <div className="text-xs text-muted-foreground">{o.proposed} to review</div>
          </Link>
        </li>
      ))}
    </ul>
  )
}

function TreeList({
  nodes, selected, onSelect,
}: { nodes: TreeNode[]; selected: string | null; onSelect: (id: string | null) => void }) {
  const rootId = nodes.find(n => n.parent_id === null)?.entity_id
  return (
    <ul className="p-2 space-y-0.5">
      {treeRows(nodes).map(({ node, indent, note, selectable }) => {
        const active = (selected ?? rootId) === node.entity_id
        const inner = (
          <>
            <span className="truncate">{node.name}</span>
            {node.status === "proposed" && <span className="ml-1 text-[10px] text-muted-foreground">proposed</span>}
            {note && <span className="block text-[11px] text-muted-foreground">{note}</span>}
          </>
        )
        return (
          <li key={node.entity_id} style={{ paddingLeft: indent * 12 }}>
            {selectable ? (
              <button
                type="button"
                onClick={() => onSelect(node.entity_id === rootId ? null : node.entity_id)}
                className={cn("w-full text-left rounded-md px-2 py-1.5 text-sm hover:bg-accent", active && "bg-primary/15 text-primary")}
              >
                {inner}
              </button>
            ) : (
              <div className="rounded-md px-2 py-1.5 text-sm opacity-50 cursor-not-allowed">{inner}</div>
            )}
          </li>
        )
      })}
    </ul>
  )
}

function LeftPanel({
  orgs, orgId, nodes, node, onNode,
}: { orgs: OrganizationSummary[]; orgId?: string; nodes: TreeNode[] | undefined; node: string | null; onNode: (id: string | null) => void }) {
  // The crumb shows the root list without leaving the org route (a bare
  // /organizations auto-forwards to the first root).
  const [browsing, setBrowsing] = useState(false)
  return (
    <aside className="w-[260px] shrink-0 border-r bg-card/30 overflow-y-auto">
      {orgId && !browsing ? (
        <>
          <button type="button" onClick={() => setBrowsing(true)}
            className="w-full text-left px-4 py-3 text-sm text-muted-foreground hover:text-foreground border-b">
            ‹ All organizations
          </button>
          {nodes ? <TreeList nodes={nodes} selected={node} onSelect={onNode} /> : <Skeleton className="m-3 h-20" />}
        </>
      ) : (
        <div onClick={() => setBrowsing(false)}><RootList orgs={orgs} activeId={orgId} /></div>
      )}
    </aside>
  )
}

// ── header pieces ───────────────────────────────────────────────────────────

function Kpi({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border bg-card px-3 py-2 min-w-[120px]">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold tabular-nums">{value}</div>
      {hint && <div className="text-[10px] text-muted-foreground">{hint}</div>}
    </div>
  )
}

function KpiRow({ s }: { s: OrgDetailSummary | undefined }) {
  return (
    <div className="flex flex-wrap gap-3">
      <Kpi label="Claimed domains" value={s?.claimed ?? "—"} />
      <Kpi label="Candidates to review" value={s?.to_review ?? "—"} />
      <Kpi label="Leads" value={s?.leads ?? "—"} />
      <Kpi label="Assets under claimed scope" value={s?.assets_under_claimed_scope ?? "—"} />
      <Kpi label="ASNs & prefixes" value="—" hint="after ASN discovery" />
    </div>
  )
}

function Placeholder({ text }: { text: string }) {
  return <div className="rounded-lg border bg-card p-12 text-center text-sm text-muted-foreground">{text}</div>
}

function NotFound() {
  return (
    <div className="flex-1 flex items-center justify-center p-12 text-center text-muted-foreground">
      <div><Building2 className="h-12 w-12 mx-auto mb-4 opacity-30" /><p className="font-medium">Organization not found</p></div>
    </div>
  )
}

// ── add-domain sheet ────────────────────────────────────────────────────────

function AddDomainSheet({
  orgId, nodes, onClose,
}: { orgId: string; nodes: TreeNode[]; onClose: () => void }) {
  const qc = useQueryClient()
  const confirmed = confirmedNodes(nodes)
  const rootId = confirmed.find(n => n.parent_id === null)?.entity_id ?? ""
  const [domain, setDomain] = useState("")
  const [sourceUrl, setSourceUrl] = useState("")
  const [quote, setQuote] = useState("")
  const [excerpt, setExcerpt] = useState("")
  const [via, setVia] = useState(rootId)
  const m = useMutation({
    mutationFn: () => api.post<CandidateRow>(`/organizations/${orgId}/candidates`, {
      domain: domain.trim(),
      via_entity_id: via || undefined,
      source_url: sourceUrl.trim(),
      quote: quote.trim(),
      excerpt: (excerpt.trim() || quote).trim(), // the API requires an excerpt
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["org-candidates", orgId] })
      void qc.invalidateQueries({ queryKey: ["org-summary", orgId] })
      void qc.invalidateQueries({ queryKey: ["organizations"] })
      onClose()
    },
  })
  const ready = domain.trim() && sourceUrl.trim() && quote.trim()
  return (
    <Sheet open onOpenChange={o => !o && onClose()}>
      <SheetContent className="w-[480px] sm:max-w-[480px] flex flex-col gap-4">
        <SheetHeader>
          <SheetTitle>Add domain</SheetTitle>
          <SheetDescription>Propose a domain with the source that says it belongs to this organization.</SheetDescription>
        </SheetHeader>
        <div className="space-y-1.5"><Label htmlFor="ad-domain">Domain</Label>
          <Input id="ad-domain" value={domain} onChange={e => setDomain(e.target.value)} placeholder="fabrikam.com" /></div>
        <div className="space-y-1.5"><Label htmlFor="ad-url">Source URL</Label>
          <Input id="ad-url" value={sourceUrl} onChange={e => setSourceUrl(e.target.value)} placeholder="https://" /></div>
        <div className="space-y-1.5"><Label htmlFor="ad-quote">Quote (required)</Label>
          <Textarea id="ad-quote" value={quote} onChange={e => setQuote(e.target.value)} /></div>
        <div className="space-y-1.5"><Label htmlFor="ad-excerpt">Excerpt (optional, defaults to the quote)</Label>
          <Textarea id="ad-excerpt" value={excerpt} onChange={e => setExcerpt(e.target.value)} /></div>
        <div className="space-y-1.5"><Label>Organization it belongs to</Label>
          <Select value={via} onValueChange={setVia}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>{confirmed.map(n => <SelectItem key={n.entity_id} value={n.entity_id}>{n.name}</SelectItem>)}</SelectContent>
          </Select></div>
        {m.isError && <p role="alert" className="text-sm text-destructive">{errorDetail(m.error)}</p>}
        <Button disabled={!ready || m.isPending} onClick={() => m.mutate()}>Add domain</Button>
      </SheetContent>
    </Sheet>
  )
}

// ── bulk claim ──────────────────────────────────────────────────────────────

type BulkResult = { id: string; value: string; ok: boolean; message?: string }

function BulkClaimDialog({
  rows, destination, onClose, onDone,
}: { rows: CandidateRow[]; destination: string; onClose: () => void; onDone: () => void }) {
  const [results, setResults] = useState<BulkResult[] | null>(null)
  const [running, setRunning] = useState(false)
  async function run() {
    setRunning(true)
    const out: BulkResult[] = []
    // Sequential on purpose: keeps the audit order and avoids lock contention.
    for (const r of rows) {
      try {
        await api.post(`/organizations/candidates/${r.id}/claim`, {})
        out.push({ id: r.id, value: r.value, ok: true })
      } catch (e) {
        out.push({ id: r.id, value: r.value, ok: false, message: `${e instanceof ApiError ? e.status : "error"}: ${errorDetail(e)}` })
      }
      setResults([...out])
    }
    setRunning(false)
    onDone()
  }
  return (
    <Dialog open onOpenChange={o => !o && !running && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Claim selected</DialogTitle>
          <DialogDescription>
            Claims {rows.length} domain{rows.length === 1 ? "" : "s"} into {destination}. Each claim is recorded separately.
          </DialogDescription>
        </DialogHeader>
        {results && (
          <ul className="text-sm space-y-1 max-h-64 overflow-y-auto">
            {results.map(r => (
              <li key={r.id} className={r.ok ? "" : "text-destructive"}>
                {r.ok ? "✓" : "✗"} <span className="font-mono">{r.value}</span>{r.ok ? " claimed" : ` failed ${r.message}`}
              </li>
            ))}
          </ul>
        )}
        <DialogFooter>
          <Button variant="outline" disabled={running} onClick={onClose}>{results && !running ? "Close" : "Cancel"}</Button>
          {!results && <Button disabled={running} onClick={() => void run()}>Claim {rows.length}</Button>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── candidate table ─────────────────────────────────────────────────────────

function CandidateTable({
  rows, group, labelOf, selectable, selected, onToggle, onToggleAll, onOpen, activeId,
}: {
  rows: CandidateRow[]
  group: OrgGroupMode
  labelOf: (t: string) => string
  selectable: boolean
  selected: Set<string>
  onToggle: (id: string) => void
  onToggleAll: (ids: string[], on: boolean) => void
  onOpen: (r: CandidateRow) => void
  activeId?: string
}) {
  const pickable = rows.filter(r => r.status === "open" && r.proposable)
  const allOn = pickable.length > 0 && pickable.every(r => selected.has(r.id))
  const groups = groupRows(rows, group, labelOf)
  const cols = selectable ? 8 : 7
  return (
    <Table>
      <TableHeader>
        <TableRow>
          {selectable && (
            <TableHead className="w-8">
              <IndeterminateCheckbox checked={allOn} indeterminate={!allOn && pickable.some(r => selected.has(r.id))}
                onChange={on => onToggleAll(pickable.map(r => r.id), on)} />
            </TableHead>
          )}
          <TableHead>Domain</TableHead><TableHead>Organization</TableHead><TableHead>State</TableHead>
          <TableHead>Strength</TableHead><TableHead>Signals</TableHead><TableHead>Assets · findings</TableHead><TableHead>First seen</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {groups.map(g => (
          <Fragment key={g.key}>
            <TableRow className="bg-muted/30 hover:bg-muted/30">
              <TableCell colSpan={cols} className="text-xs font-semibold text-muted-foreground">{g.label} ({g.rows.length})</TableCell>
            </TableRow>
            {g.rows.map(r => (
              <TableRow key={`${g.key}:${r.id}`} className={cn("cursor-pointer", r.id === activeId && "bg-accent/50")} onClick={() => onOpen(r)}>
                {selectable && (
                  <TableCell onClick={e => e.stopPropagation()}>
                    {r.status === "open" && r.proposable && (
                      <input type="checkbox" className="h-4 w-4 accent-primary" checked={selected.has(r.id)} onChange={() => onToggle(r.id)} />
                    )}
                  </TableCell>
                )}
                <TableCell className="font-mono text-sm">{r.value}</TableCell>
                <TableCell><OrganizationCell row={r} /></TableCell>
                <TableCell><StateCell row={r} /></TableCell>
                <TableCell className="text-sm">{STRENGTH_LABEL[r.strength] ?? r.strength}</TableCell>
                <TableCell><SignalsCell row={r} labelOf={labelOf} /></TableCell>
                <TableCell><AssetsCell row={r} /></TableCell>
                <TableCell className="text-xs text-muted-foreground">{relativeTime(r.first_seen_at)}</TableCell>
              </TableRow>
            ))}
          </Fragment>
        ))}
      </TableBody>
    </Table>
  )
}

// ── workspace for one organization ──────────────────────────────────────────

function OrgWorkspace({
  org, nodes, node, signalTypes,
}: { org: OrganizationSummary; nodes: TreeNode[]; node: string | null; signalTypes: SignalType[] }) {
  const qc = useQueryClient()
  const can = useCan()
  const [tab, setTab] = useUrlState("tab", "domains")
  const [segmentRaw, setSegment] = useUrlState("seg", "candidates")
  const segment = (SEGMENTS as string[]).includes(segmentRaw) ? (segmentRaw as Segment) : "candidates"
  const [q, setQ] = useDebouncedUrlState("q")
  const [qApplied] = useUrlState("q", "")
  const [strength, setStrength] = useUrlState("strength", "all")
  const [signal, setSignal] = useUrlState("signal", "all")
  const [groupRaw, setGroup] = useUrlState("group", "organization")
  const group = (GROUP_OPTIONS.some(o => o.value === groupRaw) ? groupRaw : "organization") as OrgGroupMode
  const [addOpen, setAddOpen] = useState(false)
  const [leadsOpen, setLeadsOpen] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulkOpen, setBulkOpen] = useState(false)

  const confirmed = useMemo(() => confirmedNodes(nodes), [nodes])
  const subtreeOf = node && confirmed.some(n => n.entity_id === node) ? node : null
  const labels = useMemo(() => new Map(signalTypes.map(s => [s.signal_type, s.label])), [signalTypes])
  const labelOf = (t: string) => labels.get(t) ?? t

  const summaryQ = useQuery({
    queryKey: ["org-summary", org.id, subtreeOf],
    queryFn: () => api.get<OrgDetailSummary>(`/organizations/${org.id}/summary${subtreeOf ? `?subtree_of=${subtreeOf}` : ""}`),
  })
  const summary = summaryQ.data

  const filters = { segment, q: qApplied, strength, signalType: signal, subtreeOf }
  const listKey = ["org-candidates", org.id, filters.segment, filters.q, filters.strength, filters.signalType, subtreeOf]
  const listQ = useInfiniteQuery({
    queryKey: listKey,
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.get<CandidatePage>(`/organizations/${org.id}/candidates?${candidateParams({ ...filters, limit: PAGE, offset: pageParam })}`),
    getNextPageParam: (last, all) => {
      const loaded = all.reduce((n, p) => n + p.items.length, 0)
      return loaded < last.total ? loaded : undefined
    },
  })
  const rows = useMemo(() => listQ.data?.pages.flatMap(p => p.items) ?? [], [listQ.data])
  const total = listQ.data?.pages[0]?.total ?? 0

  const showLeads = segment === "candidates"
  const leadsQ = useQuery({
    queryKey: ["org-candidates", org.id, "leads", qApplied, signal, subtreeOf],
    enabled: showLeads && leadsOpen,
    queryFn: () => api.get<CandidatePage>(
      `/organizations/${org.id}/candidates?${candidateParams({ ...filters, leadsOnly: true, limit: PAGE })}`),
  })
  const leadRows = leadsQ.data?.items ?? []

  const allRows = useMemo(() => [...rows, ...leadRows], [rows, leadRows])
  const { selected: openRow, open: openFlyout, close: closeFlyout } = useFlyout(allRows)

  const detailQ = useQuery({
    queryKey: ["org-candidate", openRow?.id],
    enabled: !!openRow,
    queryFn: () => api.get<CandidateDetail>(`/organizations/candidates/${openRow!.id}`),
  })

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ["org-candidates", org.id] })
    void qc.invalidateQueries({ queryKey: ["org-candidate"] })
    void qc.invalidateQueries({ queryKey: ["org-summary", org.id] })
    void qc.invalidateQueries({ queryKey: ["organizations"] })
  }

  // Selection never survives a change of what is on screen.
  useEffect(() => { setSelected(new Set()) }, [segment, qApplied, strength, signal, subtreeOf, org.id])

  const selectable = can(DECIDE) && (segment === "candidates" || segment === "all")
  const selectedRows = rows.filter(r => selected.has(r.id) && r.status === "open" && r.proposable)

  const tabs = [
    { key: "domains", label: "Domains", count: summary ? segmentCount(segment, summary) : undefined },
    { key: "asns", label: "ASNs & IP space" },
    { key: "acquisitions", label: "Acquisitions" },
    { key: "companies", label: "Companies & filings" },
  ]

  const builtSignals = signalTypes.filter(s => s.built)
  const toolbar = tab === "domains" ? (
    <>
      <div className="inline-flex rounded-md border h-9 p-0.5">
        {SEGMENTS.map(sg => (
          <button key={sg} type="button" aria-pressed={segment === sg} onClick={() => setSegment(sg)}
            className={cn("px-3 text-sm rounded", segment === sg ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground")}>
            {SEGMENT_LABEL[sg]}{summary ? ` ${segmentCount(sg, summary)}` : ""}
          </button>
        ))}
      </div>
      <Input className="w-48 h-9" placeholder="Filter domains…" value={q} onChange={e => setQ(e.target.value)} />
      <Select value={strength} onValueChange={setStrength}>
        <SelectTrigger className="w-36 h-9 text-sm"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="all">Any strength</SelectItem>
          <SelectItem value="strong">Strong</SelectItem>
          <SelectItem value="supporting">Supporting</SelectItem>
        </SelectContent>
      </Select>
      <Select value={signal} onValueChange={setSignal}>
        <SelectTrigger className="w-52 h-9 text-sm"><SelectValue /></SelectTrigger>
        <SelectContent>
          <SelectItem value="all">Any signal</SelectItem>
          {builtSignals.map(s => <SelectItem key={s.signal_type} value={s.signal_type}>{s.label}</SelectItem>)}
        </SelectContent>
      </Select>
      <Select value={group} onValueChange={setGroup}>
        <SelectTrigger className="w-48 h-9 text-sm"><SelectValue /></SelectTrigger>
        <SelectContent>{GROUP_OPTIONS.map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}</SelectContent>
      </Select>
      <span className="text-xs text-muted-foreground">{TIER_LEGEND}</span>
    </>
  ) : undefined

  const bulkBar = tab === "domains" && selectable && selectedRows.length > 0 ? (
    <div className="flex items-center gap-3 text-sm">
      <Button size="sm" onClick={() => setBulkOpen(true)}>Claim selected ({selectedRows.length})</Button>
      <button type="button" className="text-muted-foreground underline" onClick={() => setSelected(new Set())}>Clear</button>
    </div>
  ) : undefined

  const toggle = (id: string) => setSelected(prev => { const n = new Set(prev); if (n.has(id)) n.delete(id); else n.add(id); return n })
  const toggleAll = (ids: string[], on: boolean) => setSelected(prev => { const n = new Set(prev); ids.forEach(i => (on ? n.add(i) : n.delete(i))); return n })

  const tableProps = { group, labelOf, selected, onToggle: toggle, onToggleAll: toggleAll, onOpen: openFlyout, activeId: openRow?.id }

  let body: React.ReactNode
  if (tab === "asns") body = <Placeholder text="ASN and IP-space discovery is not built yet." />
  else if (tab === "acquisitions") body = <Placeholder text="Acquisition roll-ups are not built yet." />
  else if (tab === "companies") body = <Placeholder text="Companies & filings are not built yet." />
  else if (listQ.isLoading) body = <div className="space-y-2">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
  else if (listQ.isError) body = <Placeholder text={`Could not load domains: ${errorDetail(listQ.error)}`} />
  else {
    body = (
      <div className="space-y-4">
        {rows.length === 0
          ? <Placeholder text="No domains in this view." />
          : <CandidateTable rows={rows} selectable={selectable} {...tableProps} />}
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <span>Showing {rows.length} of {total}</span>
          {listQ.hasNextPage && (
            <Button size="sm" variant="outline" disabled={listQ.isFetchingNextPage} onClick={() => void listQ.fetchNextPage()}>Load more</Button>
          )}
        </div>
        {showLeads && (
          <div className="rounded-lg border">
            <button type="button" onClick={() => setLeadsOpen(o => !o)} className="w-full flex items-center gap-2 px-3 py-2 text-sm text-left">
              {leadsOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              <span className="font-medium">Leads ({summary?.leads ?? "…"})</span>
              <span className="text-xs text-muted-foreground">
                One Supporting signal so far — shown here until a second, independent signal arrives.
              </span>
            </button>
            {leadsOpen && (
              leadsQ.isLoading ? <Skeleton className="h-16 m-3" />
              : leadsQ.isError ? <p className="p-3 text-sm text-destructive">{errorDetail(leadsQ.error)}</p>
              : leadRows.length === 0 ? <p className="p-3 text-sm text-muted-foreground">No leads.</p>
              : <CandidateTable rows={leadRows} selectable={false} {...tableProps} />
            )}
          </div>
        )}
      </div>
    )
  }

  return (
    <>
      <WorkspaceShell
        title={org.name}
        subtitle={headerSubtitle(org, summary)}
        headerExtra={<KpiRow s={summary} />}
        tabs={tabs}
        activeTab={tab}
        onTabChange={t => { setTab(t); setSelected(new Set()) }}
        primaryAction={can(PROPOSE) ? (
          <Button size="sm" onClick={() => setAddOpen(true)}><Plus className="h-4 w-4 mr-1" />Add domain</Button>
        ) : undefined}
        toolbar={toolbar}
        bulkBar={bulkBar}
      >
        {body}
      </WorkspaceShell>

      {addOpen && <AddDomainSheet orgId={org.id} nodes={nodes} onClose={() => setAddOpen(false)} />}

      {bulkOpen && (
        <BulkClaimDialog rows={selectedRows} destination={destinationText(org)}
          onClose={() => { setBulkOpen(false); setSelected(new Set()) }} onDone={invalidate} />
      )}

      {openRow && (
        <Sheet open onOpenChange={o => !o && closeFlyout()}>
          <SheetContent className="w-[560px] sm:max-w-[560px] flex flex-col gap-0 p-0">
            <SheetHeader className="px-6 pt-5 pb-3 border-b shrink-0">
              <SheetTitle className="font-mono text-base">{openRow.value}</SheetTitle>
              <SheetDescription className="sr-only">Candidate domain detail</SheetDescription>
            </SheetHeader>
            {detailQ.isLoading ? <Skeleton className="m-6 h-40" />
              : detailQ.isError ? <p className="p-6 text-sm text-destructive">{errorDetail(detailQ.error)}</p>
              : detailQ.data && (
                <CandidateFlyoutContent
                  detail={detailQ.data} org={org} labelOf={labelOf} nodes={confirmed}
                  onClaim={async aff => {
                    await api.post(`/organizations/candidates/${detailQ.data!.id}/claim`, aff ? { affiliated_entity_id: aff } : {})
                    invalidate()
                  }}
                  onReject={async reason => {
                    await api.post(`/organizations/candidates/${detailQ.data!.id}/reject`, { reason })
                    invalidate()
                  }}
                />
              )}
          </SheetContent>
        </Sheet>
      )}
    </>
  )
}

// ── route component ─────────────────────────────────────────────────────────

export default function Organizations() {
  usePermissionsSync()
  const { orgId } = useParams<{ orgId?: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const node = searchParams.get("node")

  const orgsQ = useQuery({ queryKey: ["organizations"], queryFn: () => api.get<OrganizationSummary[]>("/organizations") })
  const orgs = orgsQ.data
  const org = orgs?.find(o => o.id === orgId)

  const treeQ = useQuery({
    queryKey: ["org-tree", orgId], enabled: !!orgId && !!org,
    queryFn: () => api.get<TreeNode[]>(`/organizations/${orgId}/tree`), retry: (n, e) => !isNotFound(e) && n < 2,
  })
  const sigQ = useQuery({
    queryKey: ["org-signal-types"], enabled: !!orgId,
    queryFn: () => api.get<SignalType[]>("/organizations/signal-types"), staleTime: 5 * 60_000,
  })

  if (orgsQ.isLoading) return <div className="p-6"><Skeleton className="h-40 w-full" /></div>
  if (orgsQ.isError) return <div className="p-6 text-sm text-destructive">Could not load organizations: {errorDetail(orgsQ.error)}</div>
  if (orgs && orgs.length === 0) {
    return (
      <div className="flex min-h-full">
        <LeftPanel orgs={[]} nodes={undefined} node={null} onNode={() => undefined} />
        <div className="flex-1 flex items-center justify-center p-12 text-center text-muted-foreground">
          <div><Building2 className="h-12 w-12 mx-auto mb-4 opacity-30" /><p className="font-medium">No organizations yet</p>
            <p className="text-sm mt-1">An organization is added from its primary domain.</p></div>
        </div>
      </div>
    )
  }
  if (!orgId && orgs && orgs.length > 0) return <Navigate to={`/organizations/${orgs[0].id}`} replace />

  const setNode = (id: string | null) =>
    setSearchParams(prev => { const n = new URLSearchParams(prev); if (id) n.set("node", id); else n.delete("node"); n.delete("id"); return n }, { replace: true })

  const notFound = (orgs && !org) || isNotFound(treeQ.error)
  return (
    <div className="flex min-h-full">
      <LeftPanel orgs={orgs ?? []} orgId={orgId} nodes={notFound ? undefined : treeQ.data} node={node} onNode={setNode} />
      <div className="flex-1 min-w-0">
        {notFound ? <NotFound />
          : org && treeQ.data && sigQ.data
            ? <OrgWorkspace key={org.id} org={org} nodes={treeQ.data} node={node} signalTypes={sigQ.data} />
            : treeQ.isError || sigQ.isError
              ? <div className="p-6 text-sm text-destructive">Could not load organization: {errorDetail(treeQ.error ?? sigQ.error)}</div>
              : <div className="p-6"><Skeleton className="h-40 w-full" /></div>}
      </div>
    </div>
  )
}
