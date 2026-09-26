import { useMemo, useState, type ReactNode } from "react"
import { Link, useParams } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Check, ChevronLeft, Loader2, Plus, SquareArrowOutUpRight, X } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import {
  api,
  type CandidateDomain,
  type Engagement,
  type EntityEdge,
  type EntityEdgeSource,
  type EntityFilingEvent,
  type EntityFilingSection,
  type OrgEntity,
  type SubsidiaryListingGroup,
} from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { openEvidence } from "@/lib/evidence"

// ── helpers ──────────────────────────────────────────────────────────────────

function EvidenceButton({ id }: { id: string }) {
  return (
    <button
      onClick={() => openEvidence(id)}
      className="inline-flex items-center text-muted-foreground hover:text-primary transition-colors"
      title="Open evidence"
    >
      <SquareArrowOutUpRight className="h-3.5 w-3.5" />
    </button>
  )
}

function Section({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h2 className="text-lg font-medium">
        {title}
        {count !== undefined && <span className="ml-2 text-sm text-muted-foreground">({count})</span>}
      </h2>
      {children}
    </section>
  )
}

function Empty({ children }: { children: ReactNode }) {
  return <p className="text-sm text-muted-foreground rounded-lg border bg-card p-4">{children}</p>
}

// An edge is read from THIS entity's side: "subject <relation> object".
function edgeGroup(edge: EntityEdge, selfId: string): string {
  const asSubject = edge.subject === selfId
  switch (edge.relation) {
    case "formerly_named": return asSubject ? "Former names" : "Later names"
    case "subsidiary_of": return asSubject ? "Parents" : "Subsidiaries"
    case "acquired": return asSubject ? "Acquisitions" : "Acquired by"
    case "dba": return asSubject ? "Doing business as" : "Trade name of"
    default: return edge.relation
  }
}
const GROUP_ORDER = ["Former names", "Later names", "Parents", "Acquired by", "Acquisitions", "Subsidiaries", "Doing business as", "Trade name of"]

function eventDate(s: EntityEdgeSource): string {
  if (!s.event_date) return "—"
  return s.precision === "day" || s.precision === "unknown" ? s.event_date : `${s.event_date} (${s.precision})`
}

// Same key as the ingest's one-proposal-per-first-appearance rule
// (exact name + jurisdiction), so this page and the proposals agree on what
// "appeared" means.
const listingKey = (r: { name: string; jurisdiction: string | null }) => `${r.name}\u0000${r.jurisdiction ?? ""}`

type ListingDiff = { group: SubsidiaryListingGroup; appeared: Set<string>; disappeared: SubsidiaryListingGroup["rows"]; first: boolean }

function diffListings(groups: SubsidiaryListingGroup[]): ListingDiff[] {
  // `groups` is newest first; each is compared with the next OLDER one.
  return groups.map((group, i) => {
    const older = groups[i + 1]
    if (!older) return { group, appeared: new Set(), disappeared: [], first: true }
    const olderKeys = new Set(older.rows.map(listingKey))
    const newerKeys = new Set(group.rows.map(listingKey))
    return {
      group,
      appeared: new Set(group.rows.map(listingKey).filter(k => !olderKeys.has(k))),
      disappeared: older.rows.filter(r => !newerKeys.has(listingKey(r))),
      first: false,
    }
  })
}

// A 10-K is annual, so a domain the filer still cites was cited within about
// a year. Past 18 months the filer has likely stopped citing it — and a
// domain nobody cites may have lapsed and been re-registered by a stranger.
const STALE_CITATION_DAYS = 548
function citationIsStale(lastCited: string | null): boolean {
  if (!lastCited) return false
  return (Date.now() - new Date(lastCited).getTime()) / 86_400_000 > STALE_CITATION_DAYS
}

// ── page ─────────────────────────────────────────────────────────────────────

export default function EntityDetail() {
  const { id = "" } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.role === "admin"

  const { data: entities, isLoading: entitiesLoading } = useQuery({
    queryKey: ["entities"],
    queryFn: () => api.get<OrgEntity[]>("/entities/"),
  })
  const entity = entities?.find(e => e.id === id)
  const nameById = useMemo(() => new Map((entities ?? []).map(e => [e.id, e.legal_name])), [entities])

  const { data: engagements } = useQuery({
    queryKey: ["engagements"],
    queryFn: () => api.get<Engagement[]>("/engagements/"),
  })
  const { data: edges } = useQuery({
    queryKey: ["entity-edges", id],
    queryFn: () => api.get<EntityEdge[]>(`/entities/${id}/edges`),
    enabled: !!id,
  })
  const { data: listings } = useQuery({
    queryKey: ["entity-listings", id],
    queryFn: () => api.get<SubsidiaryListingGroup[]>(`/entities/${id}/subsidiary-listings`),
    enabled: !!id,
  })
  const { data: events } = useQuery({
    queryKey: ["entity-events", id],
    queryFn: () => api.get<EntityFilingEvent[]>(`/entities/${id}/filing-events`),
    enabled: !!id,
  })
  const { data: sections } = useQuery({
    queryKey: ["entity-sections", id],
    queryFn: () => api.get<EntityFilingSection[]>(`/entities/${id}/filing-sections`),
    enabled: !!id,
  })
  const { data: candidates } = useQuery({
    queryKey: ["entity-candidates", id],
    queryFn: () => api.get<CandidateDomain[]>(`/entities/${id}/candidate-domains`),
    enabled: !!id,
  })

  const subjectOf = (engagements ?? []).filter(e => e.subject_entity_id === id)
  const engagementName = useMemo(() => new Map((engagements ?? []).map(e => [e.id, e.name])), [engagements])

  const groupedEdges = useMemo(() => {
    const m = new Map<string, EntityEdge[]>()
    for (const e of edges ?? []) {
      const g = edgeGroup(e, id)
      m.set(g, [...(m.get(g) ?? []), e])
    }
    return [...m.entries()].sort(([a], [b]) => {
      const ia = GROUP_ORDER.indexOf(a), ib = GROUP_ORDER.indexOf(b)
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib)
    })
  }, [edges, id])

  const listingDiffs = useMemo(() => diffListings(listings ?? []), [listings])

  // ── mutations ──
  const decisionMutation = useMutation({
    mutationFn: ({ relationId, status }: { relationId: string; status: "confirmed" | "rejected" }) =>
      api.post(`/entities/relations/${relationId}/decision`, { status }),
    onSuccess: () => {
      toast.success("Decision recorded")
      qc.invalidateQueries({ queryKey: ["entity-edges", id] })
      qc.invalidateQueries({ queryKey: ["entity-relations"] })
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to record decision"),
  })

  const [subjectPick, setSubjectPick] = useState<string>("")
  const [subjectConfirm, setSubjectConfirm] = useState<Engagement | null>(null)
  const subjectMutation = useMutation({
    mutationFn: (engagementId: string) => api.patch(`/engagements/${engagementId}`, { subject_entity_id: id }),
    onSuccess: () => {
      toast.success("Engagement subject set")
      setSubjectPick("")
      setSubjectConfirm(null)
      qc.invalidateQueries({ queryKey: ["engagements"] })
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to set subject"),
  })
  const chooseSubject = (engagementId: string) => {
    const eng = engagements?.find(e => e.id === engagementId)
    if (!eng) return
    if (eng.subject_entity_id && eng.subject_entity_id !== id) setSubjectConfirm(eng)
    else subjectMutation.mutate(eng.id)
  }

  const [acceptFor, setAcceptFor] = useState<CandidateDomain | null>(null)
  const [acceptEngagement, setAcceptEngagement] = useState("")
  const [acceptError, setAcceptError] = useState<string | null>(null)
  const acceptMutation = useMutation({
    mutationFn: ({ cid, engagementId }: { cid: string; engagementId: string }) =>
      api.post(`/entities/candidate-domains/${cid}/accept`, { engagement_id: engagementId }),
    onSuccess: () => {
      toast.success("Accepted — passive discovery queued")
      setAcceptFor(null)
      qc.invalidateQueries({ queryKey: ["entity-candidates", id] })
    },
    // Shown verbatim in the dialog: a 409 says WHY (engagement subject is
    // not this entity or one confirmed hop from it; target already elsewhere).
    onError: (e: { message?: string }) => setAcceptError(e?.message ?? "Failed to accept"),
  })
  const rejectMutation = useMutation({
    mutationFn: (cid: string) => api.post(`/entities/candidate-domains/${cid}/reject`),
    onSuccess: () => {
      toast.success("Candidate rejected")
      qc.invalidateQueries({ queryKey: ["entity-candidates", id] })
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to reject"),
  })

  const [addOpen, setAddOpen] = useState(false)
  const [addForm, setAddForm] = useState({ domain: "", source_url: "", excerpt: "", quote: "" })
  const [addError, setAddError] = useState<string | null>(null)
  const addMutation = useMutation({
    mutationFn: () => api.post(`/entities/${id}/candidate-domains`, addForm),
    onSuccess: () => {
      toast.success("Candidate added")
      setAddOpen(false)
      setAddForm({ domain: "", source_url: "", excerpt: "", quote: "" })
      qc.invalidateQueries({ queryKey: ["entity-candidates", id] })
    },
    onError: (e: { message?: string }) => setAddError(e?.message ?? "Failed to add candidate"),
  })

  if (entitiesLoading) {
    return <div className="p-6 max-w-6xl mx-auto space-y-3">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}</div>
  }
  if (!entity) {
    return (
      <div className="p-6 max-w-6xl mx-auto space-y-4">
        <Link to="/entities" className="inline-flex items-center text-sm text-muted-foreground hover:text-primary">
          <ChevronLeft className="h-4 w-4" /> Entities
        </Link>
        <Empty>Entity not found.</Empty>
      </div>
    )
  }

  const liveEngagements = (engagements ?? []).filter(e => e.posture !== "abandoned")

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-8">
      <div className="space-y-2">
        <Link to="/entities" className="inline-flex items-center text-sm text-muted-foreground hover:text-primary">
          <ChevronLeft className="h-4 w-4" /> Entities
        </Link>
        <h1 className="text-2xl font-semibold">{entity.legal_name}</h1>
        <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-muted-foreground">
          <span>CIK <span className="font-mono">{entity.cik ?? "—"}</span></span>
          {entity.lei && <span>LEI <span className="font-mono">{entity.lei}</span></span>}
        </div>
        <div className="text-sm flex flex-wrap items-center gap-2">
          <span className="text-muted-foreground">Subject of:</span>
          {subjectOf.length ? subjectOf.map(e => (
            isAdmin
              ? <Link key={e.id} to={`/admin/engagements/${e.id}`} className="hover:text-primary"><Badge variant="outline">{e.name}</Badge></Link>
              : <Badge key={e.id} variant="outline">{e.name}</Badge>
          )) : <span className="text-muted-foreground">no engagement</span>}
          {isAdmin && (
            // Pick, then act: opening the confirm Dialog straight from
            // onValueChange races the Select's own close, and Radix leaves
            // `pointer-events: none` on <body> — the page freezes.
            <>
              <Select value={subjectPick} onValueChange={setSubjectPick}>
                <SelectTrigger className="h-8 w-64" aria-label="Use as subject of engagement">
                  <SelectValue placeholder="Use as subject of engagement…" />
                </SelectTrigger>
                <SelectContent>
                  {liveEngagements.filter(e => e.subject_entity_id !== id).map(e => (
                    <SelectItem key={e.id} value={e.id}>{e.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm" variant="outline" className="h-8"
                disabled={!subjectPick || subjectMutation.isPending}
                onClick={() => chooseSubject(subjectPick)}
              >
                Set subject
              </Button>
            </>
          )}
        </div>
      </div>

      {/* ── corporate family ── */}
      <Section title="Corporate family" count={edges?.length}>
        {!edges?.length ? <Empty>No relationships recorded.</Empty> : groupedEdges.map(([group, list]) => (
          <div key={group} className="space-y-1">
            <h3 className="text-sm font-medium text-muted-foreground">{group} ({list.length})</h3>
            <div className="rounded-lg border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Entity</TableHead>
                    <TableHead className="w-28">State</TableHead>
                    <TableHead>Sources</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map(edge => {
                    const other = edge.subject === id ? edge.object : edge.subject
                    return (
                      <TableRow key={`${edge.subject}-${edge.object}-${edge.relation}`}>
                        <TableCell className="font-medium align-top">
                          <Link to={`/entities/${other}`} className="hover:text-primary">{nameById.get(other) ?? other}</Link>
                        </TableCell>
                        <TableCell className="align-top">
                          {edge.confirmed ? <Badge>Confirmed</Badge> : <Badge variant="outline">Proposed</Badge>}
                        </TableCell>
                        <TableCell className="space-y-1">
                          {edge.sources.map(s => (
                            <div key={s.relation_id} className="flex flex-wrap items-center gap-2 text-xs">
                              <span>{s.observer ?? "—"}</span>
                              {s.trust === "inferred" && <Badge variant="outline">AI</Badge>}
                              <span className="text-muted-foreground">{s.status}</span>
                              <span className="text-muted-foreground">{eventDate(s)}</span>
                              <EvidenceButton id={s.evidence_id} />
                              {isAdmin && s.status === "proposed" && (
                                <span className="flex gap-1">
                                  <Button
                                    size="sm" variant="outline" className="h-6 px-2" title="Confirm"
                                    disabled={decisionMutation.isPending}
                                    onClick={() => decisionMutation.mutate({ relationId: s.relation_id, status: "confirmed" })}
                                  >
                                    <Check className="h-3 w-3" />
                                  </Button>
                                  <Button
                                    size="sm" variant="outline" className="h-6 px-2" title="Reject"
                                    disabled={decisionMutation.isPending}
                                    onClick={() => decisionMutation.mutate({ relationId: s.relation_id, status: "rejected" })}
                                  >
                                    <X className="h-3 w-3" />
                                  </Button>
                                </span>
                              )}
                            </div>
                          ))}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            </div>
          </div>
        ))}
      </Section>

      {/* ── candidate domains ── */}
      <Section title="Candidate domains" count={candidates?.length}>
        {isAdmin && (
          <Button size="sm" variant="outline" onClick={() => { setAddError(null); setAddOpen(true) }}>
            <Plus className="h-3.5 w-3.5 mr-1" /> Add with evidence
          </Button>
        )}
        {!candidates?.length ? <Empty>No candidate domains. The 10-K website sentence finds the filer's own; add others with evidence.</Empty> : (
          <div className="rounded-lg border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Domain</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Quote</TableHead>
                  <TableHead>Cited</TableHead>
                  <TableHead>Status</TableHead>
                  {isAdmin && <TableHead className="w-40">Decision</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {candidates.map(c => (
                  <TableRow key={c.id} data-testid="candidate-row">
                    <TableCell className="font-mono text-sm">{c.domain}</TableCell>
                    <TableCell className="text-xs">
                      <div className="flex items-center gap-1.5">
                        <span>{c.observer_name ?? "manual"}</span>
                        {c.evidence_origin === "person_supplied" && <Badge variant="outline">Person-supplied</Badge>}
                        <EvidenceButton id={c.evidence_id} />
                      </div>
                    </TableCell>
                    <TableCell className="max-w-xs truncate text-xs text-muted-foreground" title={c.quote}>{c.quote}</TableCell>
                    <TableCell className="text-xs whitespace-nowrap">
                      {c.first_cited_on || c.last_cited_on ? (
                        <>
                          <div className="text-muted-foreground">first {c.first_cited_on ?? "—"}</div>
                          <div className={citationIsStale(c.last_cited_on) ? "text-amber-600 dark:text-amber-400" : ""}>
                            last {c.last_cited_on ?? "—"}
                          </div>
                          {citationIsStale(c.last_cited_on) && (
                            <div className="text-amber-600 dark:text-amber-400">not cited recently — may have lapsed</div>
                          )}
                        </>
                      ) : <span className="text-muted-foreground">not from a filing</span>}
                    </TableCell>
                    <TableCell className="text-xs">
                      <Badge variant={c.status === "accepted" ? "default" : "outline"}>{c.status}</Badge>
                      {c.engagement_id && (
                        <div className="text-muted-foreground mt-1">into {engagementName.get(c.engagement_id) ?? c.engagement_id}</div>
                      )}
                      {c.target_id && (
                        <Link to={`/targets/${c.target_id}`} className="text-muted-foreground hover:text-primary">target</Link>
                      )}
                    </TableCell>
                    {isAdmin && (
                      <TableCell>
                        {c.status === "proposed" && (
                          <div className="flex gap-1">
                            <Button
                              size="sm" variant="outline"
                              onClick={() => { setAcceptError(null); setAcceptEngagement(subjectOf[0]?.id ?? ""); setAcceptFor(c) }}
                            >
                              Accept
                            </Button>
                            <Button
                              size="sm" variant="outline" title="Reject"
                              disabled={rejectMutation.isPending}
                              onClick={() => rejectMutation.mutate(c.id)}
                            >
                              <X className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        )}
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </Section>

      {/* ── subsidiary history ── */}
      <Section title="Subsidiary history (EX-21)" count={listings?.length}>
        {!listingDiffs.length ? <Empty>No EX-21 subsidiary listings stored.</Empty> : listingDiffs.map((d, i) => (
          <details key={d.group.accession_number} open={i === 0} className="rounded-lg border bg-card">
            <summary className="cursor-pointer px-4 py-2 text-sm flex items-center gap-3">
              <span className="font-medium">Filed {d.group.filing_date}</span>
              <span className="text-muted-foreground">{d.group.exhibit_type} · {d.group.rows.length} listed</span>
              {d.first ? (
                <span className="text-muted-foreground">first listing</span>
              ) : (
                <>
                  <span className="text-green-700 dark:text-green-400">+{d.appeared.size} appeared</span>
                  <span className="text-red-700 dark:text-red-400">−{d.disappeared.length} disappeared</span>
                </>
              )}
              <EvidenceButton id={d.group.evidence_id} />
            </summary>
            <div className="px-4 pb-3 text-sm space-y-2">
              <ul className="space-y-0.5">
                {d.group.rows.map((r, j) => {
                  const appeared = d.appeared.has(listingKey(r))
                  return (
                    <li key={j} className={appeared ? "text-green-700 dark:text-green-400" : ""} data-appeared={appeared || undefined}>
                      {appeared && "+ "}
                      {r.subsidiary_entity_id
                        ? <Link to={`/entities/${r.subsidiary_entity_id}`} className="hover:underline">{r.name}</Link>
                        : r.name}
                      {r.jurisdiction && <span className="text-muted-foreground"> — {r.jurisdiction}</span>}
                    </li>
                  )
                })}
              </ul>
              {!!d.disappeared.length && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground mt-2">Not listed any more (was in the previous EX-21):</p>
                  <ul className="space-y-0.5">
                    {d.disappeared.map((r, j) => (
                      <li key={j} className="text-red-700 dark:text-red-400 line-through" data-disappeared>
                        {r.name}{r.jurisdiction && ` — ${r.jurisdiction}`}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </details>
        ))}
      </Section>

      {/* ── filing events ── */}
      <Section title="Filing events (8-K)" count={events?.length}>
        {!events?.length ? <Empty>No 8-K events recorded.</Empty> : (
          <div className="rounded-lg border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Filed</TableHead>
                  <TableHead>Form</TableHead>
                  <TableHead>Items</TableHead>
                  <TableHead>Accession</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map(ev => (
                  <TableRow key={ev.id}>
                    <TableCell className="text-xs">{ev.filing_date}</TableCell>
                    <TableCell className="text-xs">{ev.form}</TableCell>
                    <TableCell className="text-xs font-mono">{ev.items}</TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground">{ev.accession_number}</TableCell>
                    <TableCell><EvidenceButton id={ev.evidence_id} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </Section>

      {/* ── stored footnote sections ── */}
      <Section title="Stored footnote sections" count={sections?.length}>
        {!sections?.length ? <Empty>No footnote sections stored.</Empty> : sections.map(s => (
          <details key={s.id} className="rounded-lg border bg-card">
            <summary className="cursor-pointer px-4 py-2 text-sm flex items-center gap-3">
              <span className="font-medium">{s.form} filed {s.filing_date}</span>
              <span className="text-muted-foreground truncate">{s.heading}</span>
              {s.heading_match_count > 1 && (
                <span className="text-xs text-muted-foreground">{s.heading_match_count} heading matches</span>
              )}
              <EvidenceButton id={s.evidence_id} />
            </summary>
            {/* Text only — never rendered as HTML. */}
            <pre className="px-4 pb-3 text-xs whitespace-pre-wrap max-h-96 overflow-auto">{s.text}</pre>
          </details>
        ))}
      </Section>

      {/* ── dialogs ── */}
      <Dialog open={!!subjectConfirm} onOpenChange={open => { if (!open) { setSubjectConfirm(null); setSubjectPick("") } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Replace the engagement's subject?</DialogTitle>
            <DialogDescription>
              "{subjectConfirm?.name}" is currently attributed to{" "}
              {nameById.get(subjectConfirm?.subject_entity_id ?? "") ?? "another entity"}. It will be attributed to{" "}
              {entity.legal_name} instead.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setSubjectConfirm(null); setSubjectPick("") }}>Cancel</Button>
            <Button disabled={subjectMutation.isPending} onClick={() => subjectConfirm && subjectMutation.mutate(subjectConfirm.id)}>
              {subjectMutation.isPending && <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />}
              Replace
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!acceptFor} onOpenChange={open => { if (!open) setAcceptFor(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Accept {acceptFor?.domain}</DialogTitle>
            <DialogDescription>
              Adds the domain as a target in the chosen engagement and queues passive discovery under that engagement's posture.
              The engagement's subject must be this entity, or one confirmed acquisition/subsidiary hop from it.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1">
            <Label>Engagement</Label>
            <Select value={acceptEngagement} onValueChange={setAcceptEngagement}>
              <SelectTrigger aria-label="Engagement"><SelectValue placeholder="Choose an engagement" /></SelectTrigger>
              <SelectContent>
                {liveEngagements.map(e => (
                  <SelectItem key={e.id} value={e.id}>
                    {e.name}{e.subject_entity_id === id ? " (subject: this entity)" : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {acceptError && <p className="text-sm text-destructive" role="alert">{acceptError}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => setAcceptFor(null)}>Cancel</Button>
            <Button
              disabled={!acceptEngagement || acceptMutation.isPending}
              onClick={() => { setAcceptError(null); acceptFor && acceptMutation.mutate({ cid: acceptFor.id, engagementId: acceptEngagement }) }}
            >
              {acceptMutation.isPending && <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />}
              Accept
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add a candidate domain</DialogTitle>
            <DialogDescription>
              A candidate needs evidence: paste the excerpt you read and the URL it came from. The quote must appear in the
              excerpt and contain the domain. Stored as person-supplied; nothing is fetched.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {(["domain", "source_url", "quote"] as const).map(k => (
              <div key={k} className="space-y-1">
                <Label htmlFor={`add-${k}`}>{k === "source_url" ? "Source URL" : k[0].toUpperCase() + k.slice(1)}</Label>
                <Input id={`add-${k}`} value={addForm[k]} onChange={e => setAddForm(f => ({ ...f, [k]: e.target.value }))} />
              </div>
            ))}
            <div className="space-y-1">
              <Label htmlFor="add-excerpt">Excerpt</Label>
              <Textarea id="add-excerpt" rows={5} value={addForm.excerpt} onChange={e => setAddForm(f => ({ ...f, excerpt: e.target.value }))} />
            </div>
          </div>
          {addError && <p className="text-sm text-destructive" role="alert">{addError}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button
              disabled={addMutation.isPending || !addForm.domain || !addForm.source_url || !addForm.excerpt || !addForm.quote}
              onClick={() => { setAddError(null); addMutation.mutate() }}
            >
              {addMutation.isPending && <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />}
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
