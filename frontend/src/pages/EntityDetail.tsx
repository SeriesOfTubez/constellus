import { useEffect, useMemo, useState, type ReactNode } from "react"
import { Link, useParams } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Check, ChevronLeft, Loader2, Plus, Sparkles, SquareArrowOutUpRight, X } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { RegistrantLinkPanel } from "@/components/RegistrantLinkPanel"
import {
  api,
  type CandidateDomain,
  type DroppedAcquisition,
  type Engagement,
  type EntityDestination,
  type EntityEdge,
  type EntityEdgeSource,
  type EntityFilingEvent,
  type EntityFilingSection,
  type EntityIngestRun,
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

// planning#218 — the few counters worth a glance; the full result is on the
// status line's title.
function readSummary(run: EntityIngestRun): string {
  const r = run.result
  if (!r) return ""
  const n = (k: string) => (typeof r[k] === "number" ? (r[k] as number) : 0)
  const parts = [
    `${n("sections_read")}/${n("sections_total")} sections read`,
    `${n("proposed")} proposed`,
  ]
  if (n("items_existing")) parts.push(`${n("items_existing")} already known`)
  if (n("items_ungrounded")) parts.push(`${n("items_ungrounded")} dropped (not in the text)`)
  if (n("items_filtered")) parts.push(`${n("items_filtered")} filtered`)
  if (n("names_from_variant")) parts.push(`${n("names_from_variant")} matched by a shorter name`)
  if (n("sections_failed")) parts.push(`${n("sections_failed")} sections failed`)
  if (n("sections_truncated")) parts.push(`${n("sections_truncated")} cut to fit`)
  parts.push(`LLM cost $${n("cost_usd").toFixed(4)} over ${n("calls")} calls`)
  return parts.join(" · ")
}

const READ_BADGE: Record<EntityIngestRun["status"], "default" | "secondary" | "destructive" | "outline"> = {
  queued: "outline",
  running: "secondary",
  succeeded: "default",
  failed: "destructive",
}

// planning#235 — the reader's own account of what it read but did not
// propose. Parsed defensively: `result` is not a typed API response, and
// these strings are copied from a public filing, never trusted as markup.
const DROPPED_REASON_LABEL: Record<string, string> = {
  filtered: "not a named business",
  quote_not_in_text: "quote not found in the section",
  name_not_in_quote: "name not in its quote",
}

function isDroppedAcquisition(v: unknown): v is DroppedAcquisition {
  if (typeof v !== "object" || v === null) return false
  const r = v as Record<string, unknown>
  return typeof r.name === "string" && typeof r.reason === "string" && typeof r.filing_date === "string"
}

function droppedItems(run: EntityIngestRun): DroppedAcquisition[] {
  const v = run.result?.dropped_items
  if (!Array.isArray(v)) return []
  return (v as unknown[]).filter(isDroppedAcquisition)
}

function droppedItemsOmitted(run: EntityIngestRun): number {
  const v = run.result?.dropped_items_omitted
  return typeof v === "number" ? v : 0
}

function AcquisitionReadPanel({ isAdmin, run, hasSections, busy, onStart }: {
  isAdmin: boolean
  run: EntityIngestRun | undefined
  hasSections: boolean
  busy: boolean
  onStart: () => void
}) {
  return (
    <div className="rounded-lg border bg-card p-3 space-y-2 text-sm">
      {isAdmin && (
        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="sm" variant="outline" disabled={!hasSections || busy} onClick={onStart}
            title={hasSections ? undefined : "No Business Combinations section is stored yet. Map this company from EDGAR first."}
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5 mr-1.5" />}
            Read acquisitions with AI
          </Button>
          <span className="text-xs text-muted-foreground">
            Proposals only. Each name and quote is checked against the stored Business Combinations
            section; a person confirms or rejects every one.
          </span>
        </div>
      )}
      {run && (
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2 text-xs" title={JSON.stringify(run.result ?? {}, null, 1)}>
            <span className="text-muted-foreground">Last AI read</span>
            <Badge variant={READ_BADGE[run.status]}>{run.status}</Badge>
            <span className="text-muted-foreground">{readSummary(run)}</span>
            {run.error && <span className="text-destructive">{run.error}</span>}
          </div>
          {droppedItems(run).length > 0 && (
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground">
                Show {droppedItems(run).length + droppedItemsOmitted(run)} dropped
              </summary>
              <ul className="mt-1 space-y-0.5 pl-3">
                {droppedItems(run).map((d, i) => (
                  <li key={i} className="flex flex-wrap items-baseline gap-x-1.5">
                    <span className="font-medium">{d.name}</span>
                    <span className="text-muted-foreground">{DROPPED_REASON_LABEL[d.reason] ?? d.reason}</span>
                    <span className="text-muted-foreground">10-K {d.filing_date.slice(0, 4)}</span>
                  </li>
                ))}
              </ul>
              {droppedItemsOmitted(run) > 0 && (
                <p className="mt-0.5 text-muted-foreground">…and {droppedItemsOmitted(run)} more not listed</p>
              )}
            </details>
          )}
        </div>
      )}
    </div>
  )
}

export default function EntityDetail() {
  const { id = "" } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.role === "admin"
  // planning#240: marking a company ours is an authorisation (admin only);
  // M&A target is admin + integration_admin, the same pair that may create
  // an engagement.
  const canMarkOurs = user?.role === "admin"
  const canMarkTarget = user?.role === "admin" || user?.role === "integration_admin"

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
  // planning#240: where this company's accepted candidate domains go.
  const { data: destination, isLoading: destinationLoading } = useQuery({
    queryKey: ["entity-destination", id],
    queryFn: () => api.get<EntityDestination>(`/entities/${id}/destination`),
    enabled: !!id,
  })

  // planning#218: the AI read of this filer's stored Business Combinations
  // sections. Polls only while a run is in flight.
  const { data: readRuns } = useQuery({
    queryKey: ["entity-acquisition-reads", id],
    queryFn: () => api.get<EntityIngestRun[]>(`/entities/${id}/acquisition-read/runs?limit=1`),
    enabled: !!id,
    refetchInterval: q =>
      (q.state.data ?? []).some(r => r.status === "queued" || r.status === "running") ? 3000 : false,
  })
  const lastRead = readRuns?.[0]
  const readActive = lastRead?.status === "queued" || lastRead?.status === "running"
  // A finished read creates entities and proposals: refresh both once.
  const finishedReadId = lastRead?.finished_at ? lastRead.id : ""
  useEffect(() => {
    if (!finishedReadId) return
    qc.invalidateQueries({ queryKey: ["entities"] })
    qc.invalidateQueries({ queryKey: ["entity-edges", id] })
  }, [finishedReadId, id, qc])

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

  const readMutation = useMutation({
    mutationFn: () => api.post(`/entities/${id}/acquisition-read`),
    onSuccess: () => {
      toast.success("AI read started")
      qc.invalidateQueries({ queryKey: ["entity-acquisition-reads", id] })
    },
    onError: (e: { message?: string }) => toast.error(e?.message ?? "Failed to start the AI read"),
  })

  // planning#240 — "relationship to us" dialogs. One mutation for the PUT;
  // which dialog is open and its own form fields are separate state so the
  // error from a failed attempt stays scoped to the dialog that caused it.
  const [oursOpen, setOursOpen] = useState(false)
  const [oursReference, setOursReference] = useState("")
  const [targetOpen, setTargetOpen] = useState(false)
  const [targetMode, setTargetMode] = useState<"new" | "existing">("new")
  const [targetName, setTargetName] = useState("")
  const [targetEngagementId, setTargetEngagementId] = useState("")
  const [clearOpen, setClearOpen] = useState(false)
  const [relationshipError, setRelationshipError] = useState<string | null>(null)
  const relationshipMutation = useMutation({
    mutationFn: (body: { relationship: "ours" | "ma_target" | null; reference?: string; engagement_id?: string; new_engagement_name?: string }) =>
      api.put<OrgEntity>(`/entities/${id}/relationship`, body),
    onSuccess: () => {
      toast.success("Relationship updated")
      setOursOpen(false)
      setOursReference("")
      setTargetOpen(false)
      setTargetMode("new")
      setTargetName("")
      setTargetEngagementId("")
      setClearOpen(false)
      qc.invalidateQueries({ queryKey: ["entities"] })
      qc.invalidateQueries({ queryKey: ["engagements"] })
      qc.invalidateQueries({ queryKey: ["entity-destination", id] })
    },
    // Shown verbatim inside whichever dialog triggered it.
    onError: (e: { message?: string }) => setRelationshipError(e?.message ?? "Failed to update relationship"),
  })

  const [acceptFor, setAcceptFor] = useState<CandidateDomain | null>(null)
  // planning#240: only meaningful when the destination is `ambiguous` —
  // "estate" or an engagement id. Never pre-set; the user must choose.
  const [acceptChoice, setAcceptChoice] = useState("")
  const [acceptError, setAcceptError] = useState<string | null>(null)
  const acceptMutation = useMutation({
    mutationFn: ({ cid, body }: { cid: string; body: { estate?: boolean; engagement_id?: string } }) =>
      api.post(`/entities/candidate-domains/${cid}/accept`, body),
    onSuccess: () => {
      toast.success("Accepted — discovery queued")
      setAcceptFor(null)
      qc.invalidateQueries({ queryKey: ["entity-candidates", id] })
      qc.invalidateQueries({ queryKey: ["entity-destination", id] })
    },
    // Shown verbatim in the dialog: a 409 says WHY (unset/abandoned destination,
    // target already elsewhere).
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
  // planning#240: the "existing engagement" picker in the M&A dialog — live
  // and not already a subject, since linking one that already has a subject
  // is refused server-side (409).
  const unassignedLiveEngagements = liveEngagements.filter(e => e.subject_entity_id === null)

  // The stop that produced a single-destination answer, for the "Inherited
  // from …" line. For an engagement, its own subject: another `ma_target`
  // stop on a different path may hold only abandoned engagements.
  const relevantStop = !destination
    ? undefined
    : destination.status === "ours"
      ? destination.stops.find(s => s.relationship === "ours")
      : destination.status === "engagement"
        ? destination.stops.find(s => s.entity_id === destination.engagements[0]?.subject_entity_id)
        : undefined

  const acceptDisabled =
    acceptMutation.isPending || destinationLoading || !destination ||
    destination.status === "unset" || destination.status === "abandoned" ||
    (destination.status === "ambiguous" && !acceptChoice)

  const acceptBody = (): { estate?: boolean; engagement_id?: string } => {
    if (destination?.status === "ambiguous") {
      if (acceptChoice === "estate") return { estate: true }
      if (acceptChoice) return { engagement_id: acceptChoice }
    }
    return {}
  }

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
          <span className="text-muted-foreground">Relationship to us:</span>
          {entity.relationship === null && (
            <>
              <Badge variant="outline">Not set</Badge>
              <span className="text-muted-foreground">browse only — accepting domains is blocked until this is set</span>
            </>
          )}
          {entity.relationship === "ours" && (
            <>
              <Badge>Our company</Badge>
              <span className="text-muted-foreground">
                authorised {entity.ours_authorised_at ? new Date(entity.ours_authorised_at).toLocaleDateString() : "—"} · ref {entity.ours_reference}
              </span>
            </>
          )}
          {entity.relationship === "ma_target" && (
            <>
              <Badge>M&A target</Badge>
              <span className="text-muted-foreground">Subject of:</span>
              {subjectOf.length ? subjectOf.map(e => (
                isAdmin
                  ? <Link key={e.id} to={`/admin/engagements/${e.id}`} className="hover:text-primary"><Badge variant="outline">{e.name}</Badge></Link>
                  : <Badge key={e.id} variant="outline">{e.name}</Badge>
              )) : <span className="text-muted-foreground">no engagement</span>}
            </>
          )}
          {canMarkOurs && entity.relationship !== "ours" && subjectOf.length === 0 && (
            <Button
              size="sm" variant="outline" className="h-8"
              onClick={() => { setRelationshipError(null); setOursReference(""); setOursOpen(true) }}
            >
              Mark as ours…
            </Button>
          )}
          {canMarkTarget && (entity.relationship !== "ours" || canMarkOurs) && (
            <Button
              size="sm" variant="outline" className="h-8"
              onClick={() => {
                setRelationshipError(null)
                setTargetMode(entity.relationship === "ma_target" ? "existing" : "new")
                setTargetName("")
                setTargetEngagementId("")
                setTargetOpen(true)
              }}
            >
              {entity.relationship === "ma_target" ? "Link another engagement…" : "Mark as M&A target…"}
            </Button>
          )}
          {entity.relationship !== null && subjectOf.length === 0 && (entity.relationship !== "ours" || canMarkOurs) && (
            <Button
              size="sm" variant="outline" className="h-8"
              onClick={() => { setRelationshipError(null); setClearOpen(true) }}
            >
              Clear
            </Button>
          )}
        </div>
        <RegistrantLinkPanel entity={entity} isAdmin={isAdmin} />
      </div>

      {/* ── corporate family ── */}
      <Section title="Corporate family" count={edges?.length}>
        {(isAdmin || lastRead) && (
          <AcquisitionReadPanel
            isAdmin={isAdmin}
            run={lastRead}
            hasSections={!!sections?.length}
            busy={readActive || readMutation.isPending}
            onStart={() => readMutation.mutate()}
          />
        )}
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
                              {s.trust === "inferred" && s.quote && (
                                <span
                                  className="basis-full text-muted-foreground italic"
                                  title="Checked against the extracted Business Combinations section, not the raw filing the evidence button opens. It shows the words are there, not that the deal happened."
                                >
                                  “{s.quote}”
                                </span>
                              )}
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
                      {c.status === "accepted" && (
                        <div className="text-muted-foreground mt-1">
                          into {c.engagement_id ? (engagementName.get(c.engagement_id) ?? c.engagement_id) : "your estate"}
                        </div>
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
                              onClick={() => { setAcceptError(null); setAcceptChoice(""); setAcceptFor(c) }}
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
      <Dialog open={!!acceptFor} onOpenChange={open => { if (!open) setAcceptFor(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Accept {acceptFor?.domain}</DialogTitle>
            <DialogDescription>
              Adds the domain as a target in the destination below and queues discovery under its rules.
              Domains inherit from the nearest company above this one in the confirmed family tree that has a relationship to us.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 text-sm">
            {destinationLoading ? (
              <>
                <Skeleton className="h-5 w-48" />
                <p className="text-muted-foreground">Resolving destination…</p>
              </>
            ) : !destination || destination.status === "unset" ? (
              <p className="text-muted-foreground">Set this company's relationship to us first (or its parent company's).</p>
            ) : destination.status === "abandoned" ? (
              <p className="text-muted-foreground">Its engagement was abandoned; nothing can be accepted into it.</p>
            ) : destination.status === "ours" ? (
              <>
                <p>Joins your estate.</p>
                {relevantStop && relevantStop.entity_id !== id && (
                  <p className="text-muted-foreground">Inherited from {relevantStop.legal_name}.</p>
                )}
              </>
            ) : destination.status === "engagement" ? (
              <>
                <p>
                  Joins {destination.engagements[0]?.name} ({destination.engagements[0]?.posture}
                  {destination.engagements[0]?.posture === "pre_close" ? ", passive only" : ""}).
                </p>
                {relevantStop && relevantStop.entity_id !== id && (
                  <p className="text-muted-foreground">Inherited from {relevantStop.legal_name}.</p>
                )}
              </>
            ) : (
              <>
                <p>More than one destination is reachable. Choose one:</p>
                <div className="space-y-1">
                  <Label htmlFor="accept-destination">Destination</Label>
                  <Select value={acceptChoice} onValueChange={setAcceptChoice}>
                    <SelectTrigger id="accept-destination" aria-label="Destination">
                      <SelectValue placeholder="Choose a destination" />
                    </SelectTrigger>
                    <SelectContent>
                      {destination.estate && <SelectItem value="estate">Your estate</SelectItem>}
                      {destination.engagements.map(e => (
                        <SelectItem key={e.id} value={e.id}>{e.name} ({e.posture})</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </>
            )}
          </div>
          {acceptError && <p className="text-sm text-destructive" role="alert">{acceptError}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => setAcceptFor(null)}>Cancel</Button>
            <Button
              disabled={acceptDisabled}
              onClick={() => { setAcceptError(null); acceptFor && acceptMutation.mutate({ cid: acceptFor.id, body: acceptBody() }) }}
            >
              {acceptMutation.isPending && <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />}
              Accept
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── relationship-to-us dialogs (planning#240) ── */}
      <Dialog open={oursOpen} onOpenChange={open => { if (!open) { setOursOpen(false); setRelationshipError(null) } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Mark {entity.legal_name} as our company?</DialogTitle>
            <DialogDescription>
              Marking a company as ours authorises its accepted domains, and those of its confirmed subsidiaries and
              acquisitions, to join your own estate, where they can be actively scanned. Your name, the time and the
              reference are recorded.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1">
            <Label htmlFor="ours-reference">Reference (ticket, contract or note)</Label>
            <Input id="ours-reference" value={oursReference} onChange={e => setOursReference(e.target.value)} />
          </div>
          {relationshipError && <p className="text-sm text-destructive" role="alert">{relationshipError}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => { setOursOpen(false); setRelationshipError(null) }}>Cancel</Button>
            <Button
              disabled={!oursReference.trim() || relationshipMutation.isPending}
              onClick={() => { setRelationshipError(null); relationshipMutation.mutate({ relationship: "ours", reference: oursReference.trim() }) }}
            >
              {relationshipMutation.isPending && <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />}
              Mark as ours
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={targetOpen} onOpenChange={open => { if (!open) { setTargetOpen(false); setRelationshipError(null) } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Mark {entity.legal_name} as an M&A target</DialogTitle>
            {entity.relationship === "ours" && (
              <DialogDescription>
                This company is currently marked ours. Making it an M&A target clears that authorisation.
              </DialogDescription>
            )}
          </DialogHeader>
          <div className="flex gap-2">
            <Button
              size="sm" variant={targetMode === "new" ? "default" : "outline"}
              onClick={() => { setTargetMode("new"); setRelationshipError(null) }}
            >
              New engagement
            </Button>
            <Button
              size="sm" variant={targetMode === "existing" ? "default" : "outline"}
              onClick={() => { setTargetMode("existing"); setRelationshipError(null) }}
            >
              Existing engagement
            </Button>
          </div>
          {targetMode === "new" ? (
            <div className="space-y-1">
              <Label htmlFor="target-name">Engagement name</Label>
              <Input id="target-name" value={targetName} onChange={e => setTargetName(e.target.value)} />
              <p className="text-xs text-muted-foreground">New engagements start pre-close: passive discovery only.</p>
            </div>
          ) : (
            <div className="space-y-1">
              <Label>Engagement</Label>
              {unassignedLiveEngagements.length ? (
                <Select value={targetEngagementId} onValueChange={setTargetEngagementId}>
                  <SelectTrigger aria-label="Engagement"><SelectValue placeholder="Choose an engagement" /></SelectTrigger>
                  <SelectContent>
                    {unassignedLiveEngagements.map(e => (
                      <SelectItem key={e.id} value={e.id}>{e.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <p className="text-sm text-muted-foreground">No unassigned live engagements</p>
              )}
            </div>
          )}
          {relationshipError && <p className="text-sm text-destructive" role="alert">{relationshipError}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => { setTargetOpen(false); setRelationshipError(null) }}>Cancel</Button>
            <Button
              disabled={
                relationshipMutation.isPending ||
                (targetMode === "new" ? !targetName.trim() : (!unassignedLiveEngagements.length || !targetEngagementId))
              }
              onClick={() => {
                setRelationshipError(null)
                relationshipMutation.mutate(
                  targetMode === "new"
                    ? { relationship: "ma_target", new_engagement_name: targetName.trim() }
                    : { relationship: "ma_target", engagement_id: targetEngagementId }
                )
              }}
            >
              {relationshipMutation.isPending && <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />}
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={clearOpen} onOpenChange={open => { if (!open) { setClearOpen(false); setRelationshipError(null) } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Clear the relationship?</DialogTitle>
            <DialogDescription>
              Accepting domains will be blocked and AI reads will run under the strict data policy until it is set again.
            </DialogDescription>
          </DialogHeader>
          {relationshipError && <p className="text-sm text-destructive" role="alert">{relationshipError}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => { setClearOpen(false); setRelationshipError(null) }}>Cancel</Button>
            <Button
              disabled={relationshipMutation.isPending}
              onClick={() => { setRelationshipError(null); relationshipMutation.mutate({ relationship: null }) }}
            >
              {relationshipMutation.isPending && <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />}
              Clear
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
