// planning#232 — first-run "Your company" step. The admin picks which SEC
// registrant is theirs (never matched automatically); the backend then runs the
// EDGAR ingest and the AI acquisition read. Everything it proposes stays
// proposed until accepted on the entity page, which this step only links to.
import { useState } from "react"
import { Link } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { CheckCircle2, ChevronRight, Loader2, XCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import {
  api,
  ApiError,
  type EntityIngestRun,
  type OnboardingSeedAccepted,
  type RegistrantCandidate,
} from "@/lib/api"
import { describeSeedError, followupOf, isActive, seedProgress } from "@/lib/companySeed"

const year = (d: string | null) => (d ? d.slice(0, 4) : null)

function errorText(e: unknown): string {
  if (e instanceof ApiError) return describeSeedError(e.status, e.message)
  return e instanceof Error ? e.message : "Something went wrong"
}

function CandidateRow({ c, onPick }: { c: RegistrantCandidate; onPick: () => void }) {
  return (
    <div className="rounded-lg border p-3 flex items-start justify-between gap-3">
      <div className="min-w-0 space-y-0.5 text-sm">
        <p className="font-medium">{c.name}</p>
        <p className="text-xs text-muted-foreground">
          CIK <span className="font-mono">{c.cik}</span>
          {c.state_of_incorporation && ` · ${c.state_of_incorporation}`}
          {c.sic && ` · ${c.sic}${c.sic_description ? ` ${c.sic_description}` : ""}`}
          {c.first_filing && ` · filed ${year(c.first_filing)}–${year(c.last_filing)}`}
        </p>
        {c.former_names.map((f, i) => (
          <p key={i} className="text-xs text-muted-foreground">
            formerly {f.name} ({year(f.from) ?? "?"}–{year(f.to) ?? "?"})
          </p>
        ))}
        {c.taken_by_id && (
          <p className="text-xs text-amber-600 dark:text-amber-400">
            Already in Constellus as {c.taken_by_name}
          </p>
        )}
      </div>
      <Button size="sm" variant="outline" onClick={onPick}>This is us</Button>
    </div>
  )
}

function SeedProgressPanel({
  seeded,
  onContinue,
}: {
  seeded: OnboardingSeedAccepted
  onContinue: () => void
}) {
  const qc = useQueryClient()
  const runId = seeded.run_id
  const { data: run, isError: runError } = useQuery({
    queryKey: ["onboarding-ingest-run", runId],
    queryFn: () => api.get<EntityIngestRun>(`/entities/edgar-ingest/runs/${runId}`),
    enabled: seeded.ingest === "queued" && !!runId,
    refetchInterval: (q) => (isActive(q.state.data?.status) ? 2000 : false),
  })
  const followup = followupOf(run?.result)
  const readRunId = followup?.status === "queued" ? followup.run_id : undefined

  const { data: reads, isError: readsError } = useQuery({
    queryKey: ["onboarding-read-runs", seeded.entity_id],
    queryFn: () => api.get<EntityIngestRun[]>(`/entities/${seeded.entity_id}/acquisition-read/runs?limit=5`),
    enabled: !!readRunId,
    refetchInterval: (q) => {
      const r = (q.state.data ?? []).find((x) => x.id === readRunId)
      return isActive(r?.status) ? 2000 : false
    },
  })
  const readRun = (reads ?? []).find((r) => r.id === readRunId)

  const p = seedProgress({
    ingest: seeded.ingest,
    ingestStatus: run?.status,
    ingestError: run?.error,
    followup,
    readStatus: readRun?.status,
    readError: readRun?.error,
  })

  const Icon =
    p.phase === "failed" ? XCircle : p.phase === "done" || p.phase === "already_running" ? CheckCircle2 : Loader2
  const spinning = p.phase === "ingest" || p.phase === "read"

  return (
    <div className="space-y-4">
      <div className="rounded-lg border p-4 space-y-2 text-sm">
        <p className="font-medium">{seeded.entity_name} <span className="font-mono text-xs text-muted-foreground">CIK {seeded.cik}</span></p>
        <div className="flex items-center gap-2">
          <Icon className={`h-4 w-4 ${spinning ? "animate-spin" : ""} ${p.phase === "failed" ? "text-destructive" : ""}`} />
          <span>{p.ingestLabel}</span>
        </div>
        {p.readLabel && <p className="text-muted-foreground pl-6">{p.readLabel}</p>}
        {p.hint && <p className="text-xs text-muted-foreground pl-6">{p.hint}</p>}
        {(runError || readsError) && (
          <p className="text-xs text-destructive pl-6" role="alert">
            Couldn't check progress. The company page shows the latest state.
          </p>
        )}
      </div>
      <p className="text-xs text-muted-foreground">Proposed domains stay proposed until you accept them.</p>
      <div className="flex items-center justify-between">
        <Button variant="outline" asChild>
          {/* Drop the cached first-run status so the setup guard re-reads it
              instead of bouncing back to /setup. */}
          <Link to={`/entities/${seeded.entity_id}`} onClick={() => qc.removeQueries({ queryKey: ["system-status"] })}>
            Review proposed domains
          </Link>
        </Button>
        <Button onClick={onContinue}>
          Continue <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  )
}

export function CompanySeedStep({ onContinue }: { onContinue: () => void }) {
  const [query, setQuery] = useState("")
  const [contains, setContains] = useState(false)
  const [results, setResults] = useState<RegistrantCandidate[] | null>(null)
  const [selected, setSelected] = useState<RegistrantCandidate | null>(null)
  const [seeded, setSeeded] = useState<OnboardingSeedAccepted | null>(null)

  const search = useMutation({
    mutationFn: () =>
      api.get<RegistrantCandidate[]>(
        `/entities/onboarding/registrant-search?q=${encodeURIComponent(query.trim())}&contains=${contains}`,
      ),
    onSuccess: (rows) => { setResults(rows); setSelected(null) },
  })
  const seed = useMutation({
    mutationFn: (cik: string) => api.post<OnboardingSeedAccepted>("/entities/onboarding/seed", { cik }),
    onSuccess: (r) => setSeeded(r),
  })

  let body: React.ReactNode
  let description =
    "Type your company's name. We look it up in SEC EDGAR; you choose which registrant is yours — nothing is matched automatically."

  if (seeded) {
    description = "Reading your company's SEC filings. Everything found is proposed for you to review."
    body = <SeedProgressPanel seeded={seeded} onContinue={onContinue} />
  } else if (selected) {
    description = "Confirm the registrant that is yours."
    body = (
      <div className="space-y-4 text-sm">
        <p>
          Mark <span className="font-medium">{selected.name}</span> (CIK{" "}
          <span className="font-mono">{selected.cik}</span>) as your organisation? This authorises it as yours
          (recorded as 'first-run onboarding' with your account). We'll read its SEC filings for subsidiaries,
          acquisitions and candidate domains. Nothing is scanned until you approve each domain.
        </p>
        {seed.error && <p className="text-destructive" role="alert">{errorText(seed.error)}</p>}
        <div className="flex justify-end gap-2">
          <Button variant="outline" disabled={seed.isPending} onClick={() => { seed.reset(); setSelected(null) }}>
            Back
          </Button>
          <Button disabled={seed.isPending} onClick={() => seed.mutate(selected.cik)}>
            {seed.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
            Confirm
          </Button>
        </div>
      </div>
    )
  } else {
    body = (
      <div className="space-y-4">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            if (query.trim()) search.mutate()
          }}
        >
          <div className="space-y-2">
            <Label htmlFor="company-query">Company name</Label>
            <Input id="company-query" value={query} maxLength={100} onChange={(e) => setQuery(e.target.value)} placeholder="Example Holdings A" />
          </div>
          <div className="flex items-center gap-2">
            <input
              id="company-contains"
              type="checkbox"
              checked={contains}
              onChange={(e) => setContains(e.target.checked)}
              className="h-4 w-4"
            />
            <Label htmlFor="company-contains" className="font-normal">match anywhere in the name</Label>
          </div>
          <Button type="submit" disabled={!query.trim() || search.isPending}>
            {search.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
            Search SEC filings
          </Button>
        </form>

        {search.error && <p className="text-sm text-destructive" role="alert">{errorText(search.error)}</p>}
        {results && results.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No registrant found. Private companies aren't in EDGAR — skip this step and add your domains from
            Targets, or try 'match anywhere'.
          </p>
        )}
        {results && results.length > 0 && (
          <div className="space-y-2 max-h-[40vh] overflow-y-auto">
            {results.map((c) => (
              <CandidateRow key={c.cik} c={c} onPick={() => { seed.reset(); setSelected(c) }} />
            ))}
          </div>
        )}

        <div className="pt-2">
          <button
            type="button"
            onClick={onContinue}
            className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground transition-colors"
          >
            Skip this step
          </button>
        </div>
      </div>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Your company</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>{body}</CardContent>
    </Card>
  )
}
