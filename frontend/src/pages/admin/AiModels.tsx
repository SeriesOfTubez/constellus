import { useEffect, useMemo, useState } from "react"
import { Link } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  AlertTriangle, ArrowDown, ArrowUp, Loader2, Plus, RefreshCw, RotateCcw, Save, X,
} from "lucide-react"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { api } from "@/lib/api"
import { relativeTime } from "@/lib/time"

// planning#224 — Admin → AI models. The OpenRouter key's guardrail decides
// WHICH models may be used (discovered from /models/user, cached); this page
// decides which model does which job (role bindings). No model id lives in
// application code: a fresh install starts unconfigured.

type RoleName = "research" | "extract" | "classify" | "judge" | "narrate" | "chat"

interface AllowedModel {
  id: string
  context_length: number | null
  supported_parameters: string[] | null
  pricing: { prompt?: string; completion?: string } | null
  // Display-only annotations from the public ZDR catalogue; null = the
  // catalogue could not be read at the last refresh (unknown, not zero).
  zdr_endpoints?: number | null
  zdr_structured_endpoints?: number | null
}

interface AllowedModelsResponse {
  fetched_at: string | null
  models: AllowedModel[]
}

interface RoleBinding {
  models: string[]
  max_tokens: number
  temperature: number
}

interface RoleBindingsResponse {
  configured: boolean
  bindings: Record<RoleName, RoleBinding> | null
}

interface LlmStatus {
  connector_configured: boolean
  models_configured: boolean
  key: { limit: number | null; limit_remaining: number | null; usage: number | null; is_free_tier: boolean | null } | null
  key_error: string | null
  budget: { daily_budget_usd: number; spent_today_usd: number }
  auto_writeups: AutoWriteups
}

interface AutoWriteups {
  daily_cap: number
  today: number
}

const ROLES: { name: RoleName; label: string; description: string; structured: boolean; defaults: Omit<RoleBinding, "models"> }[] = [
  { name: "research", label: "Research", description: "Long-form reading and reasoning over sources", structured: false, defaults: { max_tokens: 8192, temperature: 0.2 } },
  { name: "extract",  label: "Extract",  description: "Pulls structured facts out of text; also the tier-2 structurer for every structured call", structured: true, defaults: { max_tokens: 4096, temperature: 0 } },
  { name: "classify", label: "Classify", description: "Short labelling decisions", structured: true, defaults: { max_tokens: 1024, temperature: 0 } },
  { name: "judge",    label: "Judge",    description: "Second-opinion checks on another model's output", structured: false, defaults: { max_tokens: 4096, temperature: 0 } },
  { name: "narrate",  label: "Narrate",  description: "Human-readable write-ups", structured: false, defaults: { max_tokens: 2048, temperature: 0.4 } },
  { name: "chat",     label: "Chat",     description: "Perseus: answers questions by running read-only queries (tool calling, always strict)", structured: false, defaults: { max_tokens: 2048, temperature: 0 } },
]

// `~vendor/...-latest` slugs float: OpenRouter can change the model behind
// them without notice. Hidden by default (Jason, 2026-10-09).
const isAlias = (id: string) => id.startsWith("~")
const supportsStructured = (m: AllowedModel | undefined) => !!m?.supported_parameters?.includes("response_format")

function formatPerMillion(raw: string | undefined): string {
  if (raw === undefined || raw === null || raw === "") return "—"
  const n = Number(raw)
  if (!Number.isFinite(n)) return "—"
  if (n === 0) return "free"
  const perM = n * 1_000_000
  return `$${perM < 0.1 ? perM.toFixed(3) : perM.toFixed(2)}`
}

function formatUsd(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—"
  return `$${n.toFixed(2)}`
}

function emptyDraft(): Record<RoleName, RoleBinding> {
  const draft = {} as Record<RoleName, RoleBinding>
  for (const r of ROLES) draft[r.name] = { models: [], ...r.defaults }
  return draft
}

// ── automatic finding write-ups (planning#226 slice 2) ──────────────────

const AUTO_CAP_MAX = 1000

function AutoWriteupsCard({ auto }: { auto: AutoWriteups | undefined }) {
  const qc = useQueryClient()
  const [draft, setDraft] = useState<string>("")
  useEffect(() => {
    if (auto) setDraft(String(auto.daily_cap))
  }, [auto?.daily_cap])
  const parsed = Number(draft)
  const valid = draft.trim() !== "" && Number.isInteger(parsed) && parsed >= 0 && parsed <= AUTO_CAP_MAX
  const dirty = auto !== undefined && valid && parsed !== auto.daily_cap
  const save = useMutation({
    mutationFn: (cap: number) => api.put<AutoWriteups>("/llm/settings", { auto_writeups_daily_cap: cap }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["llm-status"] })
      toast.success(r.daily_cap === 0 ? "Automatic write-ups turned off" : `Automatic write-ups: up to ${r.daily_cap} a day`)
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  })
  if (!auto) return <Skeleton className="h-28" />
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Automatic finding write-ups</CardTitle>
        <CardDescription className="text-xs">
          After each scan, Critical and High findings that have no write-up yet get one, up to this many a day (UTC).
          0 turns it off. The daily budget above still applies.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex items-end gap-6 text-sm">
          <div className="space-y-1">
            <Label htmlFor="auto-writeups-cap" className="text-xs text-muted-foreground">Per day</Label>
            <div className="flex gap-2">
              <Input id="auto-writeups-cap" type="number" min={0} max={AUTO_CAP_MAX} step={1} className="h-8 w-24 text-xs"
                value={draft} onChange={(e) => setDraft(e.target.value)} aria-invalid={!valid} />
              <Button size="sm" className="h-8" aria-label="Save automatic write-up cap" disabled={!dirty || save.isPending} onClick={() => save.mutate(parsed)}>Save</Button>
            </div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Today</div>
            <div className="tabular-nums">{auto.daily_cap === 0 ? `${auto.today} (off)` : `${auto.today} of ${auto.daily_cap}`}</div>
          </div>
        </div>
        {!valid && <p className="mt-2 text-xs text-destructive">A whole number from 0 to {AUTO_CAP_MAX}.</p>}
      </CardContent>
    </Card>
  )
}

// ── status cards ────────────────────────────────────────────────────────

function StatusCards({ status }: { status: LlmStatus | undefined }) {
  if (!status) {
    return (
      <div className="grid grid-cols-2 gap-4">
        <Skeleton className="h-28" />
        <Skeleton className="h-28" />
      </div>
    )
  }
  const { key, key_error, budget } = status
  return (
    <div className="grid grid-cols-2 gap-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">OpenRouter key credit</CardTitle>
          <CardDescription className="text-xs">The key's own limit, set at openrouter.ai.</CardDescription>
        </CardHeader>
        <CardContent>
          {!status.connector_configured ? (
            <p className="text-sm text-muted-foreground">
              The OpenRouter connector isn't configured or enabled.{" "}
              <Link to="/admin/connectors" className="underline underline-offset-2 hover:text-foreground">Configure it</Link>.
            </p>
          ) : key_error ? (
            <p className="text-sm text-amber-600 dark:text-amber-400 flex items-start gap-1.5">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>Couldn't read the key status: {key_error}</span>
            </p>
          ) : key ? (
            <div className="flex gap-6 text-sm">
              <div><div className="text-xs text-muted-foreground">Remaining</div><div className="font-medium tabular-nums">{key.limit === null ? "no limit" : formatUsd(key.limit_remaining)}</div></div>
              <div><div className="text-xs text-muted-foreground">Limit</div><div className="tabular-nums">{key.limit === null ? "none" : formatUsd(key.limit)}</div></div>
              <div><div className="text-xs text-muted-foreground">Used</div><div className="tabular-nums">{formatUsd(key.usage)}</div></div>
            </div>
          ) : null}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Constellus daily budget</CardTitle>
          <CardDescription className="text-xs">At or above it, every new AI call is refused. Whichever limit is lower bites first.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-6 text-sm">
            <div><div className="text-xs text-muted-foreground">Spent today</div><div className="font-medium tabular-nums">{formatUsd(budget.spent_today_usd)}</div></div>
            <div><div className="text-xs text-muted-foreground">Budget</div><div className="tabular-nums">{formatUsd(budget.daily_budget_usd)}</div></div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// ── one role's ladder ───────────────────────────────────────────────────

function ModelFlags({ id, model, cachePresent, structuredRole }: {
  id: string; model: AllowedModel | undefined; cachePresent: boolean; structuredRole: boolean
}) {
  return (
    <>
      {cachePresent && !model && (
        <Tooltip>
          <TooltipTrigger asChild><Badge variant="destructive">No longer allowed</Badge></TooltipTrigger>
          <TooltipContent className="max-w-xs">Not in this key's guardrail-allowed list at the last refresh. Calls skip it without sending a request.</TooltipContent>
        </Tooltip>
      )}
      {isAlias(id) && (
        <Tooltip>
          <TooltipTrigger asChild><Badge variant="warning">floats</Badge></TooltipTrigger>
          <TooltipContent className="max-w-xs">A floating alias: OpenRouter can change the model behind it without notice.</TooltipContent>
        </Tooltip>
      )}
      {structuredRole && model && !supportsStructured(model) && (
        <Tooltip>
          <TooltipTrigger asChild><Badge variant="warning">No structured output</Badge></TooltipTrigger>
          <TooltipContent className="max-w-xs">This role needs JSON-schema output. The model doesn't list response_format, so structured calls will fall past it.</TooltipContent>
        </Tooltip>
      )}
      {model && model.zdr_endpoints === 0 && (
        <Tooltip>
          <TooltipTrigger asChild><Badge variant="warning">No ZDR endpoint</Badge></TooltipTrigger>
          <TooltipContent className="max-w-xs">No zero-data-retention endpoint serves this model, so it can't be used under the strict data policy.</TooltipContent>
        </Tooltip>
      )}
    </>
  )
}

function RoleEditor({ role, binding, onChange, byId, cachePresent, choices }: {
  role: (typeof ROLES)[number]
  binding: RoleBinding
  onChange: (b: RoleBinding) => void
  byId: Map<string, AllowedModel>
  cachePresent: boolean
  choices: AllowedModel[]
}) {
  const move = (i: number, delta: number) => {
    const models = [...binding.models]
    const [m] = models.splice(i, 1)
    models.splice(i + delta, 0, m)
    onChange({ ...binding, models })
  }
  const remove = (i: number) => onChange({ ...binding, models: binding.models.filter((_, j) => j !== i) })
  const add = (id: string) => onChange({ ...binding, models: [...binding.models, id] })
  const addable = choices.filter(m => !binding.models.includes(m.id))

  return (
    <div className="py-4 first:pt-0 last:pb-0 grid grid-cols-[180px_1fr_200px] gap-4">
      <div>
        <div className="text-sm font-medium">{role.label}</div>
        <p className="text-xs text-muted-foreground mt-0.5">{role.description}</p>
      </div>

      <div className="space-y-1.5 min-w-0">
        {binding.models.length === 0 && (
          <p className="text-xs text-amber-600 dark:text-amber-400">No model bound. Add at least one.</p>
        )}
        {binding.models.map((id, i) => (
          <div key={id} className="flex items-center gap-2 rounded-md border px-2 py-1">
            <span className="text-xs text-muted-foreground tabular-nums w-14 shrink-0">{i === 0 ? "primary" : `fallback ${i}`}</span>
            <span className="text-sm font-mono truncate">{id}</span>
            <div className="flex gap-1 flex-wrap">
              <ModelFlags id={id} model={byId.get(id)} cachePresent={cachePresent} structuredRole={role.structured} />
            </div>
            <div className="ml-auto flex gap-0.5 shrink-0">
              <Button variant="ghost" size="icon" className="h-6 w-6" aria-label={`Move ${id} up`} disabled={i === 0} onClick={() => move(i, -1)}><ArrowUp className="h-3 w-3" /></Button>
              <Button variant="ghost" size="icon" className="h-6 w-6" aria-label={`Move ${id} down`} disabled={i === binding.models.length - 1} onClick={() => move(i, 1)}><ArrowDown className="h-3 w-3" /></Button>
              <Button variant="ghost" size="icon" className="h-6 w-6" aria-label={`Remove ${id}`} onClick={() => remove(i)}><X className="h-3 w-3" /></Button>
            </div>
          </div>
        ))}
        <Select value="" onValueChange={add} disabled={addable.length === 0}>
          <SelectTrigger className="h-8 text-xs w-72" aria-label={`Add a model to ${role.label}`}>
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Plus className="h-3 w-3" />
              <SelectValue placeholder={cachePresent ? (addable.length ? "Add a model" : "No more allowed models") : "Refresh the allowed models first"} />
            </div>
          </SelectTrigger>
          <SelectContent>
            {addable.map(m => (
              <SelectItem key={m.id} value={m.id} className="text-xs font-mono">
                {m.id}{role.structured && !supportsStructured(m) ? "  (no structured output)" : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-2 gap-2 content-start">
        <div className="space-y-1">
          <Label className="text-xs" htmlFor={`${role.name}-max-tokens`}>Max tokens</Label>
          <Input id={`${role.name}-max-tokens`} type="number" min={1} className="h-8 text-xs"
            value={binding.max_tokens}
            onChange={e => onChange({ ...binding, max_tokens: Number(e.target.value) })} />
        </div>
        <div className="space-y-1">
          <Label className="text-xs" htmlFor={`${role.name}-temperature`}>Temperature</Label>
          <Input id={`${role.name}-temperature`} type="number" min={0} max={2} step={0.1} className="h-8 text-xs"
            value={binding.temperature}
            onChange={e => onChange({ ...binding, temperature: Number(e.target.value) })} />
        </div>
      </div>
    </div>
  )
}

// ── page ────────────────────────────────────────────────────────────────

export default function AiModels() {
  const qc = useQueryClient()
  const [showAliases, setShowAliases] = useState(false)

  const { data: status } = useQuery<LlmStatus>({ queryKey: ["llm-status"], queryFn: () => api.get("/llm/status") })
  const { data: allowed, isLoading: allowedLoading } = useQuery<AllowedModelsResponse>({
    queryKey: ["llm-models"], queryFn: () => api.get("/llm/models"),
  })
  const { data: saved, isLoading: bindingsLoading, error: bindingsError } = useQuery<RoleBindingsResponse>({
    queryKey: ["llm-role-bindings"], queryFn: () => api.get("/llm/role-bindings"), retry: false,
  })

  const [draft, setDraft] = useState<Record<RoleName, RoleBinding> | null>(null)
  useEffect(() => {
    if (saved) setDraft(saved.bindings ? structuredClone(saved.bindings) : emptyDraft())
  }, [saved])

  const cachePresent = !!allowed?.fetched_at
  const byId = useMemo(() => new Map((allowed?.models ?? []).map(m => [m.id, m])), [allowed])
  const visibleModels = useMemo(
    () => (allowed?.models ?? []).filter(m => showAliases || !isAlias(m.id)).sort((a, b) => a.id.localeCompare(b.id)),
    [allowed, showAliases],
  )
  const hiddenAliasCount = (allowed?.models ?? []).filter(m => isAlias(m.id)).length

  const boundRoles = useMemo(() => {
    const out = new Map<string, string[]>()
    for (const r of ROLES) for (const id of saved?.bindings?.[r.name]?.models ?? []) out.set(id, [...(out.get(id) ?? []), r.label])
    return out
  }, [saved])

  const dirty = !!draft && JSON.stringify(draft) !== JSON.stringify(saved?.bindings ?? emptyDraft())
  const complete = !!draft && ROLES.every(r => draft[r.name].models.length > 0)
  const valid = !!draft && ROLES.every(r =>
    Number.isInteger(draft[r.name].max_tokens) && draft[r.name].max_tokens > 0 &&
    draft[r.name].temperature >= 0 && draft[r.name].temperature <= 2)

  const refreshMutation = useMutation({
    mutationFn: () => api.post<AllowedModelsResponse>("/llm/models/refresh"),
    onSuccess: (r) => {
      qc.setQueryData(["llm-models"], r)
      toast.success(`Allowed models refreshed: ${r.models.length} model${r.models.length === 1 ? "" : "s"}`)
    },
    onError: (e: Error) => toast.error(`Refresh failed: ${e.message}`),
  })

  const saveMutation = useMutation({
    mutationFn: (bindings: Record<RoleName, RoleBinding>) => api.put<RoleBindingsResponse>("/llm/role-bindings", { bindings }),
    onSuccess: (r) => {
      qc.setQueryData(["llm-role-bindings"], r)
      qc.invalidateQueries({ queryKey: ["llm-status"] })
      toast.success("Role bindings saved")
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  })

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <AdminBreadcrumb page="AI models" />
      <div>
        <h1 className="text-2xl font-semibold">AI models</h1>
        <p className="text-sm text-muted-foreground mt-1">
          The OpenRouter key's guardrail decides which models may be used. Here you decide which model does which job.
        </p>
      </div>

      <StatusCards status={status} />
      <AutoWriteupsCard auto={status?.auto_writeups} />

      {saved && !saved.configured && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-medium">AI models aren't configured</div>
            <div className="text-muted-foreground">
              AI features are off until every role below has at least one model and you save.
              {!cachePresent && " Refresh the allowed models first to pick from what your key permits."}
            </div>
          </div>
        </div>
      )}

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between gap-4">
            <div>
              <CardTitle className="text-base">Role bindings</CardTitle>
              <CardDescription className="text-xs">
                Each role tries its primary first, then each fallback in order. Every change is recorded in the audit log.
              </CardDescription>
            </div>
            <div className="flex gap-2 shrink-0">
              <Button variant="outline" size="sm" disabled={!dirty || saveMutation.isPending}
                onClick={() => setDraft(saved?.bindings ? structuredClone(saved.bindings) : emptyDraft())}>
                <RotateCcw className="h-3 w-3" /> Discard
              </Button>
              <Button size="sm" disabled={!dirty || !complete || !valid || saveMutation.isPending}
                onClick={() => draft && saveMutation.mutate(draft)}
                title={!complete ? "Every role needs at least one model" : !valid ? "Max tokens must be a positive whole number; temperature 0–2" : undefined}>
                {saveMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Save className="h-3 w-3" />}
                Save
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="divide-y">
          {bindingsError ? (
            <p className="text-sm text-destructive">The stored bindings can't be read: {(bindingsError as Error).message}. Saving new bindings replaces them.</p>
          ) : bindingsLoading || !draft ? (
            <Skeleton className="h-64" />
          ) : (
            ROLES.map(r => (
              <RoleEditor key={r.name} role={r} binding={draft[r.name]} byId={byId} cachePresent={cachePresent}
                choices={visibleModels}
                onChange={b => setDraft({ ...draft, [r.name]: b })} />
            ))
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between gap-4">
            <div>
              <CardTitle className="text-base">Allowed models</CardTitle>
              <CardDescription className="text-xs">
                {cachePresent
                  ? <>What this key's OpenRouter guardrail permits, fetched {relativeTime(allowed!.fetched_at)}. Refreshed daily.</>
                  : <>Not fetched yet. Until it is, no bound model is skipped.</>}
              </CardDescription>
            </div>
            <div className="flex items-center gap-4 shrink-0">
              {hiddenAliasCount > 0 && (
                <div className="flex items-center gap-2">
                  <Switch id="show-aliases" checked={showAliases} onCheckedChange={setShowAliases} />
                  <Label htmlFor="show-aliases" className="text-xs">Show aliases ({hiddenAliasCount})</Label>
                </div>
              )}
              <Button variant="outline" size="sm" disabled={refreshMutation.isPending || !status?.connector_configured}
                onClick={() => refreshMutation.mutate()}
                title={!status?.connector_configured ? "Configure the OpenRouter connector first" : undefined}>
                {refreshMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          {allowedLoading ? <Skeleton className="h-40" /> : !cachePresent ? null : visibleModels.length === 0 ? (
            <p className="text-sm text-muted-foreground">The guardrail allows no models{hiddenAliasCount ? " besides floating aliases" : ""}.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Model</TableHead>
                  <TableHead>Structured output</TableHead>
                  <TableHead>
                    <Tooltip>
                      <TooltipTrigger className="underline decoration-dotted underline-offset-2">ZDR endpoints</TooltipTrigger>
                      <TooltipContent className="max-w-xs">Zero-data-retention endpoints serving this model, and how many of those accept JSON-schema output. Strict calls can only use these.</TooltipContent>
                    </Tooltip>
                  </TableHead>
                  <TableHead className="text-right">Input / 1M</TableHead>
                  <TableHead className="text-right">Output / 1M</TableHead>
                  <TableHead className="text-right">Context</TableHead>
                  <TableHead>Bound to</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visibleModels.map(m => (
                  <TableRow key={m.id}>
                    <TableCell className="font-mono text-xs">
                      <span className="flex items-center gap-1.5">{m.id}{isAlias(m.id) && <Badge variant="warning">floats</Badge>}</span>
                    </TableCell>
                    <TableCell>{supportsStructured(m) ? <Badge variant="success">Yes</Badge> : <span className="text-xs text-muted-foreground">No</span>}</TableCell>
                    <TableCell className="text-xs tabular-nums">
                      {m.zdr_endpoints === null || m.zdr_endpoints === undefined
                        ? <span className="text-muted-foreground">unknown</span>
                        : m.zdr_endpoints === 0
                          ? <span className="text-amber-600 dark:text-amber-400">none</span>
                          : <>{m.zdr_endpoints} <span className="text-muted-foreground">({m.zdr_structured_endpoints ?? 0} structured)</span></>}
                    </TableCell>
                    <TableCell className="text-right text-xs tabular-nums">{formatPerMillion(m.pricing?.prompt)}</TableCell>
                    <TableCell className="text-right text-xs tabular-nums">{formatPerMillion(m.pricing?.completion)}</TableCell>
                    <TableCell className="text-right text-xs tabular-nums">{m.context_length ? `${Math.round(m.context_length / 1000)}k` : "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{boundRoles.get(m.id)?.join(", ") ?? ""}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
