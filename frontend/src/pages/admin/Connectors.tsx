import { useState, useEffect } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  Plug, FlaskConical, Save, Loader2, Search, Globe, RefreshCw, Zap, Bot, Plus, Trash2, TriangleAlert, Building2, Wand2, ChevronDown, ChevronRight,
} from "lucide-react"
import { Link } from "react-router-dom"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { ConnectorConfigFields, fillConfigValues } from "@/components/ConnectorConfigFields"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import {
  api, type ApiError, type BindableOrganization, type BindingSuggestion, type ConnectorInstanceSummary,
  type ConnectorTypeSummary, type ZoneClash, type ZoneEntry,
} from "@/lib/api"
import { CORE_IMPACT_COPY } from "@/lib/connector-copy"
import {
  BINDING_NEEDS_PERMISSION_COPY, PHASE_ORDER, bindingControl, bindingErrorMessage, bindingWarning, canSync, instancePatch,
  clashReasonLabel, deleteConflictMessage, groupByPhase, hasZones, suggestionCopy,
} from "@/lib/connectors"
import { useCan } from "@/lib/permissions"

const PHASE_META: Record<string, { label: string; description: string }> = {
  discovery:    { label: "Discovery",    description: "DNS and zone data sources" },
  enrichment:   { label: "Enrichment",   description: "Asset context — cloud, firewall, vulnerability management" },
  scanning:     { label: "Scanning",     description: "Active vulnerability scanning" },
  notification: { label: "Notification", description: "Outbound alerts — email, chat, webhooks" },
  inference:    { label: "Inference",    description: "LLM providers — role-routed, data-policy enforced" },
}

const invalidate = (qc: ReturnType<typeof useQueryClient>) => qc.invalidateQueries({ queryKey: ["connectors"] })

/** The per-instance actions every row and card shares. */
function useInstanceActions(type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) {
  const qc = useQueryClient()
  const label = type.account_scoped ? `${type.name} (${instance.name})` : type.name
  const base = `/connectors/instances/${instance.id}`

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.post(`${base}/${enabled ? "enable" : "disable"}`),
    onSuccess: () => invalidate(qc),
    onError: (e: ApiError) => toast.error(`Failed to update ${label}: ${bindingErrorMessage(e)}`),
  })
  const test = useMutation({
    mutationFn: () => api.post<{ success: boolean; message: string }>(`${base}/test`),
    onSuccess: (r) => (r.success ? toast.success(`${label}: ${r.message}`) : toast.error(`${label}: ${r.message}`)),
    onError: () => toast.error("Test failed"),
  })
  const sync = useMutation({
    mutationFn: () => api.post(`${base}/sync`),
    onSuccess: () => toast.success(`${label}: sync queued`),
    onError: (e: ApiError) => toast.error(`Failed to queue sync: ${bindingErrorMessage(e)}`),
  })
  return { toggle, test, sync, label }
}

function ConfiguredBadges({ type, instance }: { type: ConnectorTypeSummary; instance: ConnectorInstanceSummary }) {
  return (
    <>
      <Badge variant={instance.configured ? "success" : "outline"}>
        {instance.configured ? "Configured" : "Not configured"}
      </Badge>
      {instance.enabled && !instance.configured && <Badge variant="warning">Needs config</Badge>}
      {instance.enabled && type.disabled_at_current_tier && (
        <Badge
          variant="outline"
          title={`This connector is gated off at the ${type.current_tier} aggressiveness tier. Raise the global tier in Admin → Settings, or override it on a specific target, to activate.`}
        >
          Inactive at {type.current_tier} tier
        </Badge>
      )}
    </>
  )
}

function InstanceButtons({
  type, instance, onConfigure, onDelete,
}: {
  type: ConnectorTypeSummary
  instance: ConnectorInstanceSummary
  onConfigure: (type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) => void
  onDelete?: (type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) => void
}) {
  const { test, sync } = useInstanceActions(type, instance)
  return (
    <div className="flex gap-2 flex-wrap justify-end">
      <Button variant="outline" size="sm" onClick={() => test.mutate()} disabled={test.isPending || !instance.configured}>
        {test.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <FlaskConical className="h-3 w-3" />}
        Test
      </Button>
      {hasZones(type) && (
        <Button variant="outline" size="sm" onClick={() => sync.mutate()} disabled={sync.isPending || !canSync(type, instance)}>
          {sync.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
          Sync
        </Button>
      )}
      {type.id === "openrouter" && (
        <Button variant="outline" size="sm" asChild>
          <Link to="/admin/ai-models"><Bot className="h-3 w-3" />AI models</Link>
        </Button>
      )}
      <Button variant="outline" size="sm" onClick={() => onConfigure(type, instance)}>
        <Plug className="h-3 w-3" />
        Configure
      </Button>
      {onDelete && (
        <Button variant="outline" size="sm" onClick={() => onDelete(type, instance)} aria-label={`Delete ${instance.name}`}>
          <Trash2 className="h-3 w-3" />
        </Button>
      )}
    </div>
  )
}

function CoreBadge({ type }: { type: ConnectorTypeSummary }) {
  if (!type.core) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="outline" className="border-primary/40 text-primary gap-1">
          <Zap className="h-3 w-3" />
          Core capability
        </Badge>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        {CORE_IMPACT_COPY[type.id]?.long ?? "Core to result quality — configuring it is strongly recommended."}
      </TooltipContent>
    </Tooltip>
  )
}

/** Global type with an instance: the original single-switch card. */
function GlobalCardBody({
  type, instance, onConfigure,
}: {
  type: ConnectorTypeSummary
  instance: ConnectorInstanceSummary
  onConfigure: (type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) => void
}) {
  const { toggle } = useInstanceActions(type, instance)
  return (
    <>
      <div className="absolute right-6 top-6">
        <Switch checked={instance.enabled} onCheckedChange={(v) => toggle.mutate(v)} disabled={toggle.isPending} />
      </div>
      <CardContent className="pt-0">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <CoreBadge type={type} />
            <ConfiguredBadges type={type} instance={instance} />
          </div>
          <InstanceButtons type={type} instance={instance} onConfigure={onConfigure} />
        </div>
        <div className="mt-2"><ClashesSection instance={instance} /></div>
      </CardContent>
    </>
  )
}

function SetUpBody({
  type, onConfigure,
}: {
  type: ConnectorTypeSummary
  onConfigure: (type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) => void
}) {
  const qc = useQueryClient()
  const create = useMutation({
    mutationFn: () =>
      api.post<ConnectorInstanceSummary>(`/connectors/${type.id}/instances`, {
        name: type.name, bound_entity_id: null, config: {},
      }),
    onSuccess: async (inst) => {
      await invalidate(qc)
      onConfigure(type, inst)
    },
    onError: (e: ApiError) => toast.error(`Could not set up ${type.name}: ${bindingErrorMessage(e)}`),
  })
  return (
    <CardContent className="pt-0">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 flex-wrap">
          <CoreBadge type={type} />
          <Badge variant="outline">Not set up</Badge>
        </div>
        <Button variant="outline" size="sm" onClick={() => create.mutate()} disabled={create.isPending}>
          {create.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Plug className="h-3 w-3" />}
          Set up
        </Button>
      </div>
    </CardContent>
  )
}

/** Collapsible "Clashes (n)": zones this instance listed that conflict with
 * something already attributed elsewhere. Loaded only when expanded; nothing
 * renders when there are none. Neutral/amber, never severity colours. */
export function ClashesSection({ instance }: { instance: ConnectorInstanceSummary }) {
  const [open, setOpen] = useState(false)
  const n = instance.open_zone_clashes
  const { data, isLoading, error } = useQuery({
    queryKey: ["connector-zone-clashes", instance.id],
    queryFn: () => api.get<ZoneClash[]>(`/connectors/instances/${instance.id}/zone-clashes`),
    enabled: open && n > 0,
  })
  if (!(n > 0)) return null
  const Chevron = open ? ChevronDown : ChevronRight
  return (
    <div className="text-xs">
      <button
        type="button"
        className="flex items-center gap-1 text-amber-600 dark:text-amber-400 font-medium"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <Chevron className="h-3.5 w-3.5" />
        Clashes ({n})
      </button>
      {open && (
        <div className="mt-1.5 space-y-1.5">
          {isLoading && <Skeleton className="h-8 w-full" />}
          {error && <p className="text-destructive">{(error as ApiError).message || "Could not load clashes"}</p>}
          {data?.map((c) => (
            <div key={c.id} className="rounded border border-amber-500/30 px-2 py-1.5">
              <p><span className="font-mono">{c.zone}</span> <span className="text-muted-foreground">{clashReasonLabel(c.reason)}</span></p>
              <p className="text-muted-foreground">
                first seen {new Date(c.first_seen_at).toLocaleDateString()} · last seen {new Date(c.last_seen_at).toLocaleDateString()}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/** Binding control for an account-scoped instance: the picker with
 * entities.decide_candidate, else the current binding read-only. */
export function InstanceBindingControl({
  type, instance, org, onChange, getConfig,
}: {
  type: ConnectorTypeSummary
  instance: ConnectorInstanceSummary
  org: string
  onChange: (id: string) => void
  getConfig: () => Record<string, string | boolean>
}) {
  const can = useCan()
  if (bindingControl(type.account_scoped, can("entities.decide_candidate")) === "picker") {
    return (
      <OrganizationField
        type={type}
        value={org}
        onChange={onChange}
        getConfig={getConfig}
        instanceId={instance.id}
        currentOrg={instance.bound_entity_id ? { id: instance.bound_entity_id, name: instance.bound_entity_name ?? "Bound organization" } : null}
      />
    )
  }
  return (
    <div className="space-y-1">
      <Label>Organization</Label>
      <p className="text-sm">
        {instance.bound_entity_id
          ? `Bound to ${instance.bound_entity_name ?? "an organization"}`
          : "Not bound to an organization"}
      </p>
      <p className="text-xs text-muted-foreground">{BINDING_NEEDS_PERMISSION_COPY}</p>
    </div>
  )
}

function AccountRow({
  type, instance, onConfigure, onDelete,
}: {
  type: ConnectorTypeSummary
  instance: ConnectorInstanceSummary
  onConfigure: (type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) => void
  onDelete: (type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) => void
}) {
  const { toggle } = useInstanceActions(type, instance)
  const warning = bindingWarning(instance)
  return (
    <li className="rounded-md border p-3 space-y-2">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0 space-y-1">
          <p className="text-sm font-medium truncate">{instance.name}</p>
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className="gap-1">
              <Building2 className="h-3 w-3" />
              {instance.bound_entity_name ?? "No organization"}
            </Badge>
            <ConfiguredBadges type={type} instance={instance} />
          </div>
        </div>
        <Switch checked={instance.enabled} onCheckedChange={(v) => toggle.mutate(v)} disabled={toggle.isPending} />
      </div>
      {warning && (
        <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
          <TriangleAlert className="h-3.5 w-3.5 mt-0.5 shrink-0" />
          {warning}
        </p>
      )}
      <ClashesSection instance={instance} />
      <InstanceButtons type={type} instance={instance} onConfigure={onConfigure} onDelete={onDelete} />
    </li>
  )
}

export function ConnectorTypeCard({
  type, onConfigure, onAdd, onDelete,
}: {
  type: ConnectorTypeSummary
  onConfigure: (type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) => void
  onAdd: (type: ConnectorTypeSummary) => void
  onDelete: (type: ConnectorTypeSummary, instance: ConnectorInstanceSummary) => void
}) {
  const globalInstance = type.account_scoped ? undefined : type.instances[0]
  return (
    <Card className="relative">
      <CardHeader className="pb-3">
        <div className="space-y-1 min-w-0 pr-14">
          <CardTitle className="text-base">{type.name}</CardTitle>
          <CardDescription className="text-xs leading-relaxed">{type.description}</CardDescription>
        </div>
      </CardHeader>
      {type.account_scoped ? (
        <CardContent className="pt-0 space-y-3">
          {type.instances.length > 0 && (
            <ul className="space-y-2">
              {type.instances.map((i) => (
                <AccountRow key={i.id} type={type} instance={i} onConfigure={onConfigure} onDelete={onDelete} />
              ))}
            </ul>
          )}
          <Button variant="outline" size="sm" onClick={() => onAdd(type)}>
            <Plus className="h-3 w-3" />
            {type.instances.length > 0 ? "Add another" : "Add"}
          </Button>
        </CardContent>
      ) : globalInstance ? (
        <GlobalCardBody type={type} instance={globalInstance} onConfigure={onConfigure} />
      ) : (
        <SetUpBody type={type} onConfigure={onConfigure} />
      )}
    </Card>
  )
}

const ZONES_PAGE_SIZE = 25

function ZonesTab({ instanceId }: { instanceId: string }) {
  const qc = useQueryClient()
  const [search, setSearch] = useState("")
  const [page, setPage] = useState(1)
  const [localZones, setLocalZones] = useState<ZoneEntry[] | null>(null)
  const [dirty, setDirty] = useState(false)

  const { data: zones, isLoading } = useQuery<ZoneEntry[]>({
    queryKey: ["connector-zones", instanceId],
    queryFn: () => api.get(`/connectors/instances/${instanceId}/zones`),
  })

  // Initialise local state from server data once
  useEffect(() => {
    if (zones && !localZones) setLocalZones(zones)
  }, [zones, localZones])

  const syncMutation = useMutation({
    mutationFn: () => api.post(`/connectors/instances/${instanceId}/sync`),
    onError: (e) => toast.error(`Zones saved but sync failed to queue: ${bindingErrorMessage(e)}`),
  })

  const saveMutation = useMutation({
    mutationFn: () => {
      const excluded = (localZones ?? []).filter(z => z.excluded).map(z => z.name)
      return api.put(`/connectors/instances/${instanceId}/zones`, { excluded_zones: excluded })
    },
    onSuccess: () => {
      toast.success("Zone selections saved — sync queued")
      setDirty(false)
      qc.invalidateQueries({ queryKey: ["connector-zones", instanceId] })
      qc.invalidateQueries({ queryKey: ["available-domains"] })
      syncMutation.mutate()
    },
    onError: () => toast.error("Failed to save zone selections"),
  })

  function toggleZone(name: string) {
    setLocalZones(prev => (prev ?? []).map(z => z.name === name ? { ...z, excluded: !z.excluded } : z))
    setDirty(true)
  }

  function selectAll() {
    setLocalZones(prev => (prev ?? []).map(z =>
      filtered.some(f => f.name === z.name) ? { ...z, excluded: false } : z
    ))
    setDirty(true)
  }

  function deselectAll() {
    setLocalZones(prev => (prev ?? []).map(z =>
      filtered.some(f => f.name === z.name) ? { ...z, excluded: true } : z
    ))
    setDirty(true)
  }

  const display = localZones ?? zones ?? []
  const filtered = display.filter(z => !search || z.name.toLowerCase().includes(search.toLowerCase()))
  const totalPages = Math.max(1, Math.ceil(filtered.length / ZONES_PAGE_SIZE))
  const safePage = Math.min(page, totalPages)
  const paginated = filtered.slice((safePage - 1) * ZONES_PAGE_SIZE, safePage * ZONES_PAGE_SIZE)
  const includedCount = display.filter(z => !z.excluded).length

  if (isLoading) return <div className="space-y-2 pt-4">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}</div>

  return (
    <div className="space-y-4 pt-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {includedCount} of {display.length} zone{display.length !== 1 ? "s" : ""} included
        </p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={selectAll}>Select all</Button>
          <Button variant="outline" size="sm" onClick={deselectAll}>Deselect all</Button>
        </div>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
        <Input className="pl-8 h-9 text-sm" placeholder="Search zones..."
          value={search} onChange={e => { setSearch(e.target.value); setPage(1) }} />
      </div>

      <div className="rounded-md border divide-y">
        {paginated.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-muted-foreground">No zones match your search.</div>
        ) : paginated.map(zone => (
          <label key={zone.name} className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/40 cursor-pointer">
            <input
              type="checkbox"
              checked={!zone.excluded}
              onChange={() => toggleZone(zone.name)}
              className="h-4 w-4 rounded border border-border accent-primary cursor-pointer"
            />
            <span className="font-mono text-sm">{zone.name}</span>
            {zone.excluded && <span className="ml-auto text-xs text-muted-foreground">excluded</span>}
          </label>
        ))}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Page {safePage} of {totalPages} ({filtered.length} zones)</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={safePage <= 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
            <Button variant="outline" size="sm" disabled={safePage >= totalPages} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        </div>
      )}

      <Separator />

      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={() => syncMutation.mutate()} disabled={syncMutation.isPending || saveMutation.isPending}>
          {syncMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1.5" /> : <RefreshCw className="h-4 w-4 mr-1.5" />}
          Sync Now
        </Button>
        <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending || !dirty}>
          {saveMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1.5" /> : <Save className="h-4 w-4 mr-1.5" />}
          Save Zones{dirty ? " *" : ""}
        </Button>
      </div>
    </div>
  )
}


/** The organization picker plus "Find matching organization" (zone-capable types). */
function OrganizationField({
  type, value, onChange, getConfig, instanceId, currentOrg,
}: {
  type: ConnectorTypeSummary
  value: string
  onChange: (id: string) => void
  getConfig: () => Record<string, string | boolean>
  instanceId?: string
  currentOrg?: { id: string; name: string } | null
}) {
  const { data: orgs } = useQuery({
    queryKey: ["bindable-organizations"],
    queryFn: () => api.get<BindableOrganization[]>("/connectors/bindable-organizations"),
  })
  const [suggestion, setSuggestion] = useState<BindingSuggestion | null>(null)

  const suggest = useMutation({
    mutationFn: () =>
      api.post<BindingSuggestion>(`/connectors/${type.id}/binding-suggestion`, {
        config: getConfig(), ...(instanceId ? { instance_id: instanceId } : {}),
      }),
    onSuccess: (s) => {
      setSuggestion(s)
      if (s.suggested_entity_id) onChange(s.suggested_entity_id)
    },
    onError: () => toast.error("Could not list zones from the provider — check the credentials with Test"),
  })

  const options = [...(orgs ?? [])]
  // An instance whose binding stopped being allowed is still bound to it: keep it selectable.
  if (currentOrg && !options.some((o) => o.id === currentOrg.id)) {
    options.unshift({ id: currentOrg.id, name: currentOrg.name, relationship: "", posture: null })
  }

  return (
    <div className="space-y-2">
      <Label>Organization</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger><SelectValue placeholder="Pick the organization this account belongs to" /></SelectTrigger>
        <SelectContent>
          {options.map((o) => <SelectItem key={o.id} value={o.id}>{o.name}</SelectItem>)}
        </SelectContent>
      </Select>
      {options.length === 0 && orgs && (
        <p className="text-xs text-muted-foreground">
          No organization can be bound yet: mark yours as "ours", or bring a deal to day 0.
        </p>
      )}
      {hasZones(type) && (
        <>
          <Button type="button" variant="outline" size="sm" onClick={() => suggest.mutate()} disabled={suggest.isPending}>
            {suggest.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Wand2 className="h-3 w-3" />}
            Find matching organization
          </Button>
          {suggestion && <p className="text-xs text-muted-foreground">{suggestionCopy(suggestion)}</p>}
        </>
      )}
    </div>
  )
}

/** Add button for the Add sheet; blocked (disabled) for an account-scoped type when the user
 * cannot bind an organization, since the org is required there. Reads the permission itself
 * so the gate is testable outside the (SSR-empty) sheet portal. */
export function AddInstanceButton({
  accountScoped, disabled, pending, onClick,
}: { accountScoped: boolean; disabled: boolean; pending: boolean; onClick: () => void }) {
  const control = bindingControl(accountScoped, useCan()("entities.decide_candidate"))
  return (
    <Button onClick={onClick} disabled={disabled || control === "blocked"}>
      {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
      Add
    </Button>
  )
}

function AddInstanceSheet({ type, onClose }: { type: ConnectorTypeSummary | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState("")
  const [org, setOrg] = useState("")
  const [values, setValues] = useState<Record<string, string | boolean>>({})
  const [error, setError] = useState<string | null>(null)
  const typeId = type?.id
  const canDecide = useCan()("entities.decide_candidate")
  const control = bindingControl(!!type?.account_scoped, canDecide)

  useEffect(() => {
    if (type) {
      setName("")
      setOrg("")
      setError(null)
      setValues(fillConfigValues(type.config_schema, {}))
    }
    // reset only when a different type is opened
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typeId])

  const create = useMutation({
    mutationFn: () =>
      api.post<ConnectorInstanceSummary>(`/connectors/${type!.id}/instances`, {
        name: name.trim(), bound_entity_id: org || null, config: values,
      }),
    onSuccess: () => {
      toast.success("Instance added")
      invalidate(qc)
      onClose()
    },
    onError: (e: ApiError) => setError(bindingErrorMessage(e)),
  })

  if (!type) return null
  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="sm:max-w-lg overflow-y-auto">
        <SheetHeader>
          <SheetTitle>Add {type.name} instance</SheetTitle>
          <SheetDescription>One instance per account. Each is bound to the organization that owns it.</SheetDescription>
        </SheetHeader>
        <div className="py-6 space-y-5">
          <div className="space-y-1.5">
            <Label htmlFor="instance-name">Name</Label>
            <Input id="instance-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Example Holdings A" />
          </div>
          <ConnectorConfigFields
            schema={type.config_schema}
            values={values}
            onChange={(key, v) => setValues((s) => ({ ...s, [key]: v }))}
          />
          {control === "picker" ? (
            <OrganizationField type={type} value={org} onChange={setOrg} getConfig={() => values} />
          ) : (
            <p className="text-xs text-muted-foreground">{BINDING_NEEDS_PERMISSION_COPY}</p>
          )}
          {error && <p className="text-sm text-destructive">{error}</p>}
        </div>
        <SheetFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <AddInstanceButton accountScoped={!!type.account_scoped} disabled={create.isPending || !name.trim()}
            pending={create.isPending} onClick={() => { setError(null); create.mutate() }} />
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

function ConfigSheet({
  type, instance, onClose,
}: {
  type: ConnectorTypeSummary | null
  instance: ConnectorInstanceSummary | null
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [values, setValues] = useState<Record<string, string | boolean>>({})
  const [loaded, setLoaded] = useState(false)
  const [name, setName] = useState("")
  const [org, setOrg] = useState("")
  const [error, setError] = useState<string | null>(null)
  const instanceId = instance?.id
  const canDecide = useCan()("entities.decide_candidate")

  const { data } = useQuery({
    queryKey: ["connector-config", instanceId],
    queryFn: () => api.get<{ config: Record<string, unknown> }>(`/connectors/instances/${instanceId}/config`),
    enabled: !!instanceId,
    gcTime: 0,
  })

  useEffect(() => {
    setLoaded(false)
    setError(null)
    setName(instance?.name ?? "")
    setOrg(instance?.bound_entity_id ?? "")
    // reset only when a different instance is opened
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [instanceId])

  useEffect(() => {
    if (type && data) {
      setValues(fillConfigValues(type.config_schema, data.config))
      setLoaded(true)
    }
  }, [type, data])

  const save = useMutation({
    mutationFn: async () => {
      if (!type || !instance) return
      if (type.account_scoped) {
        const patch = instancePatch(instance, { name, org }, canDecide)
        if (Object.keys(patch).length > 0) await api.patch(`/connectors/instances/${instance.id}`, patch)
      }
      await api.put(`/connectors/instances/${instance.id}/config`, { config: values })
    },
    onSuccess: () => {
      toast.success("Configuration saved")
      invalidate(qc)
      qc.invalidateQueries({ queryKey: ["connector-zones", instanceId] })
      onClose()
    },
    onError: (e: ApiError) => {
      setError(bindingErrorMessage(e))
      invalidate(qc)
    },
  })

  if (!type || !instance) return null

  const credentialsContent = (
    <>
      <div className="py-6 space-y-5">
        {type.account_scoped && (
          <>
            <div className="space-y-1.5">
              <Label htmlFor="instance-name">Name</Label>
              <Input id="instance-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <InstanceBindingControl type={type} instance={instance} org={org} onChange={setOrg} getConfig={() => values} />
            {bindingWarning(instance) && (
              <p className="flex items-start gap-1.5 text-xs text-amber-600 dark:text-amber-400">
                <TriangleAlert className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                {bindingWarning(instance)}
              </p>
            )}
            <Separator />
          </>
        )}
        <ConnectorConfigFields
          schema={type.config_schema}
          values={values}
          onChange={(key, v) => setValues((s) => ({ ...s, [key]: v }))}
          loaded={loaded}
        />
        {error && <p className="text-sm text-destructive">{error}</p>}
      </div>
      <SheetFooter>
        <Button variant="outline" onClick={onClose}>Cancel</Button>
        <Button onClick={() => { setError(null); save.mutate() }} disabled={save.isPending || (type.account_scoped && !name.trim())}>
          {save.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          Save
        </Button>
      </SheetFooter>
    </>
  )

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="sm:max-w-lg overflow-y-auto">
        <SheetHeader>
          <SheetTitle>{type.account_scoped ? `${type.name}: ${instance.name}` : type.name}</SheetTitle>
          <SheetDescription>{type.description}</SheetDescription>
        </SheetHeader>

        {hasZones(type) && instance.configured ? (
          <Tabs defaultValue="credentials" className="mt-4">
            <TabsList className="w-full">
              <TabsTrigger value="credentials" className="flex-1">Credentials</TabsTrigger>
              <TabsTrigger value="zones" className="flex-1">
                <Globe className="h-3.5 w-3.5 mr-1.5" />Zones
              </TabsTrigger>
            </TabsList>
            <TabsContent value="credentials">{credentialsContent}</TabsContent>
            <TabsContent value="zones"><ZonesTab instanceId={instance.id} /></TabsContent>
          </Tabs>
        ) : credentialsContent}
      </SheetContent>
    </Sheet>
  )
}

function DeleteDialog({
  target, onClose,
}: {
  target: { type: ConnectorTypeSummary; instance: ConnectorInstanceSummary } | null
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [conflict, setConflict] = useState<string | null>(null)
  const targetId = target?.instance.id

  useEffect(() => setConflict(null), [targetId])

  const del = useMutation({
    mutationFn: () => api.delete(`/connectors/instances/${targetId}`),
    onSuccess: () => {
      toast.success("Instance deleted")
      invalidate(qc)
      onClose()
    },
    onError: (e: ApiError) => {
      const msg = deleteConflictMessage(e)
      if (msg) setConflict(msg)
      else toast.error(`Could not delete: ${bindingErrorMessage(e)}`)
    },
  })

  return (
    <Dialog open={!!target} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete {target?.instance.name}?</DialogTitle>
          <DialogDescription>
            This removes the instance and its stored credentials. An instance that targets use cannot be
            deleted; disable it instead.
          </DialogDescription>
        </DialogHeader>
        {conflict && <p className="text-sm text-destructive">{conflict}</p>}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="destructive" onClick={() => del.mutate()} disabled={del.isPending}>
            {del.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            Delete
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function Connectors() {
  const [configuring, setConfiguring] = useState<{ typeId: string; instanceId: string } | null>(null)
  const [adding, setAdding] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<{ typeId: string; instanceId: string } | null>(null)

  const { data: connectors, isLoading } = useQuery({
    queryKey: ["connectors"],
    queryFn: () => api.get<ConnectorTypeSummary[]>("/connectors/"),
  })

  const grouped = groupByPhase(connectors ?? [])
  const find = (ref: { typeId: string; instanceId: string } | null) => {
    const type = connectors?.find((t) => t.id === ref?.typeId) ?? null
    const instance = type?.instances.find((i) => i.id === ref?.instanceId) ?? null
    return type && instance ? { type, instance } : null
  }
  const configuringNow = find(configuring)
  const deletingNow = find(deleting)

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-8">
      <AdminBreadcrumb page="Connectors" />
      <div>
        <h1 className="text-2xl font-semibold">Connectors</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Enable and configure integrations. Credentials are stored encrypted in the database.
        </p>
      </div>

      {isLoading ? (
        <div className="grid gap-4 sm:grid-cols-2">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-40 w-full" />)}
        </div>
      ) : (
        PHASE_ORDER.filter(phase => grouped[phase]?.length > 0).map(phase => (
          <div key={phase} className="space-y-3">
            <div>
              <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                {PHASE_META[phase]?.label ?? phase}
              </h2>
              <p className="text-xs text-muted-foreground">{PHASE_META[phase]?.description}</p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 items-start">
              {grouped[phase].map(t => (
                <ConnectorTypeCard
                  key={t.id}
                  type={t}
                  onConfigure={(ty, inst) => setConfiguring({ typeId: ty.id, instanceId: inst.id })}
                  onAdd={(ty) => setAdding(ty.id)}
                  onDelete={(ty, inst) => setDeleting({ typeId: ty.id, instanceId: inst.id })}
                />
              ))}
            </div>
          </div>
        ))
      )}

      <ConfigSheet type={configuringNow?.type ?? null} instance={configuringNow?.instance ?? null} onClose={() => setConfiguring(null)} />
      <AddInstanceSheet type={connectors?.find((t) => t.id === adding) ?? null} onClose={() => setAdding(null)} />
      <DeleteDialog target={deletingNow} onClose={() => setDeleting(null)} />
    </div>
  )
}
