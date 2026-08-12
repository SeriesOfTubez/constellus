import { useState, useEffect } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Plug, FlaskConical, Save, Loader2, Search, Globe, RefreshCw, Zap } from "lucide-react"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { ConnectorConfigFields, fillConfigValues } from "@/components/ConnectorConfigFields"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { api, type ConnectorSummary, type ZoneEntry } from "@/lib/api"
import { CORE_IMPACT_COPY } from "@/lib/connector-copy"

const PHASE_META: Record<string, { label: string; description: string }> = {
  discovery:    { label: "Discovery",    description: "DNS and zone data sources" },
  enrichment:   { label: "Enrichment",   description: "Asset context — cloud, firewall, vulnerability management" },
  scanning:     { label: "Scanning",     description: "Active vulnerability scanning" },
  notification: { label: "Notification", description: "Outbound alerts — email, chat, webhooks" },
}

const PHASE_ORDER = ["discovery", "enrichment", "scanning", "notification"]

function ConnectorCard({ connector, onConfigure }: { connector: ConnectorSummary; onConfigure: (c: ConnectorSummary) => void }) {
  const qc = useQueryClient()

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) =>
      api.post(`/connectors/${connector.id}/${enabled ? "enable" : "disable"}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
    onError: () => toast.error("Failed to update connector"),
  })

  const testMutation = useMutation({
    mutationFn: () => api.post<{ success: boolean; message: string }>(`/connectors/${connector.id}/test`),
    onSuccess: (r) => {
      if (r.success) toast.success(`${connector.name}: ${r.message}`)
      else toast.error(`${connector.name}: ${r.message}`)
    },
    onError: () => toast.error("Test failed"),
  })

  const syncMutation = useMutation({
    mutationFn: () => api.post(`/connectors/${connector.id}/sync`),
    onSuccess: () => toast.success(`${connector.name}: sync queued`),
    onError: () => toast.error("Failed to queue sync"),
  })

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1 min-w-0">
            <CardTitle className="text-base">{connector.name}</CardTitle>
            <CardDescription className="text-xs leading-relaxed">{connector.description}</CardDescription>
          </div>
          <Switch
            checked={connector.enabled}
            onCheckedChange={(v) => toggleMutation.mutate(v)}
            disabled={toggleMutation.isPending}
          />
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 flex-wrap">
            {connector.core && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge variant="outline" className="border-primary/40 text-primary gap-1">
                    <Zap className="h-3 w-3" />
                    Core capability
                  </Badge>
                </TooltipTrigger>
                <TooltipContent className="max-w-xs">
                  {CORE_IMPACT_COPY[connector.id]?.long ?? "Core to result quality — configuring it is strongly recommended."}
                </TooltipContent>
              </Tooltip>
            )}
            <Badge variant={connector.configured ? "success" : "outline"}>
              {connector.configured ? "Configured" : "Not configured"}
            </Badge>
            {connector.enabled && !connector.configured && (
              <Badge variant="warning">Needs config</Badge>
            )}
            {connector.enabled && connector.disabled_at_current_tier && (
              <Badge
                variant="outline"
                title={`This connector is gated off at the ${connector.current_tier} aggressiveness tier. Raise the global tier in Admin → Settings, or override it on a specific target, to activate.`}
              >
                Inactive at {connector.current_tier} tier
              </Badge>
            )}
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm"
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending || !connector.configured}>
              {testMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <FlaskConical className="h-3 w-3" />}
              Test
            </Button>
            {connector.phase === "discovery" && connector.configured && connector.enabled && (
              <Button variant="outline" size="sm"
                onClick={() => syncMutation.mutate()}
                disabled={syncMutation.isPending}>
                {syncMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                Sync
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={() => onConfigure(connector)}>
              <Plug className="h-3 w-3" />
              Configure
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

const ZONES_PAGE_SIZE = 25

function ZonesTab({ connectorId }: { connectorId: string }) {
  const qc = useQueryClient()
  const [search, setSearch] = useState("")
  const [page, setPage] = useState(1)
  const [localZones, setLocalZones] = useState<ZoneEntry[] | null>(null)
  const [dirty, setDirty] = useState(false)

  const { data: zones, isLoading } = useQuery<ZoneEntry[]>({
    queryKey: ["connector-zones", connectorId],
    queryFn: () => api.get(`/connectors/${connectorId}/zones`),
  })

  // Initialise local state from server data once
  useEffect(() => {
    if (zones && !localZones) setLocalZones(zones)
  }, [zones, localZones])

  const syncMutation = useMutation({
    mutationFn: () => api.post(`/connectors/${connectorId}/sync`),
    onError: () => toast.error("Zones saved but sync failed to queue"),
  })

  const saveMutation = useMutation({
    mutationFn: () => {
      const excluded = (localZones ?? []).filter(z => z.excluded).map(z => z.name)
      return api.put(`/connectors/${connectorId}/zones`, { excluded_zones: excluded })
    },
    onSuccess: () => {
      toast.success("Zone selections saved — sync queued")
      setDirty(false)
      qc.invalidateQueries({ queryKey: ["connector-zones", connectorId] })
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

function ConfigSheet({ connector, open, onClose }: { connector: ConnectorSummary | null; open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [values, setValues] = useState<Record<string, string | boolean>>({})
  const [loaded, setLoaded] = useState(false)
  const isDiscovery = connector?.phase === "discovery"

  useQuery({
    queryKey: ["connector-config", connector?.id],
    queryFn: async () => {
      if (!connector) return null
      const data = await api.get<{ config: Record<string, unknown> }>(`/connectors/${connector.id}/config`)
      setValues(fillConfigValues(connector.config_schema, data.config))
      setLoaded(true)
      return data
    },
    enabled: open && !!connector,
  })

  const saveMutation = useMutation({
    mutationFn: () => api.put(`/connectors/${connector!.id}/config`, { config: values }),
    onSuccess: () => {
      toast.success("Configuration saved")
      qc.invalidateQueries({ queryKey: ["connectors"] })
      onClose()
    },
    onError: () => toast.error("Failed to save configuration"),
  })

  if (!connector) return null

  const credentialsContent = (
    <>
      <div className="py-6">
        <ConnectorConfigFields
          schema={connector.config_schema}
          values={values}
          onChange={(key, v) => setValues(s => ({ ...s, [key]: v }))}
          loaded={loaded}
        />
      </div>
      <SheetFooter>
        <Button variant="outline" onClick={onClose}>Cancel</Button>
        <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
          {saveMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          Save
        </Button>
      </SheetFooter>
    </>
  )

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="sm:max-w-lg overflow-y-auto">
        <SheetHeader>
          <SheetTitle>{connector.name}</SheetTitle>
          <SheetDescription>{connector.description}</SheetDescription>
        </SheetHeader>

        {isDiscovery && connector.configured ? (
          <Tabs defaultValue="credentials" className="mt-4">
            <TabsList className="w-full">
              <TabsTrigger value="credentials" className="flex-1">Credentials</TabsTrigger>
              <TabsTrigger value="zones" className="flex-1">
                <Globe className="h-3.5 w-3.5 mr-1.5" />Zones
              </TabsTrigger>
            </TabsList>
            <TabsContent value="credentials">{credentialsContent}</TabsContent>
            <TabsContent value="zones"><ZonesTab connectorId={connector.id} /></TabsContent>
          </Tabs>
        ) : credentialsContent}
      </SheetContent>
    </Sheet>
  )
}

export default function Connectors() {
  const [configuring, setConfiguring] = useState<ConnectorSummary | null>(null)

  const { data: connectors, isLoading } = useQuery({
    queryKey: ["connectors"],
    queryFn: () => api.get<ConnectorSummary[]>("/connectors/"),
  })

  const grouped = PHASE_ORDER.reduce<Record<string, ConnectorSummary[]>>((acc, phase) => {
    acc[phase] = (connectors ?? []).filter(c => c.phase === phase)
    return acc
  }, {})

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
            <div className="grid gap-4 sm:grid-cols-2">
              {grouped[phase].map(c => (
                <ConnectorCard key={c.id} connector={c} onConfigure={setConfiguring} />
              ))}
            </div>
          </div>
        ))
      )}

      <ConfigSheet connector={configuring} open={!!configuring} onClose={() => setConfiguring(null)} />
    </div>
  )
}
