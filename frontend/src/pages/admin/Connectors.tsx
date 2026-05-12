import { useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Plug, FlaskConical, Eye, EyeOff, Save, Loader2 } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type ConnectorSummary } from "@/lib/api"

type FieldDef = { label: string; type: string; help?: string; default?: unknown; options?: string[] }

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
          <div className="flex items-center gap-2">
            <Badge variant={connector.configured ? "success" : "outline"}>
              {connector.configured ? "Configured" : "Not configured"}
            </Badge>
            {connector.enabled && !connector.configured && (
              <Badge variant="warning">Needs config</Badge>
            )}
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm"
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending || !connector.configured}>
              {testMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <FlaskConical className="h-3 w-3" />}
              Test
            </Button>
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

function SecretInput({ value, onChange, placeholder, id }: { value: string; onChange: (v: string) => void; placeholder?: string; id?: string }) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <Input id={id} type={show ? "text" : "password"} value={value}
        onChange={(e) => onChange(e.target.value)} className="pr-10" placeholder={placeholder} />
      <button type="button" onClick={() => setShow(s => !s)} tabIndex={-1}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
        {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
      </button>
    </div>
  )
}

function ConfigSheet({ connector, open, onClose }: { connector: ConnectorSummary | null; open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [values, setValues] = useState<Record<string, string>>({})
  const [loaded, setLoaded] = useState(false)

  useQuery({
    queryKey: ["connector-config", connector?.id],
    queryFn: async () => {
      if (!connector) return null
      const data = await api.get<{ config: Record<string, string> }>(`/connectors/${connector.id}/config`)
      const filled: Record<string, string> = {}
      Object.entries(connector.schema).forEach(([k, f]: [string, FieldDef]) => {
        filled[k] = data.config[k] ?? String(f.default ?? "")
      })
      setValues(filled)
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

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="sm:max-w-lg overflow-y-auto">
        <SheetHeader>
          <SheetTitle>{connector.name}</SheetTitle>
          <SheetDescription>{connector.description}</SheetDescription>
        </SheetHeader>

        <div className="py-6 space-y-5">
          {!loaded
            ? Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)
            : Object.entries(connector.schema).map(([key, field]: [string, FieldDef]) => (
              <div key={key} className="space-y-1.5">
                <Label htmlFor={key}>{field.label}</Label>
                {field.type === "secret" ? (
                  <SecretInput id={key} value={values[key] ?? ""}
                    onChange={(v) => setValues(s => ({ ...s, [key]: v }))}
                    placeholder={`Enter ${field.label.toLowerCase()}`} />
                ) : field.type === "select" ? (
                  <Select value={values[key] ?? String(field.default ?? "")}
                    onValueChange={(v) => setValues(s => ({ ...s, [key]: v }))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {field.options?.map(o => <SelectItem key={o} value={o}>{o}</SelectItem>)}
                    </SelectContent>
                  </Select>
                ) : (
                  <Input id={key} value={values[key] ?? ""}
                    onChange={(e) => setValues(s => ({ ...s, [key]: e.target.value }))}
                    placeholder={field.help ?? `Enter ${field.label.toLowerCase()}`} />
                )}
                {field.help && field.type !== "select" && (
                  <p className="text-xs text-muted-foreground">{field.help}</p>
                )}
              </div>
            ))}
        </div>

        <SheetFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => saveMutation.mutate()} disabled={saveMutation.isPending}>
            {saveMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save
          </Button>
        </SheetFooter>
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
    <div className="p-6 max-w-4xl mx-auto space-y-8">
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
