import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Loader2, Plus, Trash2, Clock, Bell, Gauge, AlertTriangle, Palette } from "lucide-react"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { ACCENT_PALETTE } from "@/lib/branding"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { api, type AggressivenessTier, type AppSettings, type SystemStatus } from "@/lib/api"

type MonitoringPolicy = {
  id: string
  name: string
  tag: string | null
  schedule_cron: string
  tag_priority: number | null
  enabled: boolean
  is_default: boolean
}

const CRON_PRESETS: { label: string; value: string }[] = [
  { label: "Hourly",          value: "0 * * * *" },
  { label: "Every 4 hours",   value: "0 */4 * * *" },
  { label: "Every 12 hours",  value: "0 */12 * * *" },
  { label: "Daily (02:00 UTC)", value: "0 2 * * *" },
  { label: "Twice weekly",    value: "0 2 * * 1,4" },
  { label: "Weekly",          value: "0 2 * * 0" },
]

function describeCron(cron: string): string {
  const preset = CRON_PRESETS.find(p => p.value === cron)
  return preset ? preset.label : cron
}

function PolicyDialog({
  open, onClose, existingTags,
}: {
  open: boolean
  onClose: () => void
  existingTags: string[]
}) {
  const qc = useQueryClient()
  const [tag, setTag] = useState("")
  const [cron, setCron] = useState(CRON_PRESETS[1].value)
  const [priority, setPriority] = useState("100")

  const mutation = useMutation({
    mutationFn: () =>
      api.post<MonitoringPolicy>("/monitoring/policies", {
        tag: tag.trim(),
        schedule_cron: cron,
        tag_priority: Number(priority) || 100,
      }),
    onSuccess: () => {
      toast.success(`Policy added for tag "${tag.trim()}"`)
      qc.invalidateQueries({ queryKey: ["monitoring-policies"] })
      setTag(""); setCron(CRON_PRESETS[1].value); setPriority("100")
      onClose()
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add monitoring policy</DialogTitle>
          <DialogDescription>
            Targets carrying this tag will be scanned on this cadence instead of the default.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="policy-tag">Tag</Label>
            <Input
              id="policy-tag"
              value={tag}
              onChange={e => setTag(e.target.value)}
              placeholder="critical"
              list="existing-tags"
              autoFocus
            />
            <datalist id="existing-tags">
              {existingTags.map(t => <option key={t} value={t} />)}
            </datalist>
          </div>
          <div className="space-y-1.5">
            <Label>Schedule</Label>
            <Select value={cron} onValueChange={setCron}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {CRON_PRESETS.map(p => <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>)}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground font-mono">{cron}</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="policy-priority">Priority</Label>
            <Input
              id="policy-priority"
              type="number"
              value={priority}
              onChange={e => setPriority(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              Lower wins. When a target carries multiple matching tags, the policy with the lowest priority owns it.
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={!tag.trim() || mutation.isPending} onClick={() => mutation.mutate()}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}
            Add policy
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function MonitoringPoliciesCard() {
  const qc = useQueryClient()
  const [addOpen, setAddOpen] = useState(false)

  const { data: policies, isLoading } = useQuery({
    queryKey: ["monitoring-policies"],
    queryFn: () => api.get<MonitoringPolicy[]>("/monitoring/policies"),
  })

  const { data: existingTags } = useQuery({
    queryKey: ["all-tags"],
    queryFn: () => api.get<string[]>("/tags/"),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Partial<{ schedule_cron: string; enabled: boolean; tag_priority: number }> }) =>
      api.patch(`/monitoring/policies/${id}`, patch),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["monitoring-policies"] }),
    onError: (e: Error) => toast.error(e.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/monitoring/policies/${id}`),
    onSuccess: () => {
      toast.success("Policy removed")
      qc.invalidateQueries({ queryKey: ["monitoring-policies"] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const tagOptions = [...(existingTags ?? [])].sort()

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
        <div>
          <CardTitle className="text-base flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Monitoring policies
          </CardTitle>
          <CardDescription>
            Tag-based scan cadences. The default policy scans every target unless a tag policy claims it.
            Lower-priority policies win when a target matches multiple tags.
          </CardDescription>
        </div>
        <Button size="sm" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4 mr-1.5" />Add
        </Button>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : !policies?.length ? (
          <p className="text-sm text-muted-foreground">No policies yet.</p>
        ) : (
          <div className="rounded-md border divide-y">
            {policies.map(p => (
              <div key={p.id} className="flex items-center gap-3 px-3 py-2.5 text-sm">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    {p.is_default ? (
                      <Badge variant="outline">Default</Badge>
                    ) : (
                      <Badge variant="outline" className="font-mono">{p.tag}</Badge>
                    )}
                    {!p.enabled && <Badge variant="outline" className="text-muted-foreground">disabled</Badge>}
                    {!p.is_default && p.tag_priority !== null && (
                      <span className="text-xs text-muted-foreground">priority {p.tag_priority}</span>
                    )}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-muted-foreground">
                    <Select
                      value={p.schedule_cron}
                      onValueChange={(v) => updateMutation.mutate({ id: p.id, patch: { schedule_cron: v } })}
                    >
                      <SelectTrigger className="h-7 w-44 text-xs"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {CRON_PRESETS.map(opt => (
                          <SelectItem key={opt.value} value={opt.value}>{opt.label}</SelectItem>
                        ))}
                        {!CRON_PRESETS.some(opt => opt.value === p.schedule_cron) && (
                          <SelectItem value={p.schedule_cron}>{p.schedule_cron}</SelectItem>
                        )}
                      </SelectContent>
                    </Select>
                    <span className="font-mono">{describeCron(p.schedule_cron)}</span>
                  </div>
                </div>
                {!p.is_default && (
                  <Switch
                    checked={p.enabled}
                    onCheckedChange={(v) => updateMutation.mutate({ id: p.id, patch: { enabled: v } })}
                  />
                )}
                {!p.is_default && (
                  <Button
                    variant="ghost" size="sm"
                    className="text-destructive hover:text-destructive"
                    disabled={deleteMutation.isPending}
                    onClick={() => { if (confirm(`Remove policy for tag "${p.tag}"?`)) deleteMutation.mutate(p.id) }}
                    title="Remove"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
      <PolicyDialog open={addOpen} onClose={() => setAddOpen(false)} existingTags={tagOptions} />
    </Card>
  )
}

type NotificationRule = {
  id: string
  name: string
  enabled: boolean
  severity_threshold: "info" | "low" | "medium" | "high" | "critical"
  categories: string[]
  recipients: string[]
}

const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const

function NotificationRuleDialog({
  rule, onClose,
}: {
  rule: NotificationRule | null
  onClose: () => void
}) {
  const qc = useQueryClient()
  const isNew = rule === null
  const [name, setName] = useState(rule?.name ?? "")
  const [severity, setSeverity] = useState<NotificationRule["severity_threshold"]>(rule?.severity_threshold ?? "high")
  const [recipientsText, setRecipientsText] = useState((rule?.recipients ?? []).join(", "))
  const [enabled, setEnabled] = useState(rule?.enabled ?? true)

  const mutation = useMutation({
    mutationFn: () => {
      const recipients = recipientsText.split(/[,\s]+/).map(s => s.trim()).filter(Boolean)
      const body = { name: name.trim(), severity_threshold: severity, recipients, enabled }
      if (isNew) return api.post<NotificationRule>("/notifications/rules", body)
      return api.patch<NotificationRule>(`/notifications/rules/${rule!.id}`, body)
    },
    onSuccess: () => {
      toast.success(isNew ? "Notification rule added" : "Rule updated")
      qc.invalidateQueries({ queryKey: ["notification-rules"] })
      onClose()
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{isNew ? "Add notification rule" : "Edit notification rule"}</DialogTitle>
          <DialogDescription>
            Email recipients when a new finding lands at or above the chosen severity.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="rule-name">Name</Label>
            <Input id="rule-name" value={name} onChange={e => setName(e.target.value)} placeholder="Critical findings → security@…" autoFocus />
          </div>
          <div className="space-y-1.5">
            <Label>Severity threshold</Label>
            <Select value={severity} onValueChange={(v) => setSeverity(v as NotificationRule["severity_threshold"])}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {SEVERITIES.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Notify when a finding lands at this severity or higher.
            </p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rule-recipients">Recipients</Label>
            <Input
              id="rule-recipients"
              value={recipientsText}
              onChange={e => setRecipientsText(e.target.value)}
              placeholder="security@example.com, oncall@example.com"
            />
            <p className="text-xs text-muted-foreground">Comma- or space-separated email addresses.</p>
          </div>
          <div className="flex items-center justify-between">
            <Label htmlFor="rule-enabled">Enabled</Label>
            <Switch id="rule-enabled" checked={enabled} onCheckedChange={setEnabled} />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button disabled={!name.trim() || !recipientsText.trim() || mutation.isPending} onClick={() => mutation.mutate()}>
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}
            {isNew ? "Add rule" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function NotificationRulesCard() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<NotificationRule | null | undefined>(undefined)

  const { data: rules, isLoading } = useQuery({
    queryKey: ["notification-rules"],
    queryFn: () => api.get<NotificationRule[]>("/notifications/rules"),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch(`/notifications/rules/${id}`, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["notification-rules"] }),
    onError: (e: Error) => toast.error(e.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/notifications/rules/${id}`),
    onSuccess: () => {
      toast.success("Rule removed")
      qc.invalidateQueries({ queryKey: ["notification-rules"] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
        <div>
          <CardTitle className="text-base flex items-center gap-2">
            <Bell className="h-4 w-4" />
            Notification rules
          </CardTitle>
          <CardDescription>
            Email alerts when new findings land. Requires an enabled notification connector (Admin → Connectors).
          </CardDescription>
        </div>
        <Button size="sm" onClick={() => setEditing(null)}>
          <Plus className="h-4 w-4 mr-1.5" />Add
        </Button>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : !rules?.length ? (
          <p className="text-sm text-muted-foreground">No rules yet.</p>
        ) : (
          <div className="rounded-md border divide-y">
            {rules.map(r => (
              <div key={r.id} className="flex items-center gap-3 px-3 py-2.5 text-sm">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      className="font-medium text-left hover:underline truncate"
                      onClick={() => setEditing(r)}
                    >
                      {r.name}
                    </button>
                    <Badge variant="outline" className="text-[10px] uppercase">{r.severity_threshold}+</Badge>
                  </div>
                  <p className="mt-0.5 text-xs text-muted-foreground truncate">
                    → {r.recipients.join(", ")}
                  </p>
                </div>
                <Switch
                  checked={r.enabled}
                  onCheckedChange={(v) => toggleMutation.mutate({ id: r.id, enabled: v })}
                />
                <Button
                  variant="ghost" size="sm"
                  className="text-destructive hover:text-destructive"
                  disabled={deleteMutation.isPending}
                  onClick={() => { if (confirm(`Remove "${r.name}"?`)) deleteMutation.mutate(r.id) }}
                  title="Remove"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
      {editing !== undefined && (
        <NotificationRuleDialog rule={editing} onClose={() => setEditing(undefined)} />
      )}
    </Card>
  )
}

const AGGRESSIVENESS_TIERS: { value: AggressivenessTier; label: string; blurb: string }[] = [
  {
    value: "stealth",
    label: "Stealth",
    blurb: "Lowest noise. Nuclei capped at 10 req/s, medium+ findings only, no intrusive templates. Brute-force and dnsrecon off.",
  },
  {
    value: "polite",
    label: "Polite",
    blurb: "Default. Nuclei at 50 req/s, low+ findings, no intrusive/fuzz/dos. Brute-force with small wordlist; dnsrecon on.",
  },
  {
    value: "standard",
    label: "Standard",
    blurb: "Nuclei at 150 req/s, all severities, intrusive templates allowed. Brute-force with medium wordlist.",
  },
  {
    value: "aggressive",
    label: "Aggressive",
    blurb: "Nuclei at 500 req/s, all severities, fuzz templates enabled. Large brute-force wordlist. Can trigger WAFs and rate-limits.",
  },
]

function AggressivenessCard() {
  const qc = useQueryClient()
  const [pendingTier, setPendingTier] = useState<AggressivenessTier | null>(null)

  const { data: settings, isLoading } = useQuery({
    queryKey: ["app-settings"],
    queryFn: () => api.get<AppSettings>("/settings/"),
  })

  const mutation = useMutation({
    mutationFn: (tier: AggressivenessTier) =>
      api.put<AppSettings>("/settings/", { aggressiveness: tier }),
    onSuccess: (next) => {
      toast.success(`Aggressiveness set to ${next.aggressiveness}`)
      qc.setQueryData(["app-settings"], next)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const current = settings?.aggressiveness ?? "polite"

  function onSelect(tier: AggressivenessTier) {
    if (tier === current) return
    if (tier === "aggressive") {
      setPendingTier(tier)
      return
    }
    mutation.mutate(tier)
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Gauge className="h-4 w-4" />
            Scan aggressiveness
          </CardTitle>
          <CardDescription>
            Global default for every active scanning tool (Nuclei, Naabu, brute-force, dnsrecon).
            Passive sources (CT logs, Shodan API, DNS connectors) are unaffected.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label>Default tier</Label>
                <Select value={current} onValueChange={(v) => onSelect(v as AggressivenessTier)}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {AGGRESSIVENESS_TIERS.map(t => (
                      <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <p className="text-xs text-muted-foreground">
                {AGGRESSIVENESS_TIERS.find(t => t.value === current)?.blurb}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={pendingTier !== null} onOpenChange={(o) => !o && setPendingTier(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500" />
              Enable aggressive scanning?
            </DialogTitle>
            <DialogDescription>
              Aggressive tier runs Nuclei at 500 requests/second per target with fuzz templates enabled and
              brute-forces subdomains with a large wordlist. This can trip web application firewalls,
              get your scanner IP rate-limited, generate noisy traffic in target SOCs, and miss findings
              if upstream tools start dropping requests.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingTier(null)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={mutation.isPending}
              onClick={() => {
                if (pendingTier) mutation.mutate(pendingTier)
                setPendingTier(null)
              }}
            >
              {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}
              Enable aggressive
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

function OrgBrandingCard() {
  const qc = useQueryClient()
  const { data: settings, isLoading } = useQuery({
    queryKey: ["app-settings"],
    queryFn: () => api.get<AppSettings>("/settings/"),
  })

  const [orgName,    setOrgName]    = useState<string | null>(null)
  const [logoUrl,    setLogoUrl]    = useState<string | null>(null)
  const [accent,     setAccent]     = useState<string | null>(null)
  const [nameColor,  setNameColor]  = useState<string | null>(null)

  const current = {
    org_name:         orgName    ?? settings?.org_name         ?? "Constellus",
    org_logo_url:     logoUrl    ?? settings?.org_logo_url     ?? "",
    org_brand_accent: accent     ?? settings?.org_brand_accent ?? "#8b7bf0",
    org_name_color:   nameColor  ?? settings?.org_name_color   ?? "",
  }

  const mutation = useMutation({
    mutationFn: () =>
      api.put<AppSettings>("/settings/", {
        org_name:         current.org_name,
        org_logo_url:     current.org_logo_url,
        org_brand_accent: current.org_brand_accent,
        org_name_color:   current.org_name_color,
      }),
    onSuccess: (next) => {
      toast.success("Branding saved")
      qc.setQueryData(["app-settings"], next)
      qc.invalidateQueries({ queryKey: ["org-branding"] })
      setOrgName(null); setLogoUrl(null); setAccent(null); setNameColor(null)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const isDirty = orgName !== null || logoUrl !== null || accent !== null || nameColor !== null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Palette className="h-4 w-4" />
          Organization branding
        </CardTitle>
        <CardDescription>
          Customise the logo, name, and accent colour. The severity palette and surface colours are fixed and cannot be changed.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {isLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : (
          <>
            <div className="space-y-1.5">
              <Label htmlFor="org-name">Organisation name</Label>
              <Input
                id="org-name"
                value={current.org_name}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Constellus"
                maxLength={80}
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="org-logo">Logo URL</Label>
              <Input
                id="org-logo"
                value={current.org_logo_url ?? ""}
                onChange={(e) => setLogoUrl(e.target.value)}
                placeholder="https://example.com/logo.png"
                type="url"
              />
              <p className="text-xs text-muted-foreground">
                Must be an https:// URL. Leave blank to use the Constellus logo.
                Recommended: <strong>square</strong> PNG or SVG, minimum 64×64px, transparent background.
                Non-square logos will be letterboxed into a square slot in the sidebar.
                Logo file upload coming in a future release.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="org-name-color">Organisation name colour</Label>
              <div className="flex items-center gap-2">
                <input
                  type="color"
                  id="org-name-color"
                  value={current.org_name_color || current.org_brand_accent}
                  onChange={(e) => setNameColor(e.target.value)}
                  className="h-8 w-10 cursor-pointer rounded border border-border bg-transparent p-0.5"
                />
                <Input
                  value={current.org_name_color || ""}
                  onChange={(e) => setNameColor(e.target.value)}
                  placeholder={`Default: accent colour (${current.org_brand_accent})`}
                  className="font-mono text-xs"
                  maxLength={7}
                />
                {current.org_name_color && (
                  <button
                    onClick={() => setNameColor("")}
                    className="text-xs text-muted-foreground hover:text-foreground whitespace-nowrap"
                  >
                    Reset
                  </button>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                Colour of the organisation name in the sidebar. Leave blank to follow the accent colour.
              </p>
            </div>

            <div className="space-y-2">
              <Label>Accent colour</Label>
              <div className="flex gap-2">
                {ACCENT_PALETTE.map((c) => (
                  <button
                    key={c.value}
                    title={c.name}
                    onClick={() => setAccent(c.value)}
                    className="h-7 w-7 rounded-full ring-offset-background transition-all focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                    style={{
                      backgroundColor: c.value,
                      boxShadow: current.org_brand_accent === c.value
                        ? `0 0 0 2px var(--background), 0 0 0 4px ${c.value}`
                        : undefined,
                    }}
                    aria-label={c.name}
                    aria-pressed={current.org_brand_accent === c.value}
                  />
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                {ACCENT_PALETTE.find((c) => c.value === current.org_brand_accent)?.name ?? "Custom"} — applies to buttons, links, and interactive elements.
              </p>
            </div>

            <div className="flex justify-end">
              <Button
                onClick={() => mutation.mutate()}
                disabled={!isDirty || mutation.isPending}
                size="sm"
              >
                {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}
                Save branding
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

export default function Settings() {
  const { data: status } = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatus>("/system/status"),
  })

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <AdminBreadcrumb page="Organization" />
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">System information and configuration</p>
      </div>

      <OrgBrandingCard />

      <AggressivenessCard />

      <MonitoringPoliciesCard />

      <NotificationRulesCard />

      <Separator />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">System</CardTitle>
          <CardDescription>Current deployment information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex items-center justify-between py-2 border-b">
            <span className="text-muted-foreground">Version</span>
            <Badge variant="outline">{status?.version ?? "—"}</Badge>
          </div>
          <div className="flex items-center justify-between py-2 border-b">
            <span className="text-muted-foreground">Secrets provider</span>
            <Badge variant="outline">Environment variables</Badge>
          </div>
          <div className="flex items-center justify-between py-2">
            <span className="text-muted-foreground">Setup status</span>
            <Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">Complete</Badge>
          </div>
        </CardContent>
      </Card>

      <Separator />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Secrets</CardTitle>
          <CardDescription>
            Application secrets (SECRET_KEY, DATABASE_URL) are set via environment variables.
            Connector credentials are encrypted and stored in the database, configurable via the
            Connectors page.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  )
}
