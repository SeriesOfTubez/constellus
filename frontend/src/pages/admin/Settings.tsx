import { useEffect, useState } from "react"
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
import { Skeleton } from "@/components/ui/skeleton"
import { AlertHistoryList } from "@/components/AlertHistoryList"
import { DigestHistoryList } from "@/components/DigestHistoryList"
import { BASE_URL_MAX, digestHourWarning, validBaseUrl, validDigestHour } from "@/lib/digestSettings"
import { Switch } from "@/components/ui/switch"
import {
  IMAGE_KIB_MAX, IMAGE_KIB_MIN, QUEUE_TIMEOUT_MAX, QUEUE_TIMEOUT_MIN, REVISIT_DAYS_MAX,
  REVISIT_DAYS_MIN, ARCHIVE_FRESHNESS_MAX, ARCHIVE_FRESHNESS_MIN, UA_MAX_LEN, IMAGE_KEEP_MAX, IMAGE_KEEP_MIN, PROXY_CONNECT_TIMEOUT_MAX,
  PROXY_CONNECT_TIMEOUT_MIN, PROXY_IDLE_TIMEOUT_MAX, PROXY_IDLE_TIMEOUT_MIN, PROXY_MAX_CONN_MAX,
  PROXY_MAX_CONN_MIN, bytesToKiB, kibToBytes, validateCaptureSettings,
  SWEEP_PAUSE_MIN, SWEEP_PAUSE_MAX, SWEEP_BACKOFF_MIN, SWEEP_BACKOFF_MAX,
  SWEEP_TIME_LIMIT_MIN, SWEEP_TIME_LIMIT_MAX, SWEEP_MAX_FAILURES_MIN, SWEEP_MAX_FAILURES_MAX,
  SWEEP_RETRY_LOOKUP_MIN, SWEEP_RETRY_LOOKUP_MAX, SWEEP_RETRY_OTHER_MIN, SWEEP_RETRY_OTHER_MAX,
} from "@/lib/captureSettings"
import {
  REDISCOVERY_TIME_LIMIT_MIN, REDISCOVERY_TIME_LIMIT_MAX, REDISCOVERY_PAUSE_MIN, REDISCOVERY_PAUSE_MAX,
  REDISCOVERY_BATCH_MIN, REDISCOVERY_BATCH_MAX, REDISCOVERY_REFRESH_MIN, REDISCOVERY_REFRESH_MAX,
  REDISCOVERY_FAILED_RETRY_MIN, REDISCOVERY_FAILED_RETRY_MAX, validateDiscoverySettings,
} from "@/lib/discoverySettings"
import { api, type AlertDispatch, type AggressivenessTier, type AppSettings, type CaptureSettings, type DigestSettings, type DigestSummary, type DiscoverySettings, type SystemStatus } from "@/lib/api"

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
  kind: "finding" | "org_discovery"
  name: string
  enabled: boolean
  severity_threshold: "info" | "low" | "medium" | "high" | "critical"
  categories: string[]
  recipients: string[]
  mode: "immediate" | "digest" | "both"
}

const DELIVERY_MODES: { value: NotificationRule["mode"]; label: string }[] = [
  { value: "immediate", label: "Immediately (each scan)" },
  { value: "digest", label: "Daily digest only" },
  { value: "both", label: "Both" },
]

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
  const [mode, setMode] = useState<NotificationRule["mode"]>(rule?.mode ?? "immediate")
  // The kind is chosen at create time only; the server does not allow changing it.
  const [newKind, setNewKind] = useState<NotificationRule["kind"]>("finding")
  const kind = isNew ? newKind : (rule?.kind ?? "finding")
  const isOrg = kind === "org_discovery"

  const mutation = useMutation({
    mutationFn: () => {
      const recipients = recipientsText.split(/[,\s]+/).map(s => s.trim()).filter(Boolean)
      if (isNew && isOrg) {
        return api.post<NotificationRule>("/notifications/rules", {
          name: name.trim(), kind: "org_discovery", recipients, enabled,
        })
      }
      if (!isNew && isOrg) {
        return api.patch<NotificationRule>(`/notifications/rules/${rule!.id}`, {
          name: name.trim(), recipients, enabled,
        })
      }
      const body = { name: name.trim(), severity_threshold: severity, recipients, enabled, mode }
      if (isNew) return api.post<NotificationRule>("/notifications/rules", { ...body, kind: "finding" })
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
            {isOrg
              ? "Email recipients a daily digest of new organization discovery candidates."
              : "Email recipients when a new finding lands at or above the chosen severity."}
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label>What it's about</Label>
            {isNew ? (
              <Select value={newKind} onValueChange={(v) => setNewKind(v as NotificationRule["kind"])}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="finding">New findings</SelectItem>
                  <SelectItem value="org_discovery">New organization discovery candidates</SelectItem>
                </SelectContent>
              </Select>
            ) : (
              <p className="text-sm">{isOrg ? "New organization discovery candidates" : "New findings"}</p>
            )}
            {isOrg && (
              <p className="text-xs text-muted-foreground">
                Sent once a day in the digest. Organizations under a pre-close or abandoned deal are never included.
              </p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="rule-name">Name</Label>
            <Input id="rule-name" value={name} onChange={e => setName(e.target.value)} placeholder="Critical findings → security@…" autoFocus />
          </div>
          {!isOrg && (<>
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
            <Label>Delivery</Label>
            <Select value={mode} onValueChange={(v) => setMode(v as NotificationRule["mode"])}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {DELIVERY_MODES.map(m => <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>)}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Daily digest groups the day's alerts into one email at the digest hour below. Alerts are recorded either way.
            </p>
          </div>
          </>)}
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

function DigestSettingsBlock() {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ["digest-settings"],
    queryFn: () => api.get<DigestSettings>("/notifications/digest-settings"),
  })
  const [hourDraft, setHourDraft] = useState("")
  const [urlDraft, setUrlDraft] = useState("")
  const [hourErr, setHourErr] = useState<string | null>(null)
  const [urlErr, setUrlErr] = useState<string | null>(null)
  // One effect per field: saving one field must not reset an in-progress
  // edit of the other when the query refetches.
  useEffect(() => {
    if (data) setHourDraft(String(data.digest_hour_utc))
  }, [data?.digest_hour_utc])
  useEffect(() => {
    if (data) setUrlDraft(data.app_base_url)
  }, [data?.app_base_url])

  const hourNum = hourDraft.trim() === "" ? NaN : Number(hourDraft)
  const hourValid = validDigestHour(hourNum)
  const urlValid = validBaseUrl(urlDraft.trim())
  const warning = hourValid ? digestHourWarning(hourNum) : null

  const save = useMutation({
    mutationFn: (body: Partial<DigestSettings>) => api.put<DigestSettings>("/notifications/digest-settings", body),
    onSuccess: () => {
      toast.success("Digest settings saved")
      qc.invalidateQueries({ queryKey: ["digest-settings"] })
    },
  })
  const run = (body: Partial<DigestSettings>, setErr: (m: string | null) => void) => {
    setErr(null)
    save.mutate(body, { onError: (e: Error) => setErr(e.message) })
  }

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-medium">Digest settings</h4>
      <div className="space-y-1.5">
        <Label htmlFor="digest-hour">Digest hour (UTC, 0-23)</Label>
        <div className="flex gap-2">
          <Input id="digest-hour" type="number" min={0} max={23} step={1} className="h-8 w-24 text-xs"
            value={hourDraft} onChange={e => setHourDraft(e.target.value)} aria-invalid={!hourValid} />
          <Button size="sm" className="h-8" disabled={!hourValid || save.isPending}
            onClick={() => run({ digest_hour_utc: hourNum }, setHourErr)}>Save</Button>
        </div>
        {!hourValid && <p className="text-xs text-destructive">A whole number from 0 to 23.</p>}
        {warning && <p className="text-xs text-amber-600 dark:text-amber-500">{warning}</p>}
        {hourErr && <p className="text-xs text-destructive">{hourErr}</p>}
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="digest-base-url">App link base URL (optional)</Label>
        <div className="flex gap-2">
          <Input id="digest-base-url" className="h-8 text-xs"
            value={urlDraft} onChange={e => setUrlDraft(e.target.value)} aria-invalid={!urlValid}
            placeholder="https://easm.example.com" />
          <Button size="sm" className="h-8" disabled={!urlValid || save.isPending}
            onClick={() => run({ app_base_url: urlDraft.trim() }, setUrlErr)}>Save</Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Used to turn record paths in digest emails into links, e.g. https://easm.example.com
        </p>
        {!urlValid && <p className="text-xs text-destructive">Must be empty or an http(s) URL of at most {BASE_URL_MAX} characters.</p>}
        {urlErr && <p className="text-xs text-destructive">{urlErr}</p>}
      </div>
    </div>
  )
}

function NotificationRulesCard() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<NotificationRule | null | undefined>(undefined)

  const { data: rules, isLoading } = useQuery({
    queryKey: ["notification-rules"],
    queryFn: () => api.get<NotificationRule[]>("/notifications/rules"),
  })

  const { data: alerts, isLoading: alertsLoading, isError: alertsError } = useQuery({
    queryKey: ["notification-alerts"],
    queryFn: () => api.get<AlertDispatch[]>("/notifications/alerts?limit=20"),
  })

  const { data: digests, isLoading: digestsLoading, isError: digestsError } = useQuery({
    queryKey: ["notification-digests"],
    queryFn: () => api.get<DigestSummary[]>("/notifications/digests?limit=10"),
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
                    {r.kind === "org_discovery" && (
                      <Badge variant="secondary" className="text-[10px]">Org discovery</Badge>
                    )}
                    {r.kind !== "org_discovery" && (
                      <Badge variant="outline" className="text-[10px] uppercase">{r.severity_threshold}+</Badge>
                    )}
                    {r.kind !== "org_discovery" && r.mode && r.mode !== "immediate" && (
                      <Badge variant="secondary" className="text-[10px] text-muted-foreground">
                        {r.mode === "digest" ? "Digest" : "Immediate + digest"}
                      </Badge>
                    )}
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
        <Separator className="my-4" />
        <DigestSettingsBlock />
        <Separator className="my-4" />
        <h4 className="text-sm font-medium mb-2">Recent alerts</h4>
        {alertsLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : alertsError ? (
          <p className="text-sm text-muted-foreground">Could not load alert history.</p>
        ) : (
          <AlertHistoryList dispatches={alerts ?? []} />
        )}
        <h4 className="text-sm font-medium mt-4 mb-2">Recent digests</h4>
        {digestsLoading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : digestsError ? (
          <p className="text-sm text-muted-foreground">Could not load digest history.</p>
        ) : (
          <DigestHistoryList digests={digests ?? []} />
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

const UA_MODES: { value: CaptureSettings["user_agent_mode"]; label: string; description: string }[] = [
  { value: "stock", label: "Stock browser", description: "Looks like an ordinary visitor." },
  { value: "identifying", label: "Identifying", description: "Tells the site who is looking. On a pre-close target this can reveal the deal." },
]

export function CaptureSettingsCard() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ["capture-settings"],
    queryFn: () => api.get<CaptureSettings>("/settings/capture"),
  })
  // Numeric fields are held as strings so a half-typed value is not coerced.
  const [days, setDays] = useState("")
  const [mode, setMode] = useState<CaptureSettings["user_agent_mode"]>("stock")
  const [ua, setUa] = useState("")
  const [kib, setKib] = useState("")
  const [timeout, setTimeoutS] = useState("")
  const [keep, setKeep] = useState("")
  const [connT, setConnT] = useState("")
  const [idleT, setIdleT] = useState("")
  const [maxConn, setMaxConn] = useState("")
  const [archiveDays, setArchiveDays] = useState("")
  const [swPause, setSwPause] = useState("")
  const [swBackoff, setSwBackoff] = useState("")
  const [swLimit, setSwLimit] = useState("")
  const [swMaxFail, setSwMaxFail] = useState("")
  const [swRetryLookup, setSwRetryLookup] = useState("")
  const [swRetryOther, setSwRetryOther] = useState("")
  useEffect(() => {
    if (!data) return
    setDays(String(data.browse_revisit_days))
    setMode(data.user_agent_mode)
    setUa(data.identifying_user_agent)
    setKib(String(bytesToKiB(data.max_image_bytes)))
    setTimeoutS(String(data.queue_timeout_seconds))
    setKeep(String(data.image_keep_count))
    setConnT(String(data.proxy_connect_timeout_seconds))
    setIdleT(String(data.proxy_idle_timeout_seconds))
    setMaxConn(String(data.proxy_max_connections))
    setArchiveDays(String(data.archive_freshness_days))
    setSwPause(String(data.sweep_pause_seconds))
    setSwBackoff(String(data.sweep_lookup_backoff_seconds))
    setSwLimit(String(data.sweep_time_limit_seconds))
    setSwMaxFail(String(data.sweep_max_consecutive_lookup_failures))
    setSwRetryLookup(String(data.sweep_retry_after_lookup_days))
    setSwRetryOther(String(data.sweep_retry_after_other_days))
  }, [data])

  const num = (s: string) => (s.trim() === "" ? NaN : Number(s))
  const draft: CaptureSettings = {
    browse_revisit_days: num(days),
    user_agent_mode: mode,
    identifying_user_agent: ua,
    max_image_bytes: kibToBytes(num(kib)),
    queue_timeout_seconds: num(timeout),
    image_keep_count: num(keep),
    proxy_connect_timeout_seconds: num(connT),
    proxy_idle_timeout_seconds: num(idleT),
    proxy_max_connections: num(maxConn),
    archive_freshness_days: num(archiveDays),
    sweep_pause_seconds: num(swPause),
    sweep_lookup_backoff_seconds: num(swBackoff),
    sweep_time_limit_seconds: num(swLimit),
    sweep_max_consecutive_lookup_failures: num(swMaxFail),
    sweep_retry_after_lookup_days: num(swRetryLookup),
    sweep_retry_after_other_days: num(swRetryOther),
  }
  const error = data ? validateCaptureSettings(draft) : null
  const dirty = data !== undefined && (
    draft.browse_revisit_days !== data.browse_revisit_days ||
    draft.user_agent_mode !== data.user_agent_mode ||
    draft.identifying_user_agent !== data.identifying_user_agent ||
    draft.max_image_bytes !== data.max_image_bytes ||
    draft.queue_timeout_seconds !== data.queue_timeout_seconds ||
    draft.image_keep_count !== data.image_keep_count ||
    draft.proxy_connect_timeout_seconds !== data.proxy_connect_timeout_seconds ||
    draft.proxy_idle_timeout_seconds !== data.proxy_idle_timeout_seconds ||
    draft.proxy_max_connections !== data.proxy_max_connections ||
    draft.archive_freshness_days !== data.archive_freshness_days ||
    draft.sweep_pause_seconds !== data.sweep_pause_seconds ||
    draft.sweep_lookup_backoff_seconds !== data.sweep_lookup_backoff_seconds ||
    draft.sweep_time_limit_seconds !== data.sweep_time_limit_seconds ||
    draft.sweep_max_consecutive_lookup_failures !== data.sweep_max_consecutive_lookup_failures ||
    draft.sweep_retry_after_lookup_days !== data.sweep_retry_after_lookup_days ||
    draft.sweep_retry_after_other_days !== data.sweep_retry_after_other_days
  )
  const save = useMutation({
    mutationFn: () => api.put<CaptureSettings>("/settings/capture", draft),
    onSuccess: (next) => {
      qc.setQueryData(["capture-settings"], next)
      qc.invalidateQueries({ queryKey: ["capture-settings"] })
      toast.success("Page capture settings saved")
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  })

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Page capture</CardTitle>
        <CardDescription className="text-xs">How automatic and manual page captures behave.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading || !data ? <Skeleton className="h-28" /> : (
          <>
            <div className="space-y-1">
              <Label htmlFor="capture-revisit-days" className="text-xs text-muted-foreground">Revisit budget (days)</Label>
              <Input id="capture-revisit-days" type="number" min={REVISIT_DAYS_MIN} max={REVISIT_DAYS_MAX} step={1}
                className="h-8 w-24 text-xs" value={days} onChange={(e) => setDays(e.target.value)} />
              <p className="text-xs text-muted-foreground">An automatic capture skips a domain captured within this many days. A manual Re-capture is not limited.</p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="capture-archive-days" className="text-xs text-muted-foreground">Archive snapshot freshness (days)</Label>
              <Input id="capture-archive-days" type="number" min={ARCHIVE_FRESHNESS_MIN} max={ARCHIVE_FRESHNESS_MAX} step={1}
                className="h-8 w-24 text-xs" value={archiveDays} onChange={(e) => setArchiveDays(e.target.value)} />
              <p className="text-xs text-muted-foreground">How old a web-archive snapshot may be and still be used instead of visiting the site (1–90).</p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="capture-ua-mode" className="text-xs text-muted-foreground">User-Agent</Label>
              <Select value={mode} onValueChange={(v) => setMode(v as CaptureSettings["user_agent_mode"])}>
                <SelectTrigger id="capture-ua-mode" className="h-8 w-80 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {UA_MODES.map(m => <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>)}
                </SelectContent>
              </Select>
              <ul className="space-y-0.5 text-xs text-muted-foreground">
                {UA_MODES.map(m => <li key={m.value}><span className="font-medium">{m.label}:</span> {m.description}</li>)}
              </ul>
            </div>
            <div className="space-y-1">
              <Label htmlFor="capture-ua-string" className="text-xs text-muted-foreground">Identifying User-Agent string</Label>
              <Input id="capture-ua-string" maxLength={UA_MAX_LEN} className="h-8 text-xs"
                value={ua} disabled={mode !== "identifying"} onChange={(e) => setUa(e.target.value)} />
              <p className="text-xs text-muted-foreground">Printable ASCII, up to {UA_MAX_LEN} characters.</p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="capture-max-kib" className="text-xs text-muted-foreground">Max screenshot size (KiB)</Label>
              <Input id="capture-max-kib" type="number" min={IMAGE_KIB_MIN} max={IMAGE_KIB_MAX} step={1}
                className="h-8 w-28 text-xs" value={kib} onChange={(e) => setKib(e.target.value)} />
              <p className="text-xs text-muted-foreground">Larger pages are re-encoded at lower quality; if none fits, the capture keeps its record without an image.</p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="capture-queue-timeout" className="text-xs text-muted-foreground">Queue timeout (seconds)</Label>
              <Input id="capture-queue-timeout" type="number" min={QUEUE_TIMEOUT_MIN} max={QUEUE_TIMEOUT_MAX} step={1}
                className="h-8 w-28 text-xs" value={timeout} onChange={(e) => setTimeoutS(e.target.value)} />
              <p className="text-xs text-muted-foreground">A capture not finished in this time is marked timed out.</p>
            </div>
            <div className="space-y-1">
              <Label htmlFor="capture-image-keep" className="text-xs text-muted-foreground">Screenshots kept per domain</Label>
              <Input id="capture-image-keep" type="number" min={IMAGE_KEEP_MIN} max={IMAGE_KEEP_MAX} step={1}
                className="h-8 w-24 text-xs" value={keep} onChange={(e) => setKeep(e.target.value)} />
              <p className="text-xs text-muted-foreground">Older screenshot files are deleted; the capture record stays.</p>
            </div>
            <div className="space-y-3 border-t pt-3">
              <h4 className="text-xs font-medium">Capture proxy</h4>
              <div className="space-y-1">
                <Label htmlFor="capture-proxy-connect" className="text-xs text-muted-foreground">Proxy connect timeout (s)</Label>
                <Input id="capture-proxy-connect" type="number" min={PROXY_CONNECT_TIMEOUT_MIN} max={PROXY_CONNECT_TIMEOUT_MAX} step={1}
                  className="h-8 w-24 text-xs" value={connT} onChange={(e) => setConnT(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="capture-proxy-idle" className="text-xs text-muted-foreground">Proxy idle timeout (s)</Label>
                <Input id="capture-proxy-idle" type="number" min={PROXY_IDLE_TIMEOUT_MIN} max={PROXY_IDLE_TIMEOUT_MAX} step={1}
                  className="h-8 w-24 text-xs" value={idleT} onChange={(e) => setIdleT(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="capture-proxy-maxconn" className="text-xs text-muted-foreground">Proxy max connections</Label>
                <Input id="capture-proxy-maxconn" type="number" min={PROXY_MAX_CONN_MIN} max={PROXY_MAX_CONN_MAX} step={1}
                  className="h-8 w-28 text-xs" value={maxConn} onChange={(e) => setMaxConn(e.target.value)} />
              </div>
              <p className="text-xs text-muted-foreground">Applied by the capture proxy to new connections within about 10 seconds; connections already open keep their limits.</p>
            </div>
            <div className="space-y-3 border-t pt-3">
              <h4 className="text-xs font-medium">Automatic capture (hourly)</h4>
              <p className="text-xs text-muted-foreground">Each hour, Constellus captures the due domain candidates one at a time, oldest first.</p>
              <div className="space-y-1">
                <Label htmlFor="capture-sweep-pause" className="text-xs text-muted-foreground">Pause between candidates (seconds)</Label>
                <Input id="capture-sweep-pause" type="number" min={SWEEP_PAUSE_MIN} max={SWEEP_PAUSE_MAX} step={1}
                  className="h-8 w-24 text-xs" value={swPause} onChange={(e) => setSwPause(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="capture-sweep-backoff" className="text-xs text-muted-foreground">Wait after the snapshot service fails (seconds)</Label>
                <Input id="capture-sweep-backoff" type="number" min={SWEEP_BACKOFF_MIN} max={SWEEP_BACKOFF_MAX} step={1}
                  className="h-8 w-28 text-xs" value={swBackoff} onChange={(e) => setSwBackoff(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="capture-sweep-limit" className="text-xs text-muted-foreground">Stop each hourly run after (seconds)</Label>
                <Input id="capture-sweep-limit" type="number" min={SWEEP_TIME_LIMIT_MIN} max={SWEEP_TIME_LIMIT_MAX} step={1}
                  className="h-8 w-28 text-xs" value={swLimit} onChange={(e) => setSwLimit(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="capture-sweep-maxfail" className="text-xs text-muted-foreground">Stop the run after this many snapshot-service failures in a row</Label>
                <Input id="capture-sweep-maxfail" type="number" min={SWEEP_MAX_FAILURES_MIN} max={SWEEP_MAX_FAILURES_MAX} step={1}
                  className="h-8 w-24 text-xs" value={swMaxFail} onChange={(e) => setSwMaxFail(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="capture-sweep-retry-lookup" className="text-xs text-muted-foreground">Try again after a snapshot-service failure (days)</Label>
                <Input id="capture-sweep-retry-lookup" type="number" min={SWEEP_RETRY_LOOKUP_MIN} max={SWEEP_RETRY_LOOKUP_MAX} step={1}
                  className="h-8 w-24 text-xs" value={swRetryLookup} onChange={(e) => setSwRetryLookup(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="capture-sweep-retry-other" className="text-xs text-muted-foreground">Try again after any other refusal (days)</Label>
                <Input id="capture-sweep-retry-other" type="number" min={SWEEP_RETRY_OTHER_MIN} max={SWEEP_RETRY_OTHER_MAX} step={1}
                  className="h-8 w-24 text-xs" value={swRetryOther} onChange={(e) => setSwRetryOther(e.target.value)} />
              </div>
            </div>
            {error && <p className="text-xs text-destructive">{error}</p>}
            <Button size="sm" className="h-8" aria-label="Save page capture settings"
              disabled={!dirty || error !== null || save.isPending} onClick={() => save.mutate()}>Save</Button>
          </>
        )}
      </CardContent>
    </Card>
  )
}

export function DiscoverySettingsCard() {
  const qc = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ["settings", "discovery"],
    queryFn: () => api.get<DiscoverySettings>("/settings/discovery"),
  })
  // Numeric fields are held as strings so a half-typed value is not coerced.
  const [limit, setLimit] = useState("")
  const [pause, setPause] = useState("")
  const [batch, setBatch] = useState("")
  const [refresh, setRefresh] = useState("")
  const [failedRetry, setFailedRetry] = useState("")
  useEffect(() => {
    if (!data) return
    setLimit(String(data.rediscovery_time_limit_seconds))
    setPause(String(data.rediscovery_unit_pause_seconds))
    setBatch(String(data.rediscovery_due_batch))
    setRefresh(String(data.rediscovery_refresh_interval_days))
    setFailedRetry(String(data.rediscovery_failed_retry_days))
  }, [data])

  const num = (s: string) => (s.trim() === "" ? NaN : Number(s))
  const draft: DiscoverySettings = {
    rediscovery_time_limit_seconds: num(limit),
    rediscovery_unit_pause_seconds: num(pause),
    rediscovery_due_batch: num(batch),
    rediscovery_refresh_interval_days: num(refresh),
    rediscovery_failed_retry_days: num(failedRetry),
  }
  const error = data ? validateDiscoverySettings(draft) : null
  const dirty = data !== undefined && (
    draft.rediscovery_time_limit_seconds !== data.rediscovery_time_limit_seconds ||
    draft.rediscovery_unit_pause_seconds !== data.rediscovery_unit_pause_seconds ||
    draft.rediscovery_due_batch !== data.rediscovery_due_batch ||
    draft.rediscovery_refresh_interval_days !== data.rediscovery_refresh_interval_days ||
    draft.rediscovery_failed_retry_days !== data.rediscovery_failed_retry_days
  )
  const save = useMutation({
    mutationFn: () => api.put<DiscoverySettings>("/settings/discovery", draft),
    onSuccess: (next) => {
      qc.setQueryData(["settings", "discovery"], next)
      qc.invalidateQueries({ queryKey: ["settings", "discovery"] })
      toast.success("Discovery settings saved")
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  })

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Discovery</CardTitle>
        <CardDescription className="text-xs">How often and how hard Constellus re-runs discovery.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading || !data ? <Skeleton className="h-28" /> : (
          <>
            <div className="space-y-3">
              <h4 className="text-xs font-medium">Re-discovery (hourly)</h4>
              <p className="text-xs text-muted-foreground">Each hour, Constellus refreshes the organization roots and domains that are due, oldest first. Whatever is left waits for the next hour.</p>
              <div className="space-y-1">
                <Label htmlFor="discovery-time-limit" className="text-xs text-muted-foreground">Stop each hourly run after (seconds)</Label>
                <Input id="discovery-time-limit" type="number" min={REDISCOVERY_TIME_LIMIT_MIN} max={REDISCOVERY_TIME_LIMIT_MAX} step={1}
                  className="h-8 w-28 text-xs" value={limit} onChange={(e) => setLimit(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="discovery-pause" className="text-xs text-muted-foreground">Pause between items (seconds)</Label>
                <Input id="discovery-pause" type="number" min={REDISCOVERY_PAUSE_MIN} max={REDISCOVERY_PAUSE_MAX} step={1}
                  className="h-8 w-24 text-xs" value={pause} onChange={(e) => setPause(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="discovery-batch" className="text-xs text-muted-foreground">Items read per kind per run</Label>
                <Input id="discovery-batch" type="number" min={REDISCOVERY_BATCH_MIN} max={REDISCOVERY_BATCH_MAX} step={1}
                  className="h-8 w-28 text-xs" value={batch} onChange={(e) => setBatch(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="discovery-refresh" className="text-xs text-muted-foreground">Refresh each item every (days)</Label>
                <Input id="discovery-refresh" type="number" min={REDISCOVERY_REFRESH_MIN} max={REDISCOVERY_REFRESH_MAX} step={1}
                  className="h-8 w-24 text-xs" value={refresh} onChange={(e) => setRefresh(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label htmlFor="discovery-failed-retry" className="text-xs text-muted-foreground">Try a failed item again after (days)</Label>
                <Input id="discovery-failed-retry" type="number" min={REDISCOVERY_FAILED_RETRY_MIN} max={REDISCOVERY_FAILED_RETRY_MAX} step={1}
                  className="h-8 w-24 text-xs" value={failedRetry} onChange={(e) => setFailedRetry(e.target.value)} />
                <p className="text-xs text-muted-foreground">No longer than the refresh interval.</p>
              </div>
            </div>
            {error && <p className="text-xs text-destructive">{error}</p>}
            <Button size="sm" className="h-8" aria-label="Save discovery settings"
              disabled={!dirty || error !== null || save.isPending} onClick={() => save.mutate()}>Save</Button>
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

      <CaptureSettingsCard />

      <DiscoverySettingsCard />

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
