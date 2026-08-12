import { useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Plus, Trash2, Loader2, Tag, RefreshCw } from "lucide-react"
import { AdminBreadcrumb } from "@/components/AdminBreadcrumb"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { TagBadge } from "@/components/ui/tag-badge"
import { api, type TagRule } from "@/lib/api"

// ── Field catalogue ───────────────────────────────────────────────────────────

const FIELDS: Record<TagRule["entity_type"], { value: string; label: string }[]> = {
  asset: [
    { value: "asset_type", label: "Asset type" },
    { value: "value", label: "Value" },
    { value: "parent_value", label: "Parent value" },
    { value: "metadata.proxied", label: "Proxied (Cloudflare)" },
    { value: "metadata.record_type", label: "DNS record type" },
    { value: "metadata.provider_mx", label: "Provider MX" },
  ],
  finding: [
    { value: "severity", label: "Severity" },
    { value: "category", label: "Category" },
    { value: "source", label: "Source" },
    { value: "finding_type", label: "Finding type" },
    { value: "cve_id", label: "CVE ID" },
    { value: "kev", label: "In CISA KEV" },
  ],
  target: [
    { value: "type", label: "Type" },
    { value: "value", label: "Value" },
    { value: "verified", label: "Verified" },
    { value: "whois_org", label: "WHOIS org" },
    { value: "whois_asn", label: "WHOIS ASN" },
  ],
}

const OPERATORS = [
  { value: "eq", label: "equals" },
  { value: "neq", label: "not equals" },
  { value: "contains", label: "contains" },
  { value: "glob", label: "matches glob (e.g. *.cloudfront.net)" },
  { value: "startswith", label: "starts with" },
  { value: "in", label: "is one of (comma-separated)" },
  { value: "exists", label: "exists (not null)" },
]

const ENTITY_TYPE_LABELS: Record<TagRule["entity_type"], string> = {
  asset: "Asset",
  finding: "Finding",
  target: "Target",
}

// ── Add rule dialog ───────────────────────────────────────────────────────────

function AddRuleDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState("")
  const [entityType, setEntityType] = useState<TagRule["entity_type"]>("asset")
  const [field, setField] = useState("asset_type")
  const [op, setOp] = useState("eq")
  const [value, setValue] = useState("")
  const [tag, setTag] = useState("")

  const mutation = useMutation({
    mutationFn: () => {
      let condValue: unknown = value
      if (op === "in") condValue = value.split(",").map(s => s.trim()).filter(Boolean)
      if (value === "true") condValue = true
      if (value === "false") condValue = false
      return api.post("/tags/rules", {
        name,
        entity_type: entityType,
        condition: op === "exists" ? { field, op } : { field, op, value: condValue },
        tag: tag.trim().toLowerCase(),
        enabled: true,
      })
    },
    onSuccess: () => {
      toast.success("Rule created")
      qc.invalidateQueries({ queryKey: ["tag-rules"] })
      onClose()
    },
    onError: () => toast.error("Failed to create rule"),
  })

  const fields = FIELDS[entityType]

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader><DialogTitle>New Auto-Tag Rule</DialogTitle></DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label>Rule name</Label>
            <Input placeholder="e.g. Tag CDN assets" value={name} onChange={e => setName(e.target.value)} />
          </div>

          <div className="space-y-1.5">
            <Label>Apply to</Label>
            <Select value={entityType} onValueChange={v => { setEntityType(v as TagRule["entity_type"]); setField(FIELDS[v as TagRule["entity_type"]][0].value) }}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {(["asset", "finding", "target"] as const).map(et => (
                  <SelectItem key={et} value={et}>{ENTITY_TYPE_LABELS[et]}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-3 gap-2">
            <div className="space-y-1.5">
              <Label>Field</Label>
              <Select value={field} onValueChange={setField}>
                <SelectTrigger className="text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {fields.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Operator</Label>
              <Select value={op} onValueChange={setOp}>
                <SelectTrigger className="text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {OPERATORS.map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            {op !== "exists" && (
              <div className="space-y-1.5">
                <Label>Value</Label>
                <Input
                  className="text-xs font-mono"
                  placeholder={op === "in" ? "a, b, c" : op === "glob" ? "*.example.com" : "value"}
                  value={value}
                  onChange={e => setValue(e.target.value)}
                />
              </div>
            )}
          </div>

          <div className="space-y-1.5">
            <Label>Tag to apply</Label>
            <Input
              placeholder="e.g. cdn, legacy, provider-mx"
              value={tag}
              onChange={e => setTag(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            disabled={mutation.isPending || !name || !tag}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin mr-1.5" />}
            Create Rule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function TagRules() {
  const qc = useQueryClient()
  const [addOpen, setAddOpen] = useState(false)
  const [entityFilter, setEntityFilter] = useState<string>("all")

  const { data: rules, isLoading } = useQuery<TagRule[]>({
    queryKey: ["tag-rules", entityFilter],
    queryFn: () => {
      const params = entityFilter !== "all" ? `?entity_type=${entityFilter}` : ""
      return api.get<TagRule[]>(`/tags/rules${params}`)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch(`/tags/rules/${id}`, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tag-rules"] }),
    onError: () => toast.error("Failed to update rule"),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/tags/rules/${id}`),
    onSuccess: () => {
      toast.success("Rule deleted")
      qc.invalidateQueries({ queryKey: ["tag-rules"] })
    },
    onError: () => toast.error("Failed to delete rule"),
  })

  const evaluateMutation = useMutation({
    mutationFn: () => api.post("/tags/rules/evaluate"),
    onSuccess: () => toast.success("Re-evaluation queued — tags will update in the background"),
    onError: () => toast.error("Failed to queue evaluation"),
  })

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <AdminBreadcrumb page="Tag Rules" />
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Tag Rules</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Auto-tagging rules applied to assets, findings, and targets at ingest.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={evaluateMutation.isPending} onClick={() => evaluateMutation.mutate()}>
            {evaluateMutation.isPending
              ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1.5" />
              : <RefreshCw className="h-3.5 w-3.5 mr-1.5" />}
            Re-evaluate all
          </Button>
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4 mr-1.5" />New Rule
          </Button>
        </div>
      </div>

      {/* Filter */}
      <div className="flex gap-3 items-center">
        <Select value={entityFilter} onValueChange={setEntityFilter}>
          <SelectTrigger className="w-36 h-9 text-sm"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All entities</SelectItem>
            <SelectItem value="asset">Assets</SelectItem>
            <SelectItem value="finding">Findings</SelectItem>
            <SelectItem value="target">Targets</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground">{rules?.length ?? 0} rule{rules?.length !== 1 ? "s" : ""}</span>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
      ) : !rules?.length ? (
        <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
          <Tag className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="font-medium">No rules yet</p>
          <p className="text-sm mt-1">Create a rule to automatically tag assets, findings, and targets at ingest.</p>
        </div>
      ) : (
        <div className="rounded-lg border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="w-8 pl-4">On</TableHead>
                <TableHead>Name</TableHead>
                <TableHead className="w-24">Applies to</TableHead>
                <TableHead>Condition</TableHead>
                <TableHead className="w-28">Tag</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map(rule => (
                <TableRow key={rule.id} className={rule.enabled ? "" : "opacity-50"}>
                  <TableCell className="pl-4">
                    <Switch
                      checked={rule.enabled}
                      onCheckedChange={enabled => toggleMutation.mutate({ id: rule.id, enabled })}
                    />
                  </TableCell>
                  <TableCell className="font-medium text-sm">{rule.name}</TableCell>
                  <TableCell>
                    <span className="text-xs text-muted-foreground capitalize">{rule.entity_type}</span>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs font-mono bg-muted px-2 py-0.5 rounded">
                      {JSON.stringify(rule.condition)}
                    </code>
                  </TableCell>
                  <TableCell>
                    <TagBadge tag={rule.tag} />
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost" size="sm"
                      className="text-destructive hover:text-destructive"
                      disabled={deleteMutation.isPending}
                      onClick={() => { if (confirm(`Delete rule "${rule.name}"?`)) deleteMutation.mutate(rule.id) }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {addOpen && <AddRuleDialog onClose={() => setAddOpen(false)} />}
    </div>
  )
}
