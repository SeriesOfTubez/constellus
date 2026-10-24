// planning#277 S2c — add an organization: domain → filer → relationship.
// Nothing is created and no discovery starts until Finish.
import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ExternalLink, Loader2 } from "lucide-react"
import { api } from "@/lib/api"
import { useCan } from "@/lib/permissions"
import {
  type AddOrganizationResponse, type AddOrgState, type FilerHit, type OrgRelationship,
  addOrgRequest, addOrgStepValid, filerStatsLine, relationshipOptions,
} from "@/lib/organizations"
import { errorDetail } from "@/components/OrgCandidateParts"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { cn } from "@/lib/utils"

const NONE = "none"

function cardClass(selected: boolean, disabled = false) {
  return cn(
    "w-full text-left rounded-lg border p-3 space-y-1 text-sm",
    selected ? "border-primary bg-primary/10" : "hover:bg-accent",
    disabled && "opacity-50 cursor-not-allowed hover:bg-transparent",
  )
}

function FilerCard({ hit, selected, onSelect }: { hit: FilerHit; selected: boolean; onSelect: () => void }) {
  const stats = filerStatsLine(hit.stats)
  return (
    <div role="radio" aria-checked={selected} tabIndex={0} onClick={onSelect}
      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect() } }}
      className={cn(cardClass(selected), "cursor-pointer")}>
      <div className="flex items-start justify-between gap-2">
        <span className="font-medium">{hit.display_name ?? `CIK ${hit.cik}`}</span>
        <a href={hit.edgar_url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}
          className="inline-flex items-center gap-1 text-xs text-primary hover:underline shrink-0">
          EDGAR <ExternalLink className="h-3 w-3" />
        </a>
      </div>
      <div className="text-xs text-muted-foreground">CIK <span className="font-mono">{hit.cik}</span></div>
      {hit.why.map((w, i) => <div key={i} className="text-xs text-muted-foreground">{w}</div>)}
      {stats && <div className="text-xs text-muted-foreground">{stats}</div>}
      {hit.entity_id && <div className="text-xs text-muted-foreground">Already in Constellus</div>}
    </div>
  )
}

/** Step 3: name, relationship, authorisation. Reads `entities.mark_ours` itself so the
 *  Ours gate is testable in isolation (the flow only reaches this step via state). */
export function OrgDetailsStep({
  s, set, presetRelationship, create, onNameEdit, onBack, onFinish,
}: {
  s: AddOrgState
  set: (patch: Partial<AddOrgState>) => void
  presetRelationship?: "ours"
  create: { isPending: boolean; isError: boolean; error: unknown; reset: () => void }
  onNameEdit: () => void
  onBack: () => void
  onFinish: () => void
}) {
  const can = useCan()
  const canMarkOurs = can("entities.mark_ours")
  const options = relationshipOptions(canMarkOurs, presetRelationship)
  return (
    <div className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="ao-name">Organization name</Label>
        <Input id="ao-name" value={s.orgName} onChange={e => { onNameEdit(); set({ orgName: e.target.value }) }}
          placeholder="Example Holdings A" />
      </div>

      {presetRelationship ? (
        <p className="text-sm">Relationship: <span className="font-medium">{options[0].label}</span></p>
      ) : (
        <div className="space-y-1.5">
          <Label>Relationship</Label>
          <div role="radiogroup" className="grid grid-cols-2 gap-2">
            {options.map(o => (
              <button key={o.value} type="button" role="radio" aria-checked={s.relationship === o.value}
                disabled={o.disabled} onClick={() => set({ relationship: o.value as OrgRelationship })}
                className={cardClass(s.relationship === o.value, o.disabled)}>
                <div className="font-medium">{o.label}</div>
                {o.hint && <div className="text-xs text-muted-foreground">{o.hint}</div>}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-1.5">
        <Label htmlFor="ao-ref">Authorisation reference</Label>
        <Input id="ao-ref" value={s.reference} onChange={e => set({ reference: e.target.value })} />
        <p className="text-xs text-muted-foreground">A ticket or engagement letter id that authorises scanning this organization.</p>
      </div>

      {s.relationship === "ma_target" && (
        <div className="space-y-1.5">
          <Label htmlFor="ao-eng">Engagement name</Label>
          <Input id="ao-eng" value={s.engagementName} onChange={e => set({ engagementName: e.target.value })} />
        </div>
      )}

      {create.isError && <p role="alert" className="text-sm text-destructive">{errorDetail(create.error)}</p>}
      <div className="flex justify-between gap-2">
        <Button variant="outline" disabled={create.isPending} onClick={() => { create.reset(); onBack() }}>Back</Button>
        <Button disabled={create.isPending || !addOrgStepValid(3, s, canMarkOurs)} onClick={onFinish}>
          {create.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
          Finish
        </Button>
      </div>
    </div>
  )
}

export function AddOrganizationFlow({
  presetRelationship, onCreated, onCancel,
}: {
  presetRelationship?: "ours"
  onCreated: (resp: AddOrganizationResponse, orgName: string, cik: string | null) => void
  onCancel?: () => void
}) {
  const [step, setStep] = useState<1 | 2 | 3>(1)
  const [s, setS] = useState<AddOrgState>({
    domain: "", cik: null, orgName: "", relationship: presetRelationship ?? null, reference: "", engagementName: "",
  })
  const [sel, setSel] = useState<string | null>(null) // a CIK, NONE, or not yet chosen
  const [nameEdited, setNameEdited] = useState(false)
  const set = (patch: Partial<AddOrgState>) => setS(prev => ({ ...prev, ...patch }))

  const domain = s.domain.trim()
  const filerQ = useQuery({
    queryKey: ["filer-search", domain],
    enabled: step === 2 && !!domain,
    retry: false,
    staleTime: 60_000,
    queryFn: () => api.get<FilerHit[]>(`/organizations/filer-search?domain=${encodeURIComponent(domain)}`),
  })
  const hits = filerQ.data ?? []
  const filerSettled = !filerQ.isLoading
  // 0 hits (or an error) leaves "none" as the only meaningful, preselected choice.
  const effectiveSel = sel ?? (filerSettled && hits.length === 0 ? NONE : null)
  const chosen = hits.find(h => h.cik === effectiveSel) ?? null

  const create = useMutation({
    mutationFn: () => api.post<AddOrganizationResponse>("/organizations/", addOrgRequest(s)),
    onSuccess: resp => onCreated(resp, s.orgName.trim(), s.cik),
  })

  function leaveFiler() {
    set({ cik: chosen?.cik ?? null, ...(nameEdited ? {} : { orgName: chosen?.display_name ?? "" }) })
    setStep(3)
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">Step {step} of 3. Nothing is created until you finish.</p>

      {step === 1 && (
        <form className="space-y-3" onSubmit={e => {
          e.preventDefault()
          if (addOrgStepValid(1, s, false)) { setSel(null); setStep(2) }
        }}>
          <div className="space-y-1.5">
            <Label htmlFor="ao-domain">Primary domain</Label>
            <Input id="ao-domain" value={s.domain} onChange={e => set({ domain: e.target.value })} placeholder="fabrikam.com" />
          </div>
          <div className="flex justify-end gap-2">
            {onCancel && <Button type="button" variant="outline" onClick={onCancel}>Cancel</Button>}
            <Button type="submit" disabled={!addOrgStepValid(1, s, false)}>Continue</Button>
          </div>
        </form>
      )}

      {step === 2 && (
        <div className="space-y-3">
          <p className="text-sm">SEC filers that mention <span className="font-mono">{domain}</span>.</p>
          {filerQ.isLoading ? (
            <div className="space-y-2" data-testid="filer-skeleton"><Skeleton className="h-20" /><Skeleton className="h-20" /></div>
          ) : (
            <div role="radiogroup" className="space-y-2 max-h-[45vh] overflow-y-auto">
              {filerQ.isError && (
                <p role="alert" className="text-sm text-destructive">
                  {errorDetail(filerQ.error)}. You can still continue without a filer.
                </p>
              )}
              {hits.map(h => (
                <FilerCard key={h.cik} hit={h} selected={effectiveSel === h.cik} onSelect={() => setSel(h.cik)} />
              ))}
              <div role="radio" aria-checked={effectiveSel === NONE} tabIndex={0} onClick={() => setSel(NONE)}
                onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setSel(NONE) } }}
                className={cn(cardClass(effectiveSel === NONE), "cursor-pointer")}>
                None of these: continue without a filer
              </div>
            </div>
          )}
          <div className="flex justify-between gap-2">
            <Button variant="outline" onClick={() => setStep(1)}>Back</Button>
            <Button disabled={!filerSettled || effectiveSel === null} onClick={leaveFiler}>Continue</Button>
          </div>
        </div>
      )}

      {step === 3 && (
        <OrgDetailsStep s={s} set={set} presetRelationship={presetRelationship} create={create}
          onNameEdit={() => setNameEdited(true)} onBack={() => setStep(2)} onFinish={() => create.mutate()} />
      )}
    </div>
  )
}

export function AddOrganizationDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add organization</DialogTitle>
          <DialogDescription>Start from its primary domain.</DialogDescription>
        </DialogHeader>
        {/* Unmounted while closed (Radix unmounts the content), so re-opening starts at step 1. */}
        <AddOrganizationFlow
          onCancel={() => onOpenChange(false)}
          onCreated={resp => {
            void qc.invalidateQueries({ queryKey: ["organizations"] })
            onOpenChange(false)
            navigate(`/organizations/${resp.organization_id}`)
          }}
        />
      </DialogContent>
    </Dialog>
  )
}
