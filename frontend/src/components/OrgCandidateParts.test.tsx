import { beforeEach, describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { CandidateDetail, CandidateRow, OrganizationSummary, SignalDetail } from "@/lib/organizations"
import { AssetsCell, CandidateFlyoutContent, ClaimDialog, SignalsCell, StateCell } from "@/components/OrgCandidateParts"

// Zustand's SSR snapshot is the store's INITIAL state, so setState cannot drive
// renderToStaticMarkup; stand in for the permission hook instead.
const perms = vi.hoisted(() => ({ current: [] as string[] }))
vi.mock("@/lib/permissions", () => ({ useCan: () => (p: string) => perms.current.includes(p) }))

// Radix Dialog portals its content, which renderToStaticMarkup cannot see; pass the
// parts through so ClaimDialog's own markup is what is asserted.
vi.mock("@/components/ui/dialog", () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <div>{children}</div>
  return { Dialog: Pass, DialogContent: Pass, DialogDescription: Pass, DialogFooter: Pass, DialogHeader: Pass, DialogTitle: Pass }
})

const labelOf = (t: string) => ({ mx_into_claimed: "MX into claimed", shared_vanity_ns: "Shared vanity nameserver", name_similarity: "Name similarity", admin_seed: "Admin seed" }[t] ?? t)

const row = (over: Partial<CandidateRow> = {}): CandidateRow => ({
  id: "c1", root_entity_id: "r", value: "fabrikam.com", kind: "domain", status: "open", strength: "strong", proposable: true,
  affiliated: { id: "a", name: "Example Holdings A" }, affiliated_is_default: false, signals: [], first_seen_at: null,
  previously_rejected: null, target_id: null, decided_by_connector_instance_id: null, asset_count: null,
  open_findings: null, worst_severity: null, rir: null, rir_handle: null, ...over,
})
const html = (n: React.ReactNode) => renderToStaticMarkup(<MemoryRouter><TooltipProvider>{n}</TooltipProvider></MemoryRouter>)
const sig = (signal_type: string, tier: "strong" | "supporting" | "context") => ({ signal_type, tier, family: "f", count: 1 })

describe("cells", () => {
  it("Signals cell shows labels and +n beyond two", () => {
    const out = html(<SignalsCell labelOf={labelOf} row={row({ signals: [sig("mx_into_claimed", "supporting"), sig("shared_vanity_ns", "supporting"), sig("name_similarity", "context")] })} />)
    expect(out).toContain("MX into claimed")
    expect(out).toContain("Shared vanity nameserver")
    expect(out).not.toContain(">Name similarity<")
    expect(out).toContain("+1")
  })
  it("Assets cell: claimed with zero says no assets recorded; open shows a dash", () => {
    expect(html(<AssetsCell row={row({ status: "claimed", asset_count: 0 })} />)).toContain("no assets recorded")
    expect(html(<AssetsCell row={row({ status: "open" })} />)).toContain("—")
    const bar = html(<AssetsCell row={row({ status: "claimed", asset_count: 4, open_findings: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 } })} />)
    expect(bar).toContain("bg-red-500")
  })
  it("State cell shows via connector and Claimed · seed", () => {
    const out = html(<StateCell row={row({ status: "claimed", decided_by_connector_instance_id: "k", signals: [sig("admin_seed", "strong")] })} />)
    expect(out).toContain("Claimed · seed")
    expect(out).toContain("via connector")
    expect(html(<StateCell row={row({ previously_rejected: { reason: "r", at: "t" } })} />)).toContain("previously rejected")
  })
})

const org: OrganizationSummary = {
  id: "r", name: "Example Holdings A", relationship: "ours", seed_domain: "fabrikam.com", engagement: null, claimed: 0, proposed: 0, leads: 0, rejected: 0,
}
const sd = (id: string, signal_type: string, tier: SignalDetail["tier"], matched: string[] | null): SignalDetail => ({
  id, signal_type, tier, family: "fam", anchor: { kind: "person", candidate_id: null, candidate_value: null, entity_id: null, entity_name: null, user_id: null },
  via_entity: { id: null, name: null }, quote: "the quote", evidence_id: null, matched_values: matched, first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-02T00:00:00Z",
})
const detail = (over: Partial<CandidateDetail> = {}): CandidateDetail => ({
  ...row(), signal_details: [sd("1", "mx_into_claimed", "supporting", ["mx.example.net"]), sd("2", "name_similarity", "context", null)],
  events: [], rejection_reason: null, decided_at: null, accepted_into: null, engagement_id: null, decided_by_id: null, decided_by_connector_name: null, ...over,
})
const flyout = (d: CandidateDetail) => html(
  <CandidateFlyoutContent detail={d} org={org} labelOf={labelOf} nodes={[]} onClaim={async () => undefined} onReject={async () => undefined} />,
)

describe("flyout", () => {
  beforeEach(() => { perms.current = [] })
  const asUser = (permissions: string[]) => { perms.current = permissions }

  it("puts Context under its own heading and shows matched values", () => {
    const out = flyout(detail())
    expect(out).toContain("Why we think it&#x27;s theirs")
    expect(out).toContain("Context (does not count)")
    expect(out.indexOf("Context (does not count)")).toBeLessThan(out.indexOf("Name similarity"))
    expect(out.indexOf("Why we think")).toBeLessThan(out.indexOf("MX into claimed"))
    expect(out).toContain("mx.example.net")
  })
  it("hides Claim/Reject without entities.decide_candidate and shows them with it", () => {
    expect(flyout(detail())).not.toContain(">Claim<")
    asUser(["entities.read"])
    expect(flyout(detail())).not.toContain(">Reject<")
    asUser(["entities.decide_candidate"])
    const out = flyout(detail())
    expect(out).toContain(">Claim<")
    expect(out).toContain(">Reject<")
  })
  it("offers no decision on a claimed row, and shows accepted_into + connector history", () => {
    asUser(["entities.decide_candidate"])
    const out = flyout(detail({
      status: "claimed", accepted_into: "our estate", decided_by_connector_name: "Zone account 1",
      events: [{ event: "claimed", at: "2026-01-02T00:00:00Z", user_id: null, reason: null, signal_id: null, connector_instance_id: "k" }],
    }))
    expect(out).not.toContain(">Reject<")
    expect(out).toContain("our estate")
    expect(out).toContain("by connector Zone account 1")
  })
})

describe("S3d additions", () => {
  beforeEach(() => { perms.current = [] })
  it("renders the extra node before History", () => {
    const out = html(
      <CandidateFlyoutContent detail={detail({ kind: "cidr", status: "claimed" })} org={org} labelOf={labelOf} nodes={[]}
        onClaim={async () => undefined} onReject={async () => undefined} extra={<div>EXTRA-BLOCK</div>} />,
    )
    expect(out).toContain("EXTRA-BLOCK")
    expect(out.indexOf("EXTRA-BLOCK")).toBeLessThan(out.indexOf(">History<"))
  })
  it("ClaimDialog shows the optional description after the decider line", () => {
    const d = (description?: string) => (
      <ClaimDialog value="AS64496" description={description} nodes={[]} defaultId={null} onClose={() => undefined} onSubmit={async () => undefined} />
    )
    const out = renderToStaticMarkup(d("Claiming this ASN also claims its holder."))
    expect(out).toContain("Claim AS64496")
    expect(out).toContain("The claim is recorded with you as the decider.")
    expect(out).toContain("Claiming this ASN also claims its holder.")
    expect(renderToStaticMarkup(d())).not.toContain("Claiming this ASN")
  })
})
