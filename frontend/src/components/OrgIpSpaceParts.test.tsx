import { afterEach, describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { TooltipProvider } from "@/components/ui/tooltip"
import type { CandidateRow, ReassignmentRow } from "@/lib/organizations"
import { IpSpaceTable, RecheckButton, RegistryObservationList } from "@/components/OrgIpSpaceParts"

const perms = vi.hoisted(() => ({ current: [] as string[] }))
vi.mock("@/lib/permissions", () => ({ useCan: () => (p: string) => perms.current.includes(p) }))
afterEach(() => { perms.current = [] })

const html = (n: React.ReactNode) => renderToStaticMarkup(
  <QueryClientProvider client={new QueryClient()}><MemoryRouter><TooltipProvider>{n}</TooltipProvider></MemoryRouter></QueryClientProvider>,
)

const rr = (over: Partial<ReassignmentRow> = {}): ReassignmentRow => ({
  id: "r1", candidate_id: "c1", candidate_value: "192.0.2.0/24", rir: "arin", rir_handle: "EXAMPLE-ORG-1", prefix: "192.0.2.0/25",
  new_holder_kind: "org", new_holder_handle: "EXAMPLE-ORG-2", evidence_id: null,
  first_detected_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-02T00:00:00Z", ...over,
})
const row = (over: Partial<CandidateRow> = {}): CandidateRow => ({
  id: "c1", root_entity_id: "r", value: "192.0.2.0/24", kind: "cidr", status: "claimed", strength: "strong", proposable: true,
  affiliated: { id: "a", name: "Example Holdings A" }, affiliated_is_default: false, signals: [], first_seen_at: null,
  previously_rejected: null, target_id: null, decided_by_connector_instance_id: null, asset_count: 2,
  open_findings: null, worst_severity: null, rir: "arin", rir_handle: "EXAMPLE-ORG-1", ...over,
})
const labelOf = (t: string) => t

describe("RegistryObservationList", () => {
  const rows = [
    rr({ id: "1", new_holder_kind: "org", new_holder_handle: "EXAMPLE-ORG-2" }),
    rr({ id: "2", rir: "ripe", prefix: "198.51.100.0/25", new_holder_kind: "customer", new_holder_handle: "CUST-EX1" }),
    rr({ id: "3", prefix: "203.0.113.0/25", new_holder_kind: "unknown", new_holder_handle: null }),
    rr({ id: "4", prefix: "192.0.2.128/25", new_holder_kind: "unregistered", new_holder_handle: null }),
  ]
  it("shows heading, one line per kind, timing and footer", () => {
    const out = html(<RegistryObservationList rows={rows} />)
    expect(out).toContain("Registry observations")
    expect(out).toContain("ARIN now lists 192.0.2.0/25 under EXAMPLE-ORG-2 (organization)")
    expect(out).toContain("RIPE now lists 198.51.100.0/25 under CUST-EX1 (customer)")
    expect(out).toContain("ARIN now lists 203.0.113.0/25 under an unidentified holder")
    expect(out).toContain("ARIN shows 192.0.2.128/25 is no longer registered to anyone")
    expect(out).toContain("First seen")
    expect(out).toContain("Your claim and its target are unchanged. Review whether this space is still yours.")
  })
  it("empty state names no changes", () => {
    const out = html(<RegistryObservationList rows={[]} />)
    expect(out).toContain("Registry observations")
    expect(out).toContain("No registry changes recorded.")
    expect(out).not.toMatch(/destructive|red-|orange-|amber-|critical|severity/i)
  })
  it("is not a finding: no severity markup, and no action on a record", () => {
    const out = html(<RegistryObservationList rows={rows} />)
    expect(out).toContain("ARIN now lists 192.0.2.0/25 under EXAMPLE-ORG-2 (organization)") // reached the content
    expect(out).not.toMatch(/destructive|red-|orange-|amber-|critical|severity/i)
    expect(out).not.toContain("<button")
  })
})

describe("IpSpaceTable", () => {
  it("puts the Registry change badge only on the flagged cidr row", () => {
    const rows = [row({ id: "flag", value: "192.0.2.0/24" }), row({ id: "plain", value: "198.51.100.0/24" })]
    const out = html(<IpSpaceTable rows={rows} kind="cidr" flagged={new Set(["flag"])} onOpen={() => undefined} labelOf={labelOf} />)
    expect(out.match(/Registry change/g)?.length).toBe(1)
    const [, , flaggedRow, plainRow] = out.split("<tr") // [0] preamble, [1] header row
    expect(flaggedRow).toContain("192.0.2.0/24")
    expect(flaggedRow).toContain("Registry change")
    expect(plainRow).toContain("198.51.100.0/24")
    expect(plainRow).not.toContain("Registry change")
    expect(out).toContain("ARIN · EXAMPLE-ORG-1")
    expect(out).toContain(">Assets<")
    expect(out).toContain(">Prefix<")
  })
  it("asn table has no Assets column and no badge", () => {
    const out = html(<IpSpaceTable rows={[row({ id: "a", kind: "asn", value: "AS64496" })]} kind="asn" flagged={new Set(["a"])} onOpen={() => undefined} labelOf={labelOf} />)
    expect(out).toContain("AS64496")
    expect(out).toContain(">ASN<")
    expect(out).not.toContain(">Assets<")
    expect(out).not.toContain("Registry change")
  })
})

describe("RecheckButton", () => {
  it("renders with entities.decide_candidate and not without", () => {
    perms.current = ["entities.decide_candidate"]
    expect(html(<RecheckButton orgId="o1" />)).toContain("Re-check registries")
    perms.current = ["entities.read"]
    expect(html(<RecheckButton orgId="o1" />)).toBe("")
  })
})
