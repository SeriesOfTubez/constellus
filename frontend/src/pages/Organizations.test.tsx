import { afterEach, describe, expect, it, vi } from "vitest"
import { renderToStaticMarkup } from "react-dom/server"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"

// zustand's server snapshot ignores setState, so the permission hook is mocked (as in
// AddOrganizationFlow.test / OrgCandidateParts.test).
const perms = vi.hoisted(() => ({ current: [] as string[] }))
vi.mock("@/lib/permissions", () => ({
  useCan: () => (p: string) => perms.current.includes(p),
  usePermissionsSync: () => undefined,
}))

import Organizations from "@/pages/Organizations"
import type { CandidateRow, OrganizationSummary } from "@/lib/organizations"

afterEach(() => { perms.current = [] })

const ORG: OrganizationSummary = {
  id: "o1", name: "Example Holdings A", relationship: "ours", seed_domain: "example.test", engagement: null,
  claimed: 0, proposed: 1, leads: 0, rejected: 0,
}
const ROW = {
  id: "c1", root_entity_id: "o1", value: "candidate.example.test", kind: "domain", status: "open",
  strength: "strong", proposable: true, affiliated: { id: null, name: null }, affiliated_is_default: false,
  signals: [], first_seen_at: null, previously_rejected: null, target_id: null,
  decided_by_connector_instance_id: null, asset_count: null, open_findings: null, worst_severity: null,
  rir: null, rir_handle: null,
} as CandidateRow

function render(path: string) {
  const qc = new QueryClient()
  qc.setQueryData(["organizations"], [ORG])
  qc.setQueryData(["org-tree", "o1"], [])
  qc.setQueryData(["org-signal-types"], [])
  qc.setQueryData(["org-summary", "o1", null], {
    claimed: 0, to_review: 1, leads: 0, rejected: 0, assets_under_claimed_scope: 0,
    affiliates: 0, proposed_affiliates: 0, has_filer: false,
  })
  // org-candidates key: org, segment, q, strength, signal, subtreeOf
  for (const seg of ["candidates", "all", "claimed"]) {
    qc.setQueryData(["org-candidates", "o1", seg, "", "all", "all", null], {
      pages: [{ items: [ROW], total: 1 }], pageParams: [0],
    })
  }
  return renderToStaticMarkup(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes><Route path="/organizations/:orgId" element={<Organizations />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe("Organizations workspace permission gates", () => {
  it("renders the candidate row at all (precondition for the gates below)", () => {
    perms.current = ["entities.decide_candidate", "entities.propose_candidate"]
    expect(render("/organizations/o1")).toContain("candidate.example.test")
  })

  it("Add domain is offered only with entities.propose_candidate", () => {
    perms.current = ["entities.propose_candidate"]
    expect(render("/organizations/o1")).toContain("Add domain")
    perms.current = ["entities.read"]
    expect(render("/organizations/o1")).not.toContain("Add domain")
  })

  it("row checkboxes appear only with entities.decide_candidate, and only on candidates/all", () => {
    perms.current = ["entities.decide_candidate"]
    expect(render("/organizations/o1")).toContain('type="checkbox"')
    expect(render("/organizations/o1?seg=all")).toContain('type="checkbox"')
    expect(render("/organizations/o1?seg=claimed")).not.toContain('type="checkbox"')
    perms.current = ["entities.read"]
    expect(render("/organizations/o1")).not.toContain('type="checkbox"')
  })

  // NOTE: the flyout is a Radix Sheet (portal); with the detail query seeded,
  // renderToStaticMarkup still emits no sheet content, so the "Page capture" wiring
  // is not asserted here.
})
