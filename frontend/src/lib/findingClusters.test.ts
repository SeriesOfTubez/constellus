import { describe, expect, it } from "vitest"
import type { Finding, FindingCluster } from "@/lib/api"
import { groupByCluster } from "@/lib/findingClusters"

function row(id: string, rolled?: string[]): Finding {
  return { id, rolled_up_ids: rolled, asset_value: "app.example.com", title: `t-${id}` } as unknown as Finding
}
function cluster(fp: string, members: string[], over: Partial<FindingCluster> = {}): FindingCluster {
  return {
    finding_type: "cve", source: "nuclei", fingerprint: fp, title: `CVE-2024-9${fp}`,
    max_severity: "high", finding_count: members.length, asset_count: 4, cve_id: null,
    first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-02T00:00:00Z",
    member_ids: members, ...over,
  }
}

describe("groupByCluster", () => {
  it("places a row in the cluster containing its id", () => {
    const g = groupByCluster([row("a"), row("b")], [cluster("1", ["a", "b"])])
    expect(g).toHaveLength(1)
    expect(g[0].items.map(r => r.id)).toEqual(["a", "b"])
    expect(g[0].key).toBe("cve|nuclei|1")
    expect(g[0].label).toBe("CVE-2024-91 · 4 assets")
  })

  it("lands a rolled-up row via a non-representative id", () => {
    const rep = row("rep", ["rep", "other"])
    const g = groupByCluster([rep], [cluster("1", ["other", "x"])])
    expect(g).toHaveLength(1)
    expect(g[0].cluster).not.toBeNull()
    expect(g[0].items).toEqual([rep])
  })

  it("lists a row in two clusters once, under the first", () => {
    const r = row("a", ["a", "b"])
    const g = groupByCluster([r], [cluster("1", ["a"]), cluster("2", ["b"])])
    expect(g).toHaveLength(1)
    expect(g[0].key).toBe("cve|nuclei|1")
  })

  it("omits clusters with no visible rows", () => {
    const g = groupByCluster([row("a")], [cluster("1", ["zzz"]), cluster("2", ["a"])])
    expect(g.map(x => x.key)).toEqual(["cve|nuclei|2"])
  })

  it("adds the remainder group only when there are leftovers", () => {
    const none = groupByCluster([row("a")], [cluster("1", ["a"])])
    expect(none.some(x => x.cluster === null)).toBe(false)
    const some = groupByCluster([row("a"), row("q")], [cluster("1", ["a"])])
    expect(some).toHaveLength(2)
    expect(some[1].cluster).toBeNull()
    expect(some[1].label).toBe("Other findings")
    expect(some[1].items.map(r => r.id)).toEqual(["q"])
  })

  it("falls back to the row id without rolled_up_ids", () => {
    const g = groupByCluster([row("a", undefined)], [cluster("1", ["a"])])
    expect(g[0].items[0].id).toBe("a")
  })

  it("lists every input row in exactly one group", () => {
    const rows = [row("a"), row("b", ["b", "c"]), row("d"), row("e", ["e", "a"]), row("f")]
    const g = groupByCluster(rows, [cluster("1", ["a", "c"]), cluster("2", ["a", "d"])])
    const ids = g.flatMap(x => x.items.map(r => r.id)).sort()
    expect(ids).toEqual(["a", "b", "d", "e", "f"])
  })
})
