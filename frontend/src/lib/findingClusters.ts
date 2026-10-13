import type { Finding, FindingCluster } from "@/lib/api"

export type ClusterGroup = {
  key: string
  label: string
  cluster: FindingCluster | null
  items: Finding[]
}

// Neutral on purpose: the cluster query has its own scope (state, verification
// exclusion, a group cap), so a row outside every cluster is not proof the issue
// appears on no other asset. Name the bucket, claim nothing about the world.
export const NOT_REPEATED_LABEL = "Other findings"

/**
 * Group visible finding rows by "same issue" clusters from the server.
 * A row joins the FIRST cluster (server order, most severe first) containing
 * any of its rolled_up_ids (falls back to [id]); it is listed exactly once.
 * Clusters with no visible rows are omitted; leftovers go to a final
 * `cluster: null` group.
 */
export function groupByCluster(rows: Finding[], clusters: FindingCluster[]): ClusterGroup[] {
  const memberToCluster = new Map<string, number>()
  clusters.forEach((c, idx) => {
    for (const id of c.member_ids) {
      if (!memberToCluster.has(id)) memberToCluster.set(id, idx)
    }
  })

  const buckets: Finding[][] = clusters.map(() => [])
  const rest: Finding[] = []
  for (const row of rows) {
    const ids = row.rolled_up_ids && row.rolled_up_ids.length > 0 ? row.rolled_up_ids : [row.id]
    let best = -1
    for (const id of ids) {
      const idx = memberToCluster.get(id)
      if (idx !== undefined && (best === -1 || idx < best)) best = idx
    }
    if (best === -1) rest.push(row)
    else buckets[best].push(row)
  }

  const out: ClusterGroup[] = []
  clusters.forEach((c, idx) => {
    if (buckets[idx].length === 0) return
    out.push({
      key: `${c.finding_type}|${c.source}|${c.fingerprint}`,
      label: `${c.title} · ${c.asset_count} assets`,
      cluster: c,
      items: buckets[idx],
    })
  })
  if (rest.length > 0) {
    out.push({ key: "__not_repeated", label: NOT_REPEATED_LABEL, cluster: null, items: rest })
  }
  return out
}
