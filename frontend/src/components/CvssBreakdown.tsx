/** Decodes a CVSS vector string into the labeled metric breakdown (à la NVD /
 *  VulnCheck). Full-detail-page only — too wide for the flyout. Supports CVSS
 *  v3.0/3.1 and v2 fully; unknown metrics (e.g. some v4 keys) fall back to the
 *  raw value so nothing is silently dropped. */

type MetricDef = { key: string; label: string; values: Record<string, string> }

const V3_METRICS: MetricDef[] = [
  { key: "AV", label: "Attack Vector",          values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
  { key: "AC", label: "Attack Complexity",      values: { L: "Low", H: "High" } },
  { key: "PR", label: "Privileges Required",    values: { N: "None", L: "Low", H: "High" } },
  { key: "UI", label: "User Interaction",       values: { N: "None", R: "Required" } },
  { key: "S",  label: "Scope",                  values: { U: "Unchanged", C: "Changed" } },
  { key: "C",  label: "Confidentiality Impact", values: { H: "High", L: "Low", N: "None" } },
  { key: "I",  label: "Integrity Impact",       values: { H: "High", L: "Low", N: "None" } },
  { key: "A",  label: "Availability Impact",    values: { H: "High", L: "Low", N: "None" } },
]

const V2_METRICS: MetricDef[] = [
  { key: "AV", label: "Access Vector",          values: { N: "Network", A: "Adjacent", L: "Local" } },
  { key: "AC", label: "Access Complexity",      values: { L: "Low", M: "Medium", H: "High" } },
  { key: "Au", label: "Authentication",         values: { N: "None", S: "Single", M: "Multiple" } },
  { key: "C",  label: "Confidentiality Impact", values: { N: "None", P: "Partial", C: "Complete" } },
  { key: "I",  label: "Integrity Impact",       values: { N: "None", P: "Partial", C: "Complete" } },
  { key: "A",  label: "Availability Impact",    values: { N: "None", P: "Partial", C: "Complete" } },
]

function parseVector(vector: string): { pairs: Record<string, string>; isV2: boolean } {
  const pairs: Record<string, string> = {}
  let isV2 = false
  for (const tok of vector.split("/")) {
    const [k, v] = tok.split(":")
    if (k === "CVSS") { isV2 = (v ?? "").startsWith("2"); continue }
    if (k && v) pairs[k] = v
  }
  // v2 strings have no "CVSS:" prefix; the "Au" metric is the tell-tale.
  if ("Au" in pairs) isV2 = true
  return { pairs, isV2 }
}

// Severity band from base score. v2 has no "Critical" tier.
function severityLabel(score: number, isV2: boolean): { label: string; cls: string } {
  if (!isV2 && score >= 9.0) return { label: "Critical", cls: "text-[var(--sev-critical)]" }
  if (score >= 7.0) return { label: "High",   cls: "text-[var(--sev-high)]" }
  if (score >= 4.0) return { label: "Medium", cls: "text-[var(--sev-medium)]" }
  if (score >= 0.1) return { label: "Low",    cls: "text-[var(--sev-low)]" }
  return { label: "None", cls: "text-muted-foreground" }
}

function Row({ label, value, mono, valueCls }: { label: string; value: string; mono?: boolean; valueCls?: string }) {
  return (
    <div className="flex items-baseline gap-3 px-3 py-1.5">
      <span className="text-xs text-muted-foreground w-44 shrink-0">{label}</span>
      <span className={`text-sm ${mono ? "font-mono break-all" : ""} ${valueCls ?? ""}`}>{value}</span>
    </div>
  )
}

export function CvssBreakdown({
  vector, version, score,
}: { vector: string | null; version: string | null; score: number | null }) {
  if (!vector) return null
  const { pairs, isV2 } = parseVector(vector)
  const metrics = isV2 ? V2_METRICS : V3_METRICS
  const sev = score != null ? severityLabel(score, isV2) : null

  // Any parsed keys we don't have a label for (e.g. v4 extras) — show raw, not dropped.
  const known = new Set(metrics.map(m => m.key))
  const extras = Object.entries(pairs).filter(([k]) => !known.has(k))

  return (
    <div className="rounded-md border divide-y">
      <Row label="Version" value={version ?? (isV2 ? "2.0" : "3.x")} />
      <Row label="Vector String" value={vector} mono />
      {metrics.map(m => {
        const raw = pairs[m.key]
        if (!raw) return null
        return <Row key={m.key} label={m.label} value={m.values[raw] ?? raw} />
      })}
      {extras.map(([k, v]) => <Row key={k} label={k} value={v} mono />)}
      {score != null && <Row label="Base Score" value={score.toFixed(1)} valueCls="font-semibold tabular-nums" />}
      {sev && <Row label="Base Severity" value={sev.label} valueCls={`font-semibold ${sev.cls}`} />}
    </div>
  )
}
