import { useState } from "react"
import { ChevronDown, ChevronRight, ExternalLink, ShieldAlert, ArrowDownCircle, SlidersHorizontal } from "lucide-react"
import { type Finding } from "@/lib/api"
import { exposureOverride } from "@/components/finding-badges"

/** Narrative captured from VulnCheck KEV + NVD2 during enrichment, stashed in
 *  finding.detail.cve_intel. Structured (not one growing text blob) so future
 *  additions — e.g. LLM summary / remediation steps — are just new keys here.
 *
 *  Split into two surfaces: the STORY (name / description / recommended action)
 *  lives on Overview; the EVIDENCE (exploit + reference links) lives on the Intel
 *  tab, where it has room to be a full, clickable list. */
export type CveIntel = {
  name?: string
  description?: string
  required_action?: string      // CISA KEV directive (KEV-listed CVEs only)
  remediation?: string          // vulnx — technical remediation; fills the non-KEV gap
  impact?: string               // vulnx — plain-language impact
  is_remote?: boolean           // vulnx — remotely exploitable
  is_auth?: boolean             // vulnx — authentication required
  exploits?: { url: string; type?: string; date?: string }[]
  reported_exploitation?: { url: string; date?: string }[]
  references?: { url: string; tags?: string[] }[]
}

export function getCveIntel(f: Finding): CveIntel | null {
  const intel = (f.detail as Record<string, unknown> | null)?.cve_intel
  return intel && typeof intel === "object" ? (intel as CveIntel) : null
}

function hostOf(url: string): string {
  try { return new URL(url).hostname.replace(/^www\./, "") } catch { return url }
}

/** References merged from cve_intel (NVD, with tags) + scanner-provided
 *  detail.references (Nuclei, plain URLs), deduped by URL. Keeps all tags. */
function allReferences(f: Finding): { url: string; tags: string[] }[] {
  const out: { url: string; tags: string[] }[] = []
  const seen = new Set<string>()
  for (const r of getCveIntel(f)?.references ?? []) {
    if (r.url && !seen.has(r.url)) { seen.add(r.url); out.push({ url: r.url, tags: r.tags ?? [] }) }
  }
  const scanner = (f.detail as Record<string, unknown> | null)?.references
  if (Array.isArray(scanner)) {
    for (const u of scanner) {
      if (typeof u === "string" && !seen.has(u)) { seen.add(u); out.push({ url: u, tags: [] }) }
    }
  }
  return out
}

/** True when there's anything to show on the Intel tab (drives tab visibility). */
export function hasVulnIntel(f: Finding): boolean {
  const intel = getCveIntel(f)
  return !!(intel?.exploits?.length || intel?.reported_exploitation?.length || allReferences(f).length)
}

function LinkRow({ url, label, date, tags }: { url: string; label: string; date?: string; tags?: string[] }) {
  return (
    <div className="flex items-center gap-1.5 text-xs">
      <a href={url} target="_blank" rel="noopener noreferrer"
        className="flex items-center gap-1.5 text-blue-500 hover:underline min-w-0">
        <ExternalLink className="h-3 w-3 shrink-0" />
        <span className="truncate">{label}</span>
      </a>
      {tags?.slice(0, 2).map(t => (
        <span key={t} className="shrink-0 rounded bg-muted px-1 py-0 text-[10px] text-muted-foreground">{t}</span>
      ))}
      {date && <span className="text-muted-foreground shrink-0 ml-auto">{date}</span>}
    </div>
  )
}

// ── Story (Overview) ─────────────────────────────────────────────────────────

/** Collapsible "About this vulnerability" box: name → description → recommended
 *  action. Renders nothing when there's no narrative (e.g. bare exposure findings). */
export function VulnNarrative({ finding, defaultOpen = true }: { finding: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  const intel = getCveIntel(finding)
  const description = intel?.description ?? finding.description ?? null
  const override = exposureOverride(finding)
  // Remediation: vulnx (CVEs) or the exposure rule's curated text (detail.remediation).
  const ruleRemediation = typeof (finding.detail as Record<string, unknown> | null)?.remediation === "string"
    ? (finding.detail as Record<string, unknown>).remediation as string
    : null
  const remediation = intel?.remediation ?? ruleRemediation
  if (!intel?.name && !description && !intel?.required_action && !remediation && !intel?.impact && !override) return null

  const sevLabel = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)

  return (
    <div className="rounded-md border">
      <button onClick={() => setOpen(o => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/40 transition-colors">
        {open ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">About this vulnerability</span>
        {finding.cve_id && <span className="ml-auto font-mono text-xs text-muted-foreground">{finding.cve_id}</span>}
      </button>

      {open && (
        <div className="border-t px-3 py-3 space-y-3">
          {override && (
            <div className={`rounded border-l-2 px-3 py-2 ${
              override.kind === "tag" ? "border-l-amber-500 bg-amber-500/5" : "border-l-sky-500 bg-sky-500/5"
            }`}>
              <p className={`text-[10px] font-semibold uppercase tracking-wider flex items-center gap-1 ${
                override.kind === "tag" ? "text-amber-700 dark:text-amber-400" : "text-sky-700 dark:text-sky-400"
              }`}>
                {override.kind === "tag"
                  ? <><ArrowDownCircle className="h-3 w-3" />Downgraded to {sevLabel} by tag</>
                  : <><SlidersHorizontal className="h-3 w-3" />Severity adjusted to {sevLabel}</>}
              </p>
              <p className="text-sm mt-1 text-muted-foreground leading-relaxed">
                {override.kind === "tag" ? (
                  <>
                    This asset is tagged{" "}
                    <code className="font-mono text-xs bg-muted px-1 py-0.5 rounded">{override.tag}</code>
                    , so the default severity was lowered. {override.label}
                  </>
                ) : override.kind === "banner" ? (
                  <>Severity was set from the detected service banner. {override.label}</>
                ) : (
                  <>{override.label}</>
                )}
              </p>
            </div>
          )}
          {intel?.name && <p className="text-sm font-semibold leading-snug">{intel.name}</p>}

          {(intel?.is_remote || intel?.is_auth !== undefined) && (
            <div className="flex items-center gap-1.5 flex-wrap">
              {intel?.is_remote && (
                <span className="inline-flex items-center rounded border border-orange-500/40 bg-orange-500/10 px-1.5 py-0.5 text-[10px] font-medium text-orange-600 dark:text-orange-400">Remotely exploitable</span>
              )}
              {intel?.is_auth === false && (
                <span className="inline-flex items-center rounded border border-orange-500/40 bg-orange-500/10 px-1.5 py-0.5 text-[10px] font-medium text-orange-600 dark:text-orange-400">No auth required</span>
              )}
              {intel?.is_auth === true && (
                <span className="inline-flex items-center rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">Auth required</span>
              )}
            </div>
          )}

          {description && (
            <p className="text-sm text-muted-foreground leading-relaxed whitespace-pre-wrap">{description}</p>
          )}

          {intel?.impact && (
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Impact</p>
              <p className="text-sm mt-0.5 text-muted-foreground leading-relaxed">{intel.impact}</p>
            </div>
          )}

          {(intel?.required_action || remediation) && (
            <div className="rounded bg-muted/50 px-3 py-2 space-y-2">
              {intel?.required_action && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1">
                    <ShieldAlert className="h-3 w-3" />CISA required action
                  </p>
                  <p className="text-sm mt-0.5">{intel.required_action}</p>
                </div>
              )}
              {remediation && (
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Recommended remediation</p>
                  <p className="text-sm mt-0.5">{remediation}</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Evidence (Intel tab) ──────────────────────────────────────────────────────

type IntelItem = { url: string; label: string; date?: string; tags?: string[] }

function FilterChip({ active, label, count, onClick }: { active: boolean; label: string; count: number; onClick: () => void }) {
  return (
    <button onClick={onClick}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium transition-colors ${
        active ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"
      }`}>
      {label}<span className="tabular-nums opacity-70">{count}</span>
    </button>
  )
}

/** One intel category as a self-contained panel: header + (optional) tag filter
 *  chips + paginated link list. Keyed by finding id upstream so state resets when
 *  the finding changes. */
function IntelLinkPanel({ title, subtitle, items, tagFilter = false, pageSize = 8 }: {
  title: string; subtitle?: string; items: IntelItem[]; tagFilter?: boolean; pageSize?: number
}) {
  const [tag, setTag] = useState<string | null>(null)
  const [page, setPage] = useState(0)
  if (items.length === 0) return null

  const tagCounts: [string, number][] = []
  if (tagFilter) {
    const m = new Map<string, number>()
    for (const it of items) for (const t of it.tags ?? []) m.set(t, (m.get(t) ?? 0) + 1)
    tagCounts.push(...[...m.entries()].sort((a, b) => b[1] - a[1]))
  }

  const filtered = tag ? items.filter(it => it.tags?.includes(tag)) : items
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize))
  const safePage = Math.min(page, pageCount - 1)
  const slice = filtered.slice(safePage * pageSize, safePage * pageSize + pageSize)

  return (
    <div className="rounded-lg border bg-card">
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b">
        <div>
          <p className="text-sm font-medium">{title}</p>
          {subtitle && <p className="text-xs text-muted-foreground mt-0.5">{subtitle}</p>}
        </div>
        <span className="text-xs text-muted-foreground tabular-nums shrink-0">
          {tag ? `${filtered.length} of ${items.length}` : items.length}
        </span>
      </div>

      {tagFilter && tagCounts.length > 0 && (
        <div className="flex flex-wrap gap-1.5 px-4 py-2.5 border-b">
          <FilterChip active={tag === null} label="All" count={items.length} onClick={() => { setTag(null); setPage(0) }} />
          {tagCounts.map(([t, c]) => (
            <FilterChip key={t} active={tag === t} label={t} count={c} onClick={() => { setTag(t); setPage(0) }} />
          ))}
        </div>
      )}

      <div className="px-4 py-2.5 space-y-1.5">
        {slice.map((it, i) => <LinkRow key={i} url={it.url} label={it.label} date={it.date} tags={it.tags} />)}
      </div>

      {pageCount > 1 && (
        <div className="flex items-center justify-between px-4 py-2 border-t text-xs text-muted-foreground">
          <span>Page {safePage + 1} of {pageCount}</span>
          <div className="flex items-center gap-1">
            <button disabled={safePage === 0} onClick={() => setPage(safePage - 1)}
              className="rounded border px-2 py-0.5 disabled:opacity-40 hover:text-foreground transition-colors">Prev</button>
            <button disabled={safePage >= pageCount - 1} onClick={() => setPage(safePage + 1)}
              className="rounded border px-2 py-0.5 disabled:opacity-40 hover:text-foreground transition-colors">Next</button>
          </div>
        </div>
      )}
    </div>
  )
}

/** Evidence panels — public exploits, reported exploitation, references. Each is
 *  its own panel; references add tag-filter chips + pagination so the full set
 *  (NVD can return hundreds) stays usable. Reused on the flyout + full detail. */
// Newest-first; YYYY-MM-DD sorts lexically, undated entries sink to the bottom.
const byDateDesc = (a: IntelItem, b: IntelItem) => (b.date ?? "").localeCompare(a.date ?? "")

export function VulnIntel({ finding }: { finding: Finding }) {
  const intel = getCveIntel(finding)
  const exploits: IntelItem[] = (intel?.exploits ?? []).map(e => ({
    url: e.url, label: `${(e.type ?? "exploit").replace(/-/g, " ")} · ${hostOf(e.url)}`, date: e.date,
  })).sort(byDateDesc)
  const reported: IntelItem[] = (intel?.reported_exploitation ?? []).map(r => ({
    url: r.url, label: hostOf(r.url), date: r.date,
  })).sort(byDateDesc)
  const references: IntelItem[] = allReferences(finding).map(r => ({
    url: r.url, label: hostOf(r.url), tags: r.tags,
  }))

  if (!exploits.length && !reported.length && !references.length) {
    return <p className="text-sm text-muted-foreground">No exploit or reference intelligence available for this finding.</p>
  }

  return (
    <div className="space-y-4">
      <IntelLinkPanel key={`${finding.id}-exploits`} title="Public exploits" items={exploits} />
      <IntelLinkPanel
        key={`${finding.id}-reported`}
        title="Reported exploited in the wild"
        subtitle="Third-party sources VulnCheck has linked to this CVE — specificity varies from honeypot telemetry to general coverage. Date is when VulnCheck catalogued the source, not necessarily when exploitation occurred."
        items={reported}
      />
      <IntelLinkPanel key={`${finding.id}-refs`} title="References" items={references} tagFilter pageSize={10} />
    </div>
  )
}
