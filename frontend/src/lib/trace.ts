// Words and shapes for the Trace chains (planning#362). Pure functions only:
// every piece of text the attribution and exposure-path views print is here so
// the rules are unit-tested without a DOM. API `reason` strings are never
// rewritten here; components render them as written.
import type {
  AssetSurface, AttributionChain, AttributionEvidence, AttributionHop,
  ExposureHop, ExposureHopCandidate, ExposureHopStatus, ExposurePath, Finding,
} from "@/lib/api"
import { formatClosed } from "@/lib/organizations"

export const STATUS_LABEL: Record<ExposureHopStatus, string> = {
  observed: "Observed",
  derived: "Derived",
  unknown: "Not on record",
  not_applicable: "Does not apply",
}

export const STATUS_LEGEND: { status: ExposureHopStatus; label: string; meaning: string }[] = [
  { status: "observed", label: STATUS_LABEL.observed, meaning: "A source recorded it." },
  { status: "derived", label: STATUS_LABEL.derived, meaning: "Worked out from other records. Listed, never picked." },
  { status: "unknown", label: STATUS_LABEL.unknown, meaning: "Nothing on file. The reason is shown." },
]

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

export function traceDate(iso: string | null | undefined): string | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  return `${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`
}

export function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`
}

export function humanise(code: string): string {
  return code.replace(/_/g, " ")
}

// ---- Verdict band ----

export type VerdictVariant =
  | "nuclei_check" | "nuclei_default_login"
  | "exposed_service_identified" | "exposed_service_unidentified"
  | "dangling_fingerprint" | "dangling_not_affine" | "dangling_unreachable" | "dangling_serves_others"
  | "version_match_cve" | "shodan_cve" | "shodan_cve_verified" | "shodan_label" | "other"

export type Verdict = { label: string; saw: string; didNot: string }

export const VERDICT_HEADINGS = { saw: "What we saw", didNot: "What we did not do" }

// Text is fixed per variant and settled on planning#362 (comment 6904233411). No values are
// interpolated, and a label never says "confirmed".
export const VERDICTS: Record<VerdictVariant, Verdict> = {
  nuclei_check: {
    label: "Check matched",
    saw: "A scanner check sent a request to this host, and the response matched the pattern for this issue.",
    didNot: "We did not go further than that one check. No attempt was made to use the issue.",
  },
  nuclei_default_login: {
    label: "Default login accepted",
    saw: "A scanner check tried a known default username and password on this host, and the login was accepted.",
    didNot: "We did nothing after the login. Nothing was read or changed. We kept the check's result, nothing else from the session.",
  },
  exposed_service_identified: {
    label: "Seen open",
    saw: "A port scan found this port open, and the service answering on it was identified.",
    didNot: "We did not try to log in, send commands or test the service for weaknesses. An open service is an exposure, not a break-in.",
  },
  exposed_service_unidentified: {
    label: "Seen open, service not identified",
    saw: "A port scan found this port open. What answers on it was not identified; the finding goes by the port's usual service.",
    didNot: "We did not confirm what is answering, try to log in or test it for weaknesses.",
  },
  dangling_fingerprint: {
    label: "Check matched",
    saw: "This DNS name points to a third-party service, and that service replied that nothing is set up there.",
    didNot: "We did not try to claim the resource. Whether someone else can claim it was not tested.",
  },
  dangling_not_affine: {
    label: "No sign of this name",
    saw: "This name points at a shared hosting address. The address answered, but showed no sign of serving this name.",
    didNot: "We did not try to take over the address or the name. Finding no sign is not proof the name is abandoned.",
  },
  dangling_unreachable: {
    label: "No answer",
    saw: "This name points at an address that did not answer on any port we tried.",
    didNot: "We did not find out why. The address may be retired, or something in front of it may still serve the name.",
  },
  dangling_serves_others: {
    label: "Serves another name",
    saw: "This name points at an address that did not answer for this name but does serve a different one.",
    didNot: "We did not try to claim the address or serve anything under this name.",
  },
  version_match_cve: {
    label: "Inferred from a version",
    saw: "Software on this host reported a version number, and that version is in the range this CVE affects.",
    didNot: "We did not test for the weakness itself. A vendor can patch it without changing the version number, so this can overstate.",
  },
  shodan_cve: {
    label: "Reported by Shodan",
    saw: "Shodan listed this CVE for this address, from the software version it recorded there.",
    didNot: "We did not contact the host to check it, and neither we nor Shodan tested for the weakness itself. A version match can overstate.",
  },
  shodan_cve_verified: {
    label: "Tested by Shodan",
    saw: "Shodan reports that it tested this address for this CVE and the test came back positive.",
    didNot: "We did not contact the host or repeat the test. Shodan's report is all we have.",
  },
  shodan_label: {
    label: "Reported by Shodan",
    saw: "Shodan labelled this address as compromised, hosting malware or a honeypot.",
    didNot: "We did not check the label ourselves. The record does not say what Shodan saw.",
  },
  other: {
    label: "Reported by a source",
    saw: "The source named on this finding reported it.",
    didNot: "No description of what that source checks is on file, so we cannot say what was and was not done.",
  },
}

type VerdictInput = Pick<Finding, "source" | "finding_type" | "detail">

function hasDefaultLoginTag(tags: unknown): boolean {
  const list = Array.isArray(tags) ? tags : typeof tags === "string" ? tags.split(",") : []
  return list.some((t) => typeof t === "string" && t.trim() === "default-login")
}

// Never throws; anything unmatched is "other". Fails toward the weaker claim.
export function verdictVariant(f: VerdictInput): VerdictVariant {
  const d = f.detail && typeof f.detail === "object" ? f.detail : {}
  if (f.source === "nuclei") return hasDefaultLoginTag(d.tags) ? "nuclei_default_login" : "nuclei_check"
  if (f.source === "constellus" && f.finding_type === "exposed_service") {
    return d.confidence === "confirmed" ? "exposed_service_identified" : "exposed_service_unidentified"
  }
  if (f.source === "constellus" && f.finding_type === "dangling_dns") {
    switch (d.layer) {
      case "fingerprint": return "dangling_fingerprint"
      case "affinity_not_affine": return "dangling_not_affine"
      case "affinity_unreachable": return "dangling_unreachable"
      case "affinity_corroborated_alive": return "dangling_serves_others"
      default: return "other"
    }
  }
  if (f.source === "version_match" && f.finding_type === "cve") return "version_match_cve"
  if (f.source === "shodan") {
    if (f.finding_type === "cve") return d.shodan_verified === true ? "shodan_cve_verified" : "shodan_cve"
    if (f.finding_type === "malware" || f.finding_type === "honeypot") return "shodan_label"
  }
  return "other"
}

export function verdictFor(f: VerdictInput): Verdict {
  return VERDICTS[verdictVariant(f)]
}

// ---- Question 1: attribution ----

export type OwnershipAnswer = { headline: string; note: string | null }

const NOT_AN_ANSWER = "The records below show how it came into scope. They do not make it yours."

// Answered from the surface alone; never from chains or hops.
export function ownershipAnswer(surface: AssetSurface): OwnershipAnswer {
  switch (surface) {
    case "proven_ours":
      return { headline: "Yes. The record proves this is yours.", note: null }
    case "claimed_ours":
      return { headline: "Claimed as yours, not proven.", note: null }
    case "not_ours":
      return { headline: "No. The record says this is not yours.", note: NOT_AN_ANSWER }
    case "unknown":
      return { headline: "Not checked.", note: NOT_AN_ANSWER }
  }
}

export function chainsNote(count: number, truncated: boolean): string | null {
  if (count > 1) {
    return `${count} chains on record. None is the main one.${truncated ? " More exist than are shown." : ""}`
  }
  return truncated ? "More chains exist than are shown." : null
}

export type HopTitle = {
  text: string
  mono: boolean
  href: string | null
  missing: boolean
}

const present = (text: string, mono: boolean, href: string | null = null): HopTitle => ({ text, mono, href, missing: false })
const absent = (text: string): HopTitle => ({ text, mono: false, href: null, missing: true })

export function candidatesTitle(hop: {
  kind: "host" | "address"
  candidates: ExposureHopCandidate[]
  candidates_truncated: boolean
}): string {
  const n = hop.candidates.length
  if (hop.kind === "host") {
    if (n === 0) return "No hostname on record"
    if (hop.candidates_truncated) return `More than ${n} hostnames point here`
    return n === 1 ? "1 hostname points here" : `${n} hostnames point here`
  }
  if (n === 0) return "No address on record"
  if (hop.candidates_truncated) return `Points at more than ${n} addresses`
  return n === 1 ? "Points at 1 address" : `Points at ${n} addresses`
}

export function attributionHopTitle(hop: AttributionHop): HopTitle {
  switch (hop.kind) {
    case "organization":
      if (hop.name) return present(hop.name, false, hop.entity_id ? `/organizations/entity/${hop.entity_id}` : null)
      return absent("No organization on record")
    case "entity":
      return present(hop.name, false, `/organizations/entity/${hop.entity_id}`)
    case "scope":
      if (hop.value) return present(hop.value, true, hop.target_id ? `/targets/${hop.target_id}` : null)
      return absent("No target on record")
    case "host":
      if (hop.status === "derived") return present(candidatesTitle(hop), false)
      if (hop.hostname) return present(hop.hostname, true, hop.asset_id ? `/assets/${hop.asset_id}` : null)
      return absent("No hostname on record")
    case "address":
      if (hop.address) return present(hop.address, true, hop.asset_id ? `/assets/${hop.asset_id}` : null)
      return absent("No address on record")
  }
}

export function attributionHopCaption(hop: AttributionHop): string | null {
  if (hop.kind === "organization") {
    if (hop.relationship === "ma_target") return "acquisition target"
    if (hop.relationship === "ours") {
      const date = traceDate(hop.marked_at)
      if (!date) return "your organization"
      if (hop.marked_by_id === null) return `your organization, marked on ${date}`
      return `your organization, marked by ${hop.marked_by_name ?? "a person"} on ${date}`
    }
    return null
  }
  if (hop.kind === "scope") {
    const date = traceDate(hop.claimed_at)
    if (!date) return null
    if (hop.claimed_by_id === null) return `claimed on ${date}`
    return `claimed by ${hop.claimed_by_name ?? "a person"} on ${date}`
  }
  return null
}

const CLAIM_LABEL: Record<string, string> = {
  observation: "Sighting",
  ct_cert_issuance: "Certificate issued",
  cloud_inventory: "Cloud inventory",
  affinity_confirmation: "Ownership check",
  tenancy: "Tenancy",
}

export function evidenceTitle(e: AttributionEvidence): string {
  switch (e.kind) {
    case "relation":
      return e.relation === "acquired" ? "Acquired" : "Subsidiary of"
    case "signal":
      return e.label ?? humanise(e.signal_type)
    case "claim":
      return CLAIM_LABEL[e.claim_type] ?? humanise(e.claim_type)
  }
}

export function attributionLinkText(hop: AttributionHop): string | null {
  if (hop.kind === "organization") return null
  if (hop.kind === "entity") {
    if (hop.relation === null) return null
    let text = hop.relation === "acquired" ? "acquired by the entity above" : "a subsidiary of the entity above"
    if (hop.evidence.length === 1) {
      const e = hop.evidence[0]
      if (e.kind === "relation" && e.event_date && e.event_date_precision !== "unknown") {
        text += `, dated ${formatClosed(e.event_date, e.event_date_precision)}`
      }
    }
    return text
  }
  const n = hop.evidence.length
  if (n === 0) return null
  if (hop.kind === "scope") {
    return n === 1 ? evidenceTitle(hop.evidence[0]) : `linked by ${n} signals`
  }
  const sources = new Set<string>()
  for (const e of hop.evidence) if (e.source) sources.add(e.source)
  if (sources.size === 0) return `${plural(n, "record", "records")} on file`
  return `recorded by ${plural(sources.size, "source", "sources")}`
}

function seenParts(first: string | null, last: string | null): string[] {
  const a = traceDate(first)
  const b = traceDate(last)
  const out: string[] = []
  if (a) out.push(`first seen ${a}`)
  if (b && b !== a) out.push(`last seen ${b}`)
  return out
}

export function evidenceMeta(e: AttributionEvidence): string[] {
  const out: string[] = []
  switch (e.kind) {
    case "relation": {
      if (e.source) out.push(e.source)
      if (e.event_date && e.event_date_precision !== "unknown") {
        out.push(`dated ${formatClosed(e.event_date, e.event_date_precision)}`)
      }
      if (e.confirmed_by) {
        const on = traceDate(e.confirmed_at)
        out.push(`${e.confirmed_by === "person" ? "confirmed by a person" : "confirmed by the source"}${on ? ` on ${on}` : ""}`)
      }
      return out
    }
    case "signal":
      if (e.source) out.push(e.source)
      return [...out, ...seenParts(e.first_seen_at, e.last_seen_at)]
    case "claim":
      if (e.outcome) out.push(`outcome: ${humanise(e.outcome)}`)
      if (e.source) out.push(`${e.source}${e.source_trust ? ` (${e.source_trust})` : ""}`)
      return [...out, ...seenParts(e.first_seen_at, e.last_seen_at)]
  }
}

export function evidenceDocumentId(e: AttributionEvidence): string | null {
  if (e.kind === "relation") return e.evidence_id
  if (e.kind === "signal") return e.evidence_id
  return null
}

export function candidateMeta(c: ExposureHopCandidate): string[] {
  const out: string[] = []
  if (c.record_type) out.push(c.record_type)
  if (c.distance === 1) out.push("its own address record")
  else if (c.distance >= 2) out.push(`through ${plural(c.distance - 1, "CNAME record", "CNAME records")}`)
  const last = traceDate(c.link_last_seen_at)
  if (last) out.push(`last seen ${last}`)
  return out
}

// ---- Question 2: exposure path ----

export function pathsAnswer(paths: ExposurePath[]): string {
  if (paths.length === 0) return "No place is recorded for this finding."
  if (paths.every((p) => p.observation === "not_recorded")) return "The source recorded no place for this finding."
  const c = paths.filter((p) => p.observation === "current").length
  const r = paths.filter((p) => p.observation === "not_reobserved").length
  let text = c > 0
    ? `Observed at ${plural(c, "place", "places")} in the latest observation.`
    : "Not observed at any place in the latest observation."
  if (r > 0) text += ` ${plural(r, "earlier place was", "earlier places were")} not seen again.`
  return text
}

export function observationLabel(path: ExposurePath): string {
  switch (path.observation) {
    case "current":
      return "Seen in the latest observation"
    case "not_reobserved": {
      const d = traceDate(path.last_seen_at)
      return d ? `Not seen again since ${d}` : "Not seen again"
    }
    case "not_recorded":
      return "No place recorded"
  }
}

export function exposureHopTitle(hop: ExposureHop, findingTitle: string | null): HopTitle {
  if (hop.status === "not_applicable") return absent("Does not apply")
  switch (hop.kind) {
    case "internet":
      return present("Internet", false)
    case "host":
      if (hop.status === "derived") return present(candidatesTitle(hop), false)
      if (hop.hostname) return present(hop.hostname, true, hop.asset_id ? `/assets/${hop.asset_id}` : null)
      return absent("No hostname on record")
    case "address":
      if (hop.status === "derived") return present(candidatesTitle(hop), false)
      if (hop.address) return present(hop.address, true, hop.asset_id ? `/assets/${hop.asset_id}` : null)
      return absent("No address on record")
    case "port":
      if (hop.port === null) return { text: "No port on record", mono: true, href: null, missing: true }
      return present(hop.protocol ? `${hop.port}/${hop.protocol}` : `${hop.port}`, true)
    case "service":
      if (!hop.service) return absent("No service on record")
      return present(hop.version ? `${hop.service} ${hop.version}` : hop.service, false)
    case "finding":
      return present(findingTitle ?? humanise(hop.finding_type), false)
  }
}

export function exposureHopCaption(hop: ExposureHop): string | null {
  if (hop.kind === "service" && hop.protocol) return `the port inventory lists ${hop.protocol}`
  return null
}

export function sourcesText(sources: string[]): string | null {
  return sources.length === 0 ? null : `Recorded by ${sources.join(", ")}`
}

export function seenText(first: string | null, last: string | null): string | null {
  const a = traceDate(first)
  const b = traceDate(last)
  if (a && b) return a === b ? `seen ${a}` : `first seen ${a}, last seen ${b}`
  if (a) return `first seen ${a}`
  if (b) return `last seen ${b}`
  return null
}

export type Segment = { text: string; mono: boolean; missing: boolean }

export function attributionSummary(chain: AttributionChain): Segment[] {
  return chain.hops.map((hop) => {
    const t = attributionHopTitle(hop)
    return { text: t.text, mono: t.mono, missing: t.missing }
  })
}

export function exposureSummary(path: ExposurePath, findingTitle: string | null): Segment[] {
  const out: Segment[] = []
  for (const hop of path.hops) {
    if (hop.status === "not_applicable") continue
    const t = exposureHopTitle(hop, findingTitle)
    const text = hop.kind === "port" && !t.missing ? `:${t.text}` : t.text
    out.push({ text, mono: t.mono, missing: t.missing })
  }
  return out
}
