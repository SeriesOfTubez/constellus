import { Radio } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { relativeTime } from "@/lib/time"

// Per-port "sources" values are connector registry IDs (asset_writer's union
// of banner_grab.py / naabu.py / httpx_probe.py / tlsx.py / shodan.py
// `sources: [...]` entries) — human-readable labels for the signals hover card.
export const SOURCE_LABELS: Record<string, string> = {
  naabu: "Naabu — port scan",
  nmap: "Nmap — service verification",
  banner_grab: "Banner Grab — zgrab2 service identification",
  httpx: "HTTPX — HTTP probe",
  tlsx: "TLSX — TLS certificate scan",
  shodan: "Shodan — internet exposure data",
}

// Sources that mean our own active stack confirmed the port. A port whose
// only source is Shodan is intel we haven't reproduced — flagged "unverified".
const ACTIVE_PROBE_SOURCES = ["naabu", "nmap", "banner_grab", "httpx", "tlsx"]

/**
 * Unified open-ports panel.
 *
 * Reads `ip.asset_metadata.open_ports[]` (canonical, written by naabu and
 * merged per-port by `asset_writer._merge_open_ports`) and folds in any
 * legacy `shodan_ports[]` numbers that haven't been recorded as
 * structured entries yet. Same merge model: union sources, newest
 * last_seen wins.
 *
 * Each row shows: port/protocol, well-known service name (if known),
 * source chips, last-seen relative time. Designed to scale — when
 * tlsx/httpx/banner-grab start contributing they just add their source
 * chip and (eventually) extra columns for service/version/tech.
 */

export type OpenPortEntry = {
  port: number
  protocol?: string
  sources?: string[]
  last_seen_at?: string
  // Forward-compatible — future enrichers contribute these fields and
  // the panel surfaces them automatically once present.
  service?: string
  service_version?: string
  banner_snippet?: string
  // CPE list + Shodan module name, captured from Shodan's per-port data[].
  cpe?: string[]
  shodan_module?: string
  // Application-layer verification: true = a prober (nmap -sV / banner_grab /
  // httpx / tlsx) got a real service; false = handshake only (firewall phantom /
  // tcpwrapped); undefined = legacy/Shodan-only (see PortRow `unverified`).
  l7_confirmed?: boolean
  tech_stack?: string[]
  http_title?: string
  favicon_hash?: string
  jarm?: string
  cert_summary?: CertSummary
}

export type CertSummary = {
  subject_cn?: string
  sans?: string[]
  issuer_cn?: string
  issuer_org?: string
  not_before?: string
  not_after?: string
  cipher?: string
  tls_version?: string
  // sha256 fingerprint (cross-asset cert-reuse key), serial, JA3 hashes, ALPN — #56.
  fingerprint?: string
  serial?: string
  ja3?: string
  ja3s?: string
  alpn?: string[]
}

/** Expiry state for a cert's not_after, with the shared 30-day warning window.
 *  Used by the inline port row and the dedicated TLS panel so they can't drift. */
export function certExpiryState(notAfter?: string): {
  date: Date | null; daysToExpiry: number | null; expired: boolean; expiringSoon: boolean
} {
  const date = notAfter ? new Date(notAfter) : null
  const valid = date && !Number.isNaN(date.getTime())
  const daysToExpiry = valid ? Math.floor((date!.getTime() - Date.now()) / 86_400_000) : null
  return {
    date: valid ? date : null,
    daysToExpiry,
    expired: daysToExpiry !== null && daysToExpiry < 0,
    expiringSoon: daysToExpiry !== null && daysToExpiry <= 30 && daysToExpiry >= 0,
  }
}

// IANA top-N well-known port → service label. Covers the common cases the
// operator would otherwise have to mentally translate. Anything not in the
// table renders without a label rather than guessing.
const WELL_KNOWN: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
  68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos", 110: "pop3",
  111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios",
  139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
  194: "irc", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
  500: "isakmp", 514: "syslog", 515: "lpd", 587: "smtp-submission",
  636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
  1194: "openvpn", 1433: "mssql", 1521: "oracle", 1723: "pptp",
  2049: "nfs", 2375: "docker", 2376: "docker-tls", 2483: "oracle-ssl",
  2484: "oracle-ssl", 3000: "http-alt", 3128: "squid", 3268: "ldap-gc",
  3306: "mysql", 3389: "rdp", 4444: "krb524", 5000: "http-alt",
  5432: "postgres", 5433: "postgres", 5601: "kibana", 5672: "amqp",
  5900: "vnc", 5984: "couchdb", 5985: "winrm", 5986: "winrm-tls",
  6379: "redis", 6443: "k8s-api", 6667: "irc", 7001: "weblogic",
  7077: "spark", 8000: "http-alt", 8008: "http-alt", 8009: "ajp",
  8080: "http-alt", 8081: "http-alt", 8086: "influxdb", 8088: "http-alt",
  8089: "splunk", 8090: "http-alt", 8161: "activemq", 8443: "https-alt",
  8500: "consul", 8888: "http-alt", 9000: "http-alt", 9001: "tor-control",
  9042: "cassandra", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
  9418: "git", 9999: "http-alt", 10000: "webmin", 11211: "memcached",
  15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb", 27019: "mongodb",
  50070: "hadoop", 50090: "hadoop",
}

export function OpenPortsPanel({
  entries,
  legacyShodanPorts,
}: {
  entries: OpenPortEntry[]
  /**
   * Bare port numbers from the legacy `shodan_ports[]` metadata path
   * (pre-refactor data). Folded into `entries` by port — if a port is
   * already in `entries`, "shodan" is just added to its sources.
   */
  legacyShodanPorts?: number[]
}) {
  const merged = mergeEntries(entries, legacyShodanPorts ?? [])
  if (merged.length === 0) return null

  // Derive "last scanned" from the freshest per-port timestamp — the
  // IP-level `naabu_last_scan_at` field can go stale because the writer's
  // shallow merge rule is "only fill if empty", while per-port last_seen_at
  // is updated by the per-port merge on every scan.
  const lastScanAt = merged.reduce<string | null>(
    (max, e) => (e.last_seen_at && (!max || e.last_seen_at > max)) ? e.last_seen_at : max,
    null,
  )

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Open ports ({merged.length})
        </p>
        {lastScanAt && (
          <span
            className="text-[10px] text-muted-foreground"
            title={new Date(lastScanAt).toLocaleString()}
          >
            scanned {relativeTime(lastScanAt)}
          </span>
        )}
      </div>
      <div className="rounded-md border divide-y text-sm">
        {merged.map(entry => <PortRow key={entry.port} entry={entry} />)}
      </div>
    </div>
  )
}

function PortRow({ entry }: { entry: OpenPortEntry }) {
  const proto = entry.protocol ?? "tcp"
  const service = entry.service ?? WELL_KNOWN[entry.port]
  const sources = entry.sources ?? []
  // "Unverified" = our stack hasn't confirmed a real application-layer service:
  //  - l7_confirmed === false: nmap -sV scanned it but got no real service
  //    (firewall-proxied handshake / tcpwrapped) — kept as intel, not a finding.
  //  - Shodan-only (no active prober, and not explicitly l7-confirmed): passive
  //    intel awaiting cross-run verification.
  // l7_confirmed === true (nmap or a banner prober got real data) → verified.
  const shodanOnly = sources.includes("shodan") && !sources.some(s => ACTIVE_PROBE_SOURCES.includes(s))
  const unverified =
    entry.l7_confirmed === false || (entry.l7_confirmed === undefined && shodanOnly)
  // Prefer the parsed service_version over the raw banner snippet — both
  // are derived from the same bytes but the version is the curated form.
  // If neither is set, fall through to nothing (service alone is enough).
  const rawSecondary = entry.service_version || entry.banner_snippet || null
  // Some ports (e.g. nping-echo on 9929) respond with random binary data —
  // latin-1-decoded mojibake is useless, so show a hex preview instead.
  const secondary = rawSecondary && isBinary(rawSecondary) ? hexPreview(rawSecondary) : rawSecondary

  const cert = entry.cert_summary
  const certIssuer = cert?.issuer_cn || cert?.issuer_org
  // Same expiry thresholds as the domain-WHOIS expiry display (Assets.tsx).
  const { date: certExpiry, daysToExpiry: certDaysToExpiry, expired: certExpired, expiringSoon: certExpiringSoon } =
    certExpiryState(cert?.not_after)

  return (
    <div className="px-3 py-1.5 space-y-0.5">
      <div className="flex items-center gap-3">
        <span className="font-mono text-foreground w-20 shrink-0">
          {entry.port}/{proto}
        </span>
        <span className="text-muted-foreground w-24 shrink-0 truncate" title={service}>
          {service ?? "—"}
        </span>
        {unverified && (
          <Badge
            variant="outline"
            className="h-4 px-1.5 py-0 text-[9px] font-normal text-muted-foreground shrink-0"
            title="Seen by Shodan; not yet confirmed by our scanners"
          >
            unverified
          </Badge>
        )}
        <div className="flex-1" />
        {sources.length > 0 && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="shrink-0 inline-flex items-center justify-center text-muted-foreground hover:text-foreground cursor-help">
                <Radio className="h-3 w-3" />
              </span>
            </TooltipTrigger>
            <TooltipContent side="left" className="max-w-xs">
              <div className="space-y-1">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
                  Signals
                </p>
                {sources.map(s => (
                  <div key={s}>{SOURCE_LABELS[s] ?? s}</div>
                ))}
              </div>
            </TooltipContent>
          </Tooltip>
        )}
        {entry.last_seen_at && (
          <span
            className="text-[10px] text-muted-foreground shrink-0 w-28 text-right"
            title={new Date(entry.last_seen_at).toLocaleString()}
          >
            {shodanOnly ? `Shodan · ${relativeTime(entry.last_seen_at)}` : relativeTime(entry.last_seen_at)}
          </span>
        )}
      </div>
      {secondary && (
        <div
          className="font-mono text-[10px] text-muted-foreground/80 truncate pl-[5.75rem]"
          title={secondary}
        >
          {secondary}
        </div>
      )}
      {entry.tech_stack && entry.tech_stack.length > 0 && (
        <div className="flex flex-wrap gap-1 pl-[5.75rem]">
          {entry.tech_stack.map(t => (
            <Badge key={t} variant="outline" className="h-4 px-1.5 py-0 text-[9px] font-normal">
              {t}
            </Badge>
          ))}
        </div>
      )}
      {certIssuer && (
        <div className="font-mono text-[10px] text-muted-foreground/80 truncate pl-[5.75rem]">
          {certIssuer}
          {cert?.not_after && (
            <span className={certExpired ? "text-destructive font-medium" : certExpiringSoon ? "text-orange-500 font-medium" : ""}>
              {" · "}
              {certExpired ? "expired" : "expires"} {certExpiry!.toLocaleDateString()}
              {certExpiringSoon && ` (${certDaysToExpiry}d)`}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

// Banners are captured latin-1 (lossless byte→char). Printable ASCII plus
// common whitespace renders fine; anything else means the service responded
// with non-text data (e.g. nping-echo's random payload on 9929/tcp).
function isBinary(s: string): boolean {
  let nonPrintable = 0
  for (const ch of s) {
    const code = ch.codePointAt(0) ?? 0
    if (code < 0x20 && code !== 0x09 || code > 0x7e) nonPrintable++
  }
  return nonPrintable / s.length > 0.3
}

function hexPreview(s: string, maxBytes = 24): string {
  const bytes = [...s].slice(0, maxBytes).map(ch => (ch.codePointAt(0) ?? 0).toString(16).padStart(2, "0"))
  return `${bytes.join(" ")}${s.length > maxBytes ? " …" : ""} (${s.length} bytes)`
}

function mergeEntries(entries: OpenPortEntry[], legacyShodan: number[]): OpenPortEntry[] {
  const byPort = new Map<number, OpenPortEntry>()
  for (const e of entries) {
    if (typeof e?.port !== "number") continue
    byPort.set(e.port, { ...e, sources: [...(e.sources ?? [])] })
  }
  for (const p of legacyShodan) {
    if (typeof p !== "number") continue
    const existing = byPort.get(p)
    if (existing) {
      if (!existing.sources!.includes("shodan")) existing.sources!.push("shodan")
    } else {
      byPort.set(p, { port: p, protocol: "tcp", sources: ["shodan"] })
    }
  }
  return [...byPort.values()].sort((a, b) => a.port - b.port)
}
