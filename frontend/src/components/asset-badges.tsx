import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { OverflowCell } from "@/components/ui/overflow-cell"

export const SOURCE_META: Record<string, { label: string; color: string; description: string }> = {
  cloudflare:        { label: "CF", color: "bg-orange-500/15 text-orange-600 dark:text-orange-400",  description: "Cloudflare DNS connector" },
  certspotter:       { label: "CS", color: "bg-blue-500/15 text-blue-600 dark:text-blue-400",        description: "Certificate Transparency (Certspotter)" },
  cert_transparency: { label: "CT", color: "bg-blue-500/15 text-blue-600 dark:text-blue-400",        description: "Certificate Transparency" },
  dns_resolve:       { label: "DR", color: "bg-slate-500/15 text-slate-600 dark:text-slate-400",     description: "Resolved via public DNS (1.1.1.1 / 8.8.8.8)" },
  subfinder:         { label: "SF", color: "bg-purple-500/15 text-purple-600 dark:text-purple-400",  description: "subfinder passive enumeration" },
  dnsrecon:          { label: "DR", color: "bg-green-500/15 text-green-600 dark:text-green-400",     description: "dnsrecon active DNS enumeration" },
  bruteforce:        { label: "BF", color: "bg-yellow-500/15 text-yellow-600 dark:text-yellow-400",  description: "Subdomain brute-force" },
  tenable:           { label: "TN", color: "bg-red-500/15 text-red-600 dark:text-red-400",           description: "Tenable enrichment" },
  wiz:               { label: "WZ", color: "bg-cyan-500/15 text-cyan-600 dark:text-cyan-400",        description: "Wiz cloud enrichment" },
  fortimanager:      { label: "FM", color: "bg-indigo-500/15 text-indigo-600 dark:text-indigo-400",  description: "FortiManager enrichment" },
  shodan:            { label: "SH", color: "bg-rose-500/15 text-rose-600 dark:text-rose-400",        description: "Shodan internet exposure enrichment" },
  manual:            { label: "MN", color: "bg-muted text-muted-foreground",                         description: "Manually added" },
}

export function SourceBadges({ metadata }: { metadata: Record<string, unknown> }) {
  const sources: string[] = Array.isArray(metadata.sources)
    ? (metadata.sources as string[])
    : metadata.source ? [metadata.source as string] : []
  if (!sources.length) return null
  return (
    <OverflowCell
      items={sources}
      limit={3}
      emptyLabel=""
      renderItem={(src) => {
        const meta = SOURCE_META[src] ?? { label: src.slice(0, 2).toUpperCase(), color: "bg-muted text-muted-foreground", description: src }
        return (
          <Tooltip key={src}>
            <TooltipTrigger asChild>
              <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold cursor-help ${meta.color}`}>
                {meta.label}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top">{meta.description}</TooltipContent>
          </Tooltip>
        )
      }}
      renderOverflowItem={(src) => {
        const meta = SOURCE_META[src] ?? { label: src.slice(0, 2).toUpperCase(), color: "bg-muted text-muted-foreground", description: src }
        return (
          <div className="flex items-start gap-2">
            <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-semibold shrink-0 ${meta.color}`}>{meta.label}</span>
            <span className="text-muted-foreground leading-snug pt-0.5">{meta.description}</span>
          </div>
        )
      }}
      getLabel={(src) => SOURCE_META[src]?.description ?? src}
    />
  )
}

const RECORD_TYPE_COLOR: Record<string, string> = {
  A:     "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  AAAA:  "bg-teal-500/10 text-teal-700 dark:text-teal-400",
  CNAME: "bg-blue-500/10 text-blue-700 dark:text-blue-400",
  MX:    "bg-purple-500/10 text-purple-700 dark:text-purple-400",
}

export function RecordTypeBadge({ type }: { type: string }) {
  const cls = RECORD_TYPE_COLOR[type] ?? "bg-muted text-muted-foreground"
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-mono font-semibold ${cls}`}>
      {type}
    </span>
  )
}

const TYPE_COLOR: Record<string, string> = {
  ip_address:     "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400",
  service:        "bg-purple-500/10 text-purple-600 dark:text-purple-400",
  cloud_resource: "bg-sky-500/10 text-sky-600 dark:text-sky-400",
  internal_host:  "bg-rose-500/10 text-rose-600 dark:text-rose-400",
}

export function AssetTypeBadge({ type }: { type: string }) {
  const cls = TYPE_COLOR[type] ?? "bg-muted text-muted-foreground"
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${cls}`}>
      {type.replace(/_/g, " ")}
    </span>
  )
}
