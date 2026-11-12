import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { OverflowCell } from "@/components/ui/overflow-cell"
import { CHIP } from "@/components/ui/chip"
import { cn } from "@/lib/utils"

export const SOURCE_META: Record<string, { label: string; description: string }> = {
  cloudflare:        { label: "CF", description: "Cloudflare DNS connector" },
  certspotter:       { label: "CS", description: "Certificate Transparency (Certspotter)" },
  cert_transparency: { label: "CT", description: "Certificate Transparency" },
  dns_resolve:       { label: "DR", description: "Resolved via public DNS (1.1.1.1 / 8.8.8.8)" },
  subfinder:         { label: "SF", description: "subfinder passive enumeration" },
  dnsrecon:          { label: "DR", description: "dnsrecon active DNS enumeration" },
  bruteforce:        { label: "BF", description: "Subdomain brute-force" },
  tenable:           { label: "TN", description: "Tenable enrichment" },
  wiz:               { label: "WZ", description: "Wiz cloud enrichment" },
  fortimanager:      { label: "FM", description: "FortiManager enrichment" },
  shodan:            { label: "SH", description: "Shodan internet exposure enrichment" },
  manual:            { label: "MN", description: "Manually added" },
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
        const meta = SOURCE_META[src] ?? { label: src.slice(0, 2).toUpperCase(), description: src }
        return (
          <Tooltip key={src}>
            <TooltipTrigger asChild>
              <span className={cn(CHIP, "cursor-help")}>
                {meta.label}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top">{meta.description}</TooltipContent>
          </Tooltip>
        )
      }}
      renderOverflowItem={(src) => {
        const meta = SOURCE_META[src] ?? { label: src.slice(0, 2).toUpperCase(), description: src }
        return (
          <div className="flex items-start gap-2">
            <span className={cn(CHIP, "shrink-0")}>{meta.label}</span>
            <span className="text-muted-foreground leading-snug pt-1">{meta.description}</span>
          </div>
        )
      }}
      getLabel={(src) => SOURCE_META[src]?.description ?? src}
    />
  )
}

export function RecordTypeBadge({ type }: { type: string }) {
  return (
    <span className={cn(CHIP, "font-mono")}>
      {type}
    </span>
  )
}

export function AssetTypeBadge({ type }: { type: string }) {
  return (
    <span className={CHIP}>
      {type.replace(/_/g, " ")}
    </span>
  )
}
