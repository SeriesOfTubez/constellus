import React, { useState } from "react"
import { AlertTriangle, ChevronDown, ChevronRight, Lock } from "lucide-react"
import { cn } from "@/lib/utils"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { OverflowCell } from "@/components/ui/overflow-cell"
import { SeverityBadge } from "@/components/finding-badges"
import { type Finding } from "@/lib/api"
import { relativeTime } from "@/lib/time"
import { displayName } from "@/lib/apex"

// Port numbers from risky_exposures.yaml that warrant a lock flag even with zero findings.
export const SENSITIVE_PORTS = new Set<number>([
  21, 22, 23,                                    // FTP, SSH, Telnet
  88, 135, 139, 389, 445, 464,                   // Kerberos, MSRPC, NetBIOS, LDAP, SMB
  512, 513, 514, 636,                            // r-services, LDAPS
  873,                                           // rsync
  1433, 1521, 1522, 1525, 1526,                 // MSSQL, Oracle TNS
  2181, 2375, 2376, 2379, 2380,                 // ZooKeeper, Docker API, etcd
  3268, 3269, 3306, 3389,                       // GlobalCatalog LDAP, MySQL, RDP
  5432, 5672, 5900, 5901, 5902, 5903,           // PostgreSQL, RabbitMQ, VNC
  5984, 5985, 5986, 6000, 6001, 6002,           // CouchDB, WinRM, X11
  6003, 6004, 6005, 6006,                        // X11 cont.
  6379, 6443, 6984,                              // Redis, Kubernetes API, CouchDB TLS
  7474, 7687,                                    // Neo4j HTTP + Bolt
  8086,                                          // InfluxDB
  9042, 9092, 9093, 9200, 9300,                 // Cassandra, Kafka, Elasticsearch
  10250, 10255,                                  // Kubelet
  11211,                                         // Memcached
  15672,                                         // RabbitMQ management UI
  27017, 27018, 27019,                           // MongoDB
])

// ── Types ─────────────────────────────────────────────────────────────────────

export interface PivotAssetRow {
  assetId: string
  assetValue: string
  assetParentValue: string | null
  port: number
  service: string | null
  serviceVersion: string | null
  lastSeenAt: string | null
  worstSeverity: Finding["severity"] | null
}

export interface PivotSummaryRow {
  key: string
  label: string
  sublabel?: string      // Ports mode: dominant detected service; Services mode: omitted
  isSensitive: boolean
  services: string[]     // Ports mode: unique services detected on this port
  ports: number[]        // Services mode: unique ports running this service
  versions: string[]     // unique non-null service_version values
  hasDrift: boolean      // versions.length > 1 — the killer signal
  assetCount: number     // unique IP assets
  worstSeverity: Finding["severity"] | null
  assets: PivotAssetRow[]
}

interface PivotTableProps {
  rows: PivotSummaryRow[]
  mode: "ports" | "services"
  onAssetClick: (assetId: string) => void
  emptyMessage?: string
}

// ── Component ─────────────────────────────────────────────────────────────────

export function PivotTable({ rows, mode, onAssetClick, emptyMessage }: PivotTableProps) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const isPortsMode = mode === "ports"

  function toggle(key: string) {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  if (!rows.length) {
    return (
      <div className="rounded-lg border bg-card p-12 text-center text-muted-foreground">
        <p className="font-medium">{emptyMessage ?? "No data"}</p>
      </div>
    )
  }

  return (
    <div className="rounded-lg border overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-8" />
            <TableHead>{isPortsMode ? "Port" : "Service"}</TableHead>
            <TableHead>{isPortsMode ? "Service" : "Ports"}</TableHead>
            <TableHead className="w-28">Versions</TableHead>
            <TableHead className="w-20 text-right">Assets</TableHead>
            <TableHead className="w-24 text-right">Risk</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map(row => {
            const isOpen = expanded.has(row.key)
            return (
              <React.Fragment key={row.key}>
                {/* ── Summary row ────────────────────────────────────────── */}
                <TableRow
                  className="cursor-pointer hover:bg-muted/50 select-none"
                  onClick={() => toggle(row.key)}
                >
                  <TableCell className="w-8 pl-3">
                    {isOpen
                      ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                      : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
                  </TableCell>

                  {/* Port number / service name */}
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {row.isSensitive && (
                        <span title="Sensitive service — high risk if internet-exposed" className="inline-flex shrink-0">
                          <Lock className="h-3 w-3 text-muted-foreground" />
                        </span>
                      )}
                      <span className="font-mono font-semibold text-primary">{row.label}</span>
                      {row.sublabel && (
                        <span className="text-xs text-muted-foreground">· {row.sublabel}</span>
                      )}
                    </div>
                  </TableCell>

                  {/* Services (ports mode) or port chips (services mode) */}
                  <TableCell>
                    {isPortsMode ? (
                      row.services.length > 0 ? (
                        <OverflowCell
                          items={row.services}
                          renderItem={(svc, i) => (
                            <span key={i} className="text-sm text-foreground">{svc}</span>
                          )}
                          getLabel={svc => svc}
                          limit={1}
                        />
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )
                    ) : (
                      row.ports.length > 0 ? (
                        <OverflowCell
                          items={row.ports}
                          renderItem={(p, i) => (
                            <span
                              key={i}
                              className={cn(
                                "font-mono text-xs px-1.5 py-0.5 rounded",
                                SENSITIVE_PORTS.has(p)
                                  ? "bg-primary/10 text-primary"
                                  : "bg-muted text-muted-foreground",
                              )}
                            >
                              {p}
                            </span>
                          )}
                          getLabel={p => String(p)}
                          limit={3}
                        />
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )
                    )}
                  </TableCell>

                  {/* Versions — calm when consistent, loud when drift */}
                  <TableCell className="w-28">
                    {row.versions.length === 0 ? (
                      <span className="text-xs text-muted-foreground">—</span>
                    ) : row.hasDrift ? (
                      <span className="inline-flex items-center gap-1 text-xs font-medium text-amber-500">
                        <AlertTriangle className="h-3 w-3 shrink-0" />
                        {row.versions.length} versions
                      </span>
                    ) : (
                      <span
                        className="block max-w-[100px] truncate text-xs font-mono text-muted-foreground"
                        title={row.versions[0]}
                      >
                        {row.versions[0]}
                      </span>
                    )}
                  </TableCell>

                  {/* Blast radius */}
                  <TableCell className="w-20 text-right">
                    <span className="text-sm font-medium tabular-nums">{row.assetCount}</span>
                  </TableCell>

                  {/* Risk rollup */}
                  <TableCell className="w-24 text-right pr-4">
                    {row.worstSeverity
                      ? <SeverityBadge severity={row.worstSeverity} />
                      : <span className="text-xs text-muted-foreground">—</span>}
                  </TableCell>
                </TableRow>

                {/* ── Expanded asset rows ─────────────────────────────────── */}
                {isOpen && row.assets.map(asset => (
                  <TableRow
                    key={`${asset.assetId}:${asset.port}`}
                    className="cursor-pointer bg-muted/10 hover:bg-muted/25 text-xs"
                    onClick={e => { e.stopPropagation(); onAssetClick(asset.assetId) }}
                  >
                    <TableCell className="w-8" />
                    <TableCell className="pl-7 font-mono text-foreground">
                      {displayName(asset.assetValue)}
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {asset.assetParentValue ? displayName(asset.assetParentValue) : "—"}
                    </TableCell>
                    <TableCell className="w-28 font-mono text-muted-foreground truncate">
                      {isPortsMode
                        ? (asset.serviceVersion ?? asset.service ?? "—")
                        : `:${asset.port}${asset.serviceVersion ? ` · ${asset.serviceVersion}` : ""}`}
                    </TableCell>
                    <TableCell className="w-20 text-right">
                      {asset.worstSeverity
                        ? <SeverityBadge severity={asset.worstSeverity} />
                        : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="w-24 text-right pr-4 text-muted-foreground">
                      {asset.lastSeenAt ? relativeTime(asset.lastSeenAt) : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </React.Fragment>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}
