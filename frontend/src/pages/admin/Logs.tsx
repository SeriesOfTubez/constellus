import { useState, useEffect, useRef } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Filter, RefreshCw, Trash2, Loader2, Circle, Timer } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { api } from "@/lib/api"

type LogEntry = {
  id: string
  created_at: string
  level: "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL"
  source: string
  logger_name: string
  message: string
}

const LEVEL_COLOR: Record<string, string> = {
  DEBUG:    "text-muted-foreground",
  INFO:     "text-blue-500",
  WARNING:  "text-yellow-500",
  ERROR:    "text-red-500",
  CRITICAL: "text-red-600 font-bold",
}

const LEVEL_BG: Record<string, string> = {
  DEBUG:    "",
  INFO:     "",
  WARNING:  "bg-yellow-500/5",
  ERROR:    "bg-red-500/5",
  CRITICAL: "bg-red-500/10",
}

const SOURCE_COLOR: Record<string, string> = {
  system:           "text-muted-foreground",
  scan_executor:    "text-purple-500",
  cloudflare:       "text-orange-500",
  mailtrap:         "text-blue-500",
  tenable:          "text-red-500",
  wiz:              "text-cyan-500",
  fortimanager:     "text-indigo-500",
  nuclei:           "text-green-500",
  cert_transparency:"text-blue-400",
  subfinder:        "text-purple-400",
  dnsrecon:         "text-green-400",
  bruteforce:       "text-yellow-500",
}

function fmt(iso: string) {
  const d = new Date(iso)
  return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    + "." + String(d.getMilliseconds()).padStart(3, "0")
}

export default function Logs() {
  const qc = useQueryClient()
  const [source, setSource] = useState("all")
  const [level, setLevel] = useState("all")
  const [search, setSearch] = useState("")
  const [autoRefresh, setAutoRefresh] = useState(true)
  const bottomRef = useRef<HTMLDivElement>(null)
  const [pinToBottom, setPinToBottom] = useState(true)

  const { data: sources } = useQuery({
    queryKey: ["log-sources"],
    queryFn: () => api.get<string[]>("/logs/sources"),
    staleTime: 30_000,
  })

  const { data: logSettings } = useQuery({
    queryKey: ["log-settings"],
    queryFn: () => api.get<{ retention_days: number; retention_options: number[] }>("/logs/settings"),
  })

  const retentionMutation = useMutation({
    mutationFn: (days: number) => api.put("/logs/settings", { retention_days: days }),
    onSuccess: (_, days) => {
      toast.success(`Log retention set to ${days === 1 ? "24 hours" : `${days} days`}`)
      qc.invalidateQueries({ queryKey: ["log-settings"] })
    },
    onError: () => toast.error("Failed to update retention"),
  })

  const { data: logs, isLoading, isFetching } = useQuery({
    queryKey: ["logs", source, level, search],
    queryFn: () => {
      const params = new URLSearchParams()
      if (source !== "all") params.set("source", source)
      if (level !== "all") params.set("level", level)
      if (search) params.set("search", search)
      return api.get<LogEntry[]>(`/logs/?${params}`)
    },
    refetchInterval: autoRefresh ? 5000 : false,
  })

  const clearMutation = useMutation({
    mutationFn: () => api.delete("/logs/"),
    onSuccess: () => {
      toast.success("Logs cleared")
      qc.invalidateQueries({ queryKey: ["logs"] })
      qc.invalidateQueries({ queryKey: ["log-sources"] })
    },
    onError: () => toast.error("Failed to clear logs"),
  })

  // Scroll to bottom when new entries arrive (if pinned)
  useEffect(() => {
    if (pinToBottom) bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [logs, pinToBottom])

  const reversed = [...(logs ?? [])].reverse()

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <div className="p-4 border-b space-y-3 flex-shrink-0">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-semibold">Logs</h1>
            <p className="text-xs text-muted-foreground mt-0.5">Backend application and connector logs</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              {isFetching && <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />}
              {autoRefresh && !isFetching && (
                <Circle className="h-2 w-2 fill-emerald-500 text-emerald-500 animate-pulse" />
              )}
              <Label className="text-xs text-muted-foreground cursor-pointer">Live</Label>
              <Switch checked={autoRefresh} onCheckedChange={setAutoRefresh} />
            </div>
            <Button variant="outline" size="sm"
              onClick={() => qc.invalidateQueries({ queryKey: ["logs"] })}>
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
            {logSettings && (
              <div className="flex items-center gap-1.5">
                <Timer className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                <span className="text-xs text-muted-foreground whitespace-nowrap">Retain for</span>
                <Select
                  value={String(logSettings.retention_days)}
                  onValueChange={v => retentionMutation.mutate(Number(v))}
                >
                  <SelectTrigger className="h-8 w-28 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {logSettings.retention_options.map(d => (
                      <SelectItem key={d} value={String(d)}>
                        {d === 1 ? "24 hours" : `${d} days`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <Button variant="outline" size="sm"
              className="text-destructive hover:text-destructive"
              disabled={clearMutation.isPending}
              onClick={() => { if (confirm("Clear all logs?")) clearMutation.mutate() }}>
              <Trash2 className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2 items-center">
          <div className="relative flex-1 min-w-48 max-w-xs">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input className="pl-8 h-8 text-xs font-mono" placeholder="Search messages..."
              value={search} onChange={e => setSearch(e.target.value)} />
          </div>

          <Select value={source} onValueChange={setSource}>
            <SelectTrigger className="w-44 h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All sources</SelectItem>
              <SelectItem value="system">System</SelectItem>
              {sources?.filter(s => s !== "system").map(s => (
                <SelectItem key={s} value={s}>{s}</SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={level} onValueChange={setLevel}>
            <SelectTrigger className="w-32 h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All levels</SelectItem>
              <SelectItem value="INFO">Info</SelectItem>
              <SelectItem value="WARNING">Warning</SelectItem>
              <SelectItem value="ERROR">Error</SelectItem>
              <SelectItem value="CRITICAL">Critical</SelectItem>
            </SelectContent>
          </Select>

          <span className="text-xs text-muted-foreground ml-auto">
            {logs?.length ?? 0} entries
          </span>
        </div>
      </div>

      {/* Log output */}
      <div className="flex-1 overflow-y-auto font-mono text-xs bg-[#0a0a0a]"
        onScroll={e => {
          const el = e.currentTarget
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
          setPinToBottom(atBottom)
        }}>
        {isLoading ? (
          <div className="p-4 text-muted-foreground">Loading…</div>
        ) : reversed.length === 0 ? (
          <div className="p-4 text-muted-foreground">No log entries yet.</div>
        ) : (
          reversed.map(entry => (
            <div key={entry.id}
              className={`flex gap-3 px-4 py-0.5 hover:bg-white/5 border-b border-white/5 ${LEVEL_BG[entry.level] ?? ""}`}>
              <span className="text-[11px] text-muted-foreground shrink-0 w-28 tabular-nums">
                {fmt(entry.created_at)}
              </span>
              <span className={`shrink-0 w-16 ${LEVEL_COLOR[entry.level] ?? "text-foreground"}`}>
                {entry.level}
              </span>
              <span className={`shrink-0 w-28 truncate ${SOURCE_COLOR[entry.source] ?? "text-muted-foreground"}`}>
                {entry.source}
              </span>
              <span className="text-foreground/90 break-all">{entry.message}</span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
