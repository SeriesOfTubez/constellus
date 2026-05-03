import { AlertTriangle } from "lucide-react"

export default function Findings() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Findings</h1>
        <p className="text-sm text-muted-foreground mt-1">Review and triage risk findings</p>
      </div>
      <div className="rounded-lg border bg-card p-8 text-center text-muted-foreground">
        <AlertTriangle className="h-12 w-12 mx-auto mb-4 opacity-30" />
        <p className="font-medium">No findings yet</p>
        <p className="text-sm mt-1">Run a scan to discover findings.</p>
      </div>
    </div>
  )
}
