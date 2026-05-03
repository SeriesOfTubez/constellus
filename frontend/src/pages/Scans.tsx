import { ScanLine } from "lucide-react"

export default function Scans() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Scans</h1>
        <p className="text-sm text-muted-foreground mt-1">Manage and schedule attack surface scans</p>
      </div>
      <div className="rounded-lg border bg-card p-8 text-center text-muted-foreground">
        <ScanLine className="h-12 w-12 mx-auto mb-4 opacity-30" />
        <p className="font-medium">No scans yet</p>
        <p className="text-sm mt-1">Scan orchestration UI coming soon.</p>
      </div>
    </div>
  )
}
