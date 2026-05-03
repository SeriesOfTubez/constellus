import { Globe } from "lucide-react"

export default function Assets() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Assets</h1>
        <p className="text-sm text-muted-foreground mt-1">Discovered public-facing assets and their correlation chain</p>
      </div>
      <div className="rounded-lg border bg-card p-8 text-center text-muted-foreground">
        <Globe className="h-12 w-12 mx-auto mb-4 opacity-30" />
        <p className="font-medium">No assets discovered</p>
        <p className="text-sm mt-1">Run a scan to populate the asset inventory.</p>
      </div>
    </div>
  )
}
