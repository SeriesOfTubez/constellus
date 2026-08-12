import { Network } from "lucide-react"

export default function Explore() {
  return (
    <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-8">
      <Network className="h-12 w-12 text-muted-foreground/40" />
      <div className="space-y-1">
        <h2 className="text-lg font-semibold">Graph Explorer</h2>
        <p className="text-sm text-muted-foreground max-w-sm">
          Point-and-click query builder over the attack-surface graph — coming soon.
        </p>
      </div>
    </div>
  )
}
