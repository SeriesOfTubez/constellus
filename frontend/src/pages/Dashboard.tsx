import { useQuery } from "@tanstack/react-query"
import { Link } from "react-router-dom"
import { AlertTriangle, Globe, ScanLine, TrendingUp } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuthStore } from "@/lib/auth"
import { api } from "@/lib/api"

function StatCard({ label, value, icon: Icon, loading, to }: { label: string; value?: number | string; icon: React.ElementType; loading?: boolean; to?: string }) {
  const inner = (
    <Card className={to ? "transition-colors hover:bg-accent/50 cursor-pointer" : undefined}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        {loading ? (
          <Skeleton className="h-8 w-16" />
        ) : (
          <div className="text-2xl font-bold">{value ?? "—"}</div>
        )}
      </CardContent>
    </Card>
  )
  return to ? <Link to={to} className="block">{inner}</Link> : inner
}

export default function Dashboard() {
  const { user } = useAuthStore()

  const { data: findings, isLoading: fLoading } = useQuery({
    queryKey: ["findings-count"],
    queryFn: () => api.get<unknown[]>("/findings/").catch(() => []),
  })

  const { data: assets, isLoading: aLoading } = useQuery({
    queryKey: ["assets-count"],
    queryFn: () => api.get<unknown[]>("/assets/").catch(() => []),
  })

  const { data: scans, isLoading: sLoading } = useQuery({
    queryKey: ["scans-count"],
    queryFn: () => api.get<unknown[]>("/scans/").catch(() => []),
  })

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-sm text-muted-foreground mt-1">Welcome back, {user?.full_name}</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Open Findings" value={findings?.length} icon={AlertTriangle} loading={fLoading} to="/findings" />
        <StatCard label="Assets" value={assets?.length} icon={Globe} loading={aLoading} to="/assets" />
        <StatCard label="Scans" value={scans?.length} icon={ScanLine} loading={sLoading} to="/scans" />
        <StatCard label="Risk Score" value="—" icon={TrendingUp} />
      </div>

      <div className="rounded-lg border bg-card p-8 text-center text-muted-foreground">
        <ScanLine className="h-12 w-12 mx-auto mb-4 opacity-30" />
        <p className="font-medium">No scans yet</p>
        <p className="text-sm mt-1">Configure your connectors and run your first scan to see results here.</p>
      </div>
    </div>
  )
}
