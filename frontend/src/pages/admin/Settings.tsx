import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useQuery } from "@tanstack/react-query"
import { api, type SystemStatus } from "@/lib/api"

export default function Settings() {
  const { data: status } = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatus>("/system/status"),
  })

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">System information and configuration</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">System</CardTitle>
          <CardDescription>Current deployment information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex items-center justify-between py-2 border-b">
            <span className="text-muted-foreground">Version</span>
            <Badge variant="outline">{status?.version ?? "—"}</Badge>
          </div>
          <div className="flex items-center justify-between py-2 border-b">
            <span className="text-muted-foreground">Secrets provider</span>
            <Badge variant="outline">Environment variables</Badge>
          </div>
          <div className="flex items-center justify-between py-2">
            <span className="text-muted-foreground">Setup status</span>
            <Badge variant="success">Complete</Badge>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Secrets</CardTitle>
          <CardDescription>
            Application secrets (SECRET_KEY, DATABASE_URL) are set via environment variables.
            Connector credentials are encrypted and stored in the database, configurable via the
            Connectors page.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  )
}
