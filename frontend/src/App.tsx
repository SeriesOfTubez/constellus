import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { Toaster } from "@/components/ui/sonner"
import { ThemeProvider } from "@/lib/theme"
import { BrandingProvider } from "@/lib/branding-context"
import { TooltipProvider } from "@/components/ui/tooltip"
import { AppShell } from "@/components/AppShell"
import { ProtectedRoute } from "@/components/ProtectedRoute"
import { api, type SystemStatus } from "@/lib/api"

import Login from "@/pages/Login"
import Setup from "@/pages/admin/Setup"
import Dashboard from "@/pages/Dashboard"
import Findings from "@/pages/Findings"
import FindingDetail from "@/pages/FindingDetail"
import Assets from "@/pages/Assets"
import AssetDetail from "@/pages/AssetDetail"
import TargetDetail from "@/pages/TargetDetail"
import Explore from "@/pages/Explore"
import Admin from "@/pages/admin/Admin"
import Connectors from "@/pages/admin/Connectors"
import Targets from "@/pages/admin/Targets"
import Activity from "@/pages/admin/Activity"
import Sso from "@/pages/admin/Sso"
import Users from "@/pages/admin/Users"
import Settings from "@/pages/admin/Settings"
import TagRules from "@/pages/admin/TagRules"

function SetupGuard({ children }: { children: React.ReactNode }) {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatus>("/system/status"),
    retry: 3,
    retryDelay: 2000,
  })

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-muted-foreground text-sm">Connecting…</div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center space-y-3">
          <p className="text-sm font-medium">Cannot reach the Constellus backend</p>
          <p className="text-xs text-muted-foreground">Make sure the server is running on port 8000</p>
          <button
            onClick={() => refetch()}
            className="text-xs underline text-muted-foreground hover:text-foreground"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  if (data?.first_run) {
    return <Navigate to="/setup" replace />
  }

  return <>{children}</>
}

export default function App() {
  return (
    <ThemeProvider>
      <TooltipProvider delayDuration={300}>
        <BrandingProvider>
          <BrowserRouter>
        <Routes>
          <Route path="/setup" element={<Setup />} />
          <Route path="/login" element={
            <SetupGuard><Login /></SetupGuard>
          } />

          <Route element={<ProtectedRoute />}>
            <Route element={<AppShell />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:id" element={<FindingDetail />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/assets/:id" element={<AssetDetail />} />
              <Route path="/targets/:id" element={<TargetDetail />} />
              <Route path="/explore" element={<Explore />} />
              <Route path="/scans" element={<Navigate to="/admin/activity" replace />} />

              <Route element={<ProtectedRoute roles={["admin", "integration_admin"]} />}>
                <Route path="/admin" element={<Admin />} />
                <Route path="/admin/connectors" element={<Connectors />} />
                <Route path="/admin/targets" element={<Targets />} />
                <Route path="/admin/activity" element={<Activity />} />
                <Route path="/admin/logs" element={<Navigate to="/admin/activity" replace />} />
                <Route path="/admin/sso" element={<Sso />} />
                <Route path="/admin/settings" element={<Settings />} />
                <Route path="/admin/tag-rules" element={<TagRules />} />
              </Route>

              <Route element={<ProtectedRoute roles={["admin"]} />}>
                <Route path="/admin/users" element={<Users />} />
              </Route>
            </Route>
          </Route>

          <Route path="/" element={<SetupGuard><Navigate to="/dashboard" replace /></SetupGuard>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
          </BrowserRouter>
          <Toaster />
        </BrandingProvider>
      </TooltipProvider>
    </ThemeProvider>
  )
}
