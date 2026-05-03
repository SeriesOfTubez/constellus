import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { Toaster } from "@/components/ui/sonner"
import { ThemeProvider } from "@/lib/theme"
import { AppShell } from "@/components/AppShell"
import { ProtectedRoute } from "@/components/ProtectedRoute"
import { api, type SystemStatus } from "@/lib/api"

import Login from "@/pages/Login"
import Setup from "@/pages/admin/Setup"
import Dashboard from "@/pages/Dashboard"
import Scans from "@/pages/Scans"
import Findings from "@/pages/Findings"
import Assets from "@/pages/Assets"
import Connectors from "@/pages/admin/Connectors"
import Sso from "@/pages/admin/Sso"
import Users from "@/pages/admin/Users"
import Settings from "@/pages/admin/Settings"

function SetupGuard({ children }: { children: React.ReactNode }) {
  const { data, isLoading } = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api.get<SystemStatus>("/system/status"),
    retry: false,
  })

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-pulse text-muted-foreground text-sm">Loading…</div>
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
      <BrowserRouter>
        <Routes>
          <Route path="/setup" element={<Setup />} />
          <Route path="/login" element={
            <SetupGuard><Login /></SetupGuard>
          } />

          <Route element={<ProtectedRoute />}>
            <Route element={<AppShell />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/assets" element={<Assets />} />

              <Route element={<ProtectedRoute roles={["admin", "integration_admin"]} />}>
                <Route path="/admin/connectors" element={<Connectors />} />
                <Route path="/admin/sso" element={<Sso />} />
                <Route path="/admin/settings" element={<Settings />} />
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
    </ThemeProvider>
  )
}
