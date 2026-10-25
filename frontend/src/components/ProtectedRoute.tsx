import { Navigate, Outlet } from "react-router-dom"
import { useAuthStore } from "@/lib/auth"
import { usePermissionsSync } from "@/lib/permissions"

interface ProtectedRouteProps {
  roles?: string[]
}

export function ProtectedRoute({ roles }: ProtectedRouteProps) {
  const { user, tokens } = useAuthStore()
  usePermissionsSync()

  if (!tokens?.access_token || !user) {
    return <Navigate to="/login" replace />
  }

  if (roles && !roles.includes(user.role)) {
    return <Navigate to="/dashboard" replace />
  }

  return <Outlet />
}
