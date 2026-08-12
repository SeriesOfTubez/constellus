import { Navigate, Outlet } from "react-router-dom"
import { useAuthStore } from "@/lib/auth"

interface ProtectedRouteProps {
  roles?: string[]
}

export function ProtectedRoute({ roles }: ProtectedRouteProps) {
  const { user, tokens } = useAuthStore()

  if (!tokens?.access_token || !user) {
    return <Navigate to="/login" replace />
  }

  if (roles && !roles.includes(user.role)) {
    return <Navigate to="/dashboard" replace />
  }

  return <Outlet />
}
