import { NavLink } from "react-router-dom"
import {
  LayoutDashboard,
  ScanLine,
  AlertTriangle,
  Globe,
  Plug,
  Users,
  Settings,
  ShieldCheck,
  BadgeCheck,
  ScrollText,
  LogOut,
} from "lucide-react"
import { Logo } from "@/components/Logo"
import { ThemeToggle } from "@/components/ThemeToggle"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Separator } from "@/components/ui/separator"
import { useAuthStore } from "@/lib/auth"
import { cn } from "@/lib/utils"

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/scans", label: "Scans", icon: ScanLine },
  { to: "/findings", label: "Findings", icon: AlertTriangle },
  { to: "/assets", label: "Assets", icon: Globe },
]

const ADMIN_NAV = [
  { to: "/admin/connectors", label: "Connectors", icon: Plug },
  { to: "/admin/targets", label: "Targets", icon: BadgeCheck },
  { to: "/admin/logs", label: "Logs", icon: ScrollText },
  { to: "/admin/sso", label: "SSO", icon: ShieldCheck },
  { to: "/admin/users", label: "Users", icon: Users },
  { to: "/admin/settings", label: "Settings", icon: Settings },
]

function NavItem({ to, label, icon: Icon }: { to: string; label: string; icon: React.ElementType }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
          isActive
            ? "bg-primary/10 text-primary"
            : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
        )
      }
    >
      <Icon className="h-4 w-4 shrink-0" />
      {label}
    </NavLink>
  )
}

export function Sidebar() {
  const { user, clearAuth } = useAuthStore()
  const isAdmin = user?.role === "admin" || user?.role === "integration_admin"
  const initials = user?.full_name
    ?.split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2) ?? "?"

  return (
    <aside className="flex h-screen w-60 flex-col border-r bg-card">
      <div className="flex h-16 items-center px-4">
        <Logo />
      </div>

      <Separator />

      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        {NAV.map((item) => (
          <NavItem key={item.to} {...item} />
        ))}

        {isAdmin && (
          <>
            <div className="pt-4 pb-1 px-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Admin</p>
            </div>
            {ADMIN_NAV.map((item) => (
              <NavItem key={item.to} {...item} />
            ))}
          </>
        )}
      </nav>

      <Separator />

      <div className="flex items-center gap-2 p-3">
        <Avatar className="h-8 w-8">
          <AvatarFallback className="text-xs bg-primary/10 text-primary">{initials}</AvatarFallback>
        </Avatar>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium truncate">{user?.full_name}</p>
          <p className="text-xs text-muted-foreground truncate capitalize">{user?.role?.replace("_", " ")}</p>
        </div>
        <ThemeToggle />
        <button
          onClick={clearAuth}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
          aria-label="Sign out"
        >
          <LogOut className="h-4 w-4" />
        </button>
      </div>
    </aside>
  )
}
