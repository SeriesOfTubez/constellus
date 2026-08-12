import { useState } from "react"
import { Link, useLocation } from "react-router-dom"
import {
  LayoutDashboard,
  AlertTriangle,
  Globe,
  Network,
  HelpCircle,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
} from "lucide-react"
import { Logo } from "@/components/Logo"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useAuthStore } from "@/lib/auth"
import { canMutate } from "@/lib/roles"
import { cn } from "@/lib/utils"

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/findings",  label: "Findings",  icon: AlertTriangle },
  { to: "/assets",    label: "Assets",    icon: Globe },
  { to: "/explore",   label: "Explore",   icon: Network },
]

// One item shape, two modes. Collapsed items are a fixed 40×40 square; their
// parent containers use `items-center`, so no mx-auto/w-full juggling is needed
// and the hover/active highlight is always a clean contained square.
const COLLAPSED_ITEM = "h-10 w-10 justify-center"
const EXPANDED_ITEM  = "h-9 w-full gap-3 px-3 text-sm"
// `relative` + a left accent bar via ::before makes the active page unmistakable
// in both modes (VSCode/Linear pattern), independent of the subtle bg tint.
const BASE_ITEM      = "relative flex items-center rounded-lg transition-colors"
const REST_STATE     = "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
const ACTIVE_STATE   =
  "bg-primary/20 text-primary font-medium " +
  "before:absolute before:left-0 before:top-1/2 before:-translate-y-1/2 " +
  "before:h-5 before:w-[3px] before:rounded-r-full before:bg-primary"

function itemClass(collapsed: boolean, active = false) {
  return cn(
    BASE_ITEM,
    collapsed ? COLLAPSED_ITEM : EXPANDED_ITEM,
    active ? ACTIVE_STATE : REST_STATE
  )
}

function NavItem({
  to, label, icon: Icon, collapsed,
}: {
  to: string; label: string; icon: React.ElementType; collapsed: boolean
}) {
  // Compute active ourselves and pass a STRING className. A function className
  // (NavLink's `({ isActive }) => …`) gets stringified by Radix `asChild` Slot
  // when wrapped in TooltipTrigger, which silently breaks all styling.
  const { pathname } = useLocation()
  const active = pathname === to || pathname.startsWith(to + "/")

  const link = (
    <Link to={to} className={itemClass(collapsed, active)}>
      <Icon className="h-4 w-4 shrink-0" />
      {!collapsed && <span>{label}</span>}
    </Link>
  )
  if (!collapsed) return link
  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{label}</TooltipContent>
    </Tooltip>
  )
}

function RailButton({
  icon: Icon, label, onClick, collapsed,
}: {
  icon: React.ElementType; label: string; onClick?: () => void; collapsed: boolean
}) {
  const btn = (
    <button onClick={onClick} className={itemClass(collapsed)}>
      <Icon className="h-4 w-4 shrink-0" />
      {!collapsed && <span>{label}</span>}
    </button>
  )
  if (!collapsed) return btn
  return (
    <Tooltip>
      <TooltipTrigger asChild>{btn}</TooltipTrigger>
      <TooltipContent side="right">{label}</TooltipContent>
    </Tooltip>
  )
}

export function Sidebar() {
  const { user, clearAuth } = useAuthStore()
  const isAdmin = canMutate(user?.role)

  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("sidebar-collapsed") === "true"
  )

  function toggleCollapsed() {
    const next = !collapsed
    setCollapsed(next)
    localStorage.setItem("sidebar-collapsed", String(next))
  }

  const initials =
    user?.full_name?.split(" ").map((n) => n[0]).join("").toUpperCase().slice(0, 2) ?? "?"

  // Containers center their children when collapsed, left-align (with padding) when expanded.
  const sectionClass = collapsed
    ? "flex flex-col items-center gap-2"
    : "px-2 space-y-1"

  return (
    <TooltipProvider delayDuration={200}>
      <aside
        className={cn(
          "flex h-screen flex-col border-r bg-card transition-all duration-200 shrink-0",
          collapsed ? "w-16" : "w-56"
        )}
      >
        {/* Header */}
        <div
          className={cn(
            "flex h-14 items-center border-b shrink-0",
            collapsed ? "justify-center" : "justify-between pl-4 pr-2"
          )}
        >
          {!collapsed && <Logo />}
          <button
            onClick={toggleCollapsed}
            className={cn(
              "flex items-center justify-center rounded-lg transition-colors",
              REST_STATE,
              collapsed ? "h-10 w-10" : "h-8 w-8 shrink-0"
            )}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed
              ? <ChevronRight className="h-4 w-4 shrink-0" />
              : <ChevronLeft className="h-4 w-4 shrink-0" />}
          </button>
        </div>

        {/* Primary nav */}
        <nav className={cn("flex-1 overflow-y-auto py-3", sectionClass)}>
          {NAV.map((item) => (
            <NavItem key={item.to} {...item} collapsed={collapsed} />
          ))}
        </nav>

        {/* Bottom utility rail */}
        <div className={cn("border-t py-3", sectionClass)}>
          <RailButton
            icon={HelpCircle}
            label="Help"
            collapsed={collapsed}
            onClick={() => window.open("https://github.com/SeriesOfTubez/constellus/issues", "_blank")}
          />

          <DropdownMenu>
            <Tooltip>
              <TooltipTrigger asChild>
                <DropdownMenuTrigger asChild>
                  <button className={itemClass(collapsed)}>
                    <Avatar className="h-5 w-5 shrink-0">
                      <AvatarFallback className="text-[10px] bg-primary/10 text-primary">
                        {initials}
                      </AvatarFallback>
                    </Avatar>
                    {!collapsed && <span className="truncate">{user?.full_name}</span>}
                  </button>
                </DropdownMenuTrigger>
              </TooltipTrigger>
              {collapsed && <TooltipContent side="right">{user?.full_name}</TooltipContent>}
            </Tooltip>

            <DropdownMenuContent side="right" align="end" className="w-48">
              <DropdownMenuLabel className="font-normal">
                <p className="text-sm font-medium">{user?.full_name}</p>
                <p className="text-xs text-muted-foreground capitalize">
                  {user?.role?.replace(/_/g, " ")}
                </p>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={clearAuth} className="text-destructive focus:text-destructive">
                <LogOut className="h-4 w-4 mr-2" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {isAdmin && (
            <NavItem to="/admin" label="Admin" icon={Settings} collapsed={collapsed} />
          )}
        </div>
      </aside>
    </TooltipProvider>
  )
}
