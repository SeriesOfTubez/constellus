import { Link } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import {
  Activity, Bell, Building2, ChevronRight, ClipboardList, GitBranch,
  Globe, KeyRound, Plug, Server, Settings2,
  ShieldCheck, Smartphone, Tags, Target as TargetIcon, Users,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import { api } from "@/lib/api"

interface AdminItem {
  label: string
  description: string
  icon: React.ElementType
  to: string | null
  statsKey?: string
  future?: boolean
}

interface AdminCategory {
  key: string
  icon: React.ElementType
  label: string
  description: string
  items: AdminItem[]
}

const CATEGORIES: AdminCategory[] = [
  {
    key: "identity",
    icon: ShieldCheck,
    label: "Identity",
    description: "Users, authentication, and access control",
    items: [
      { label: "Users",  description: "Manage accounts and roles",    to: "/admin/users",    icon: Users,      statsKey: "users" },
      { label: "SSO",    description: "Single sign-on configuration", to: "/admin/sso",      icon: KeyRound },
      { label: "MFA",    description: "Multi-factor authentication",  to: null,              icon: Smartphone, future: true },
    ],
  },
  {
    key: "discovery",
    icon: Globe,
    label: "Discovery",
    description: "Targets and data source connectors",
    items: [
      { label: "Targets",    description: "Domains and IP ranges to monitor", to: "/admin/targets",    icon: TargetIcon, statsKey: "targets" },
      { label: "Connectors", description: "Third-party integrations",          to: "/admin/connectors", icon: Plug,       statsKey: "connectors" },
    ],
  },
  {
    key: "rules",
    icon: GitBranch,
    label: "Rules",
    description: "Automated tagging and notification rules",
    items: [
      { label: "Tag Rules",          description: "Auto-tag assets based on conditions", to: "/admin/tag-rules", icon: Tags, statsKey: "tag-rules" },
      { label: "Notification Rules", description: "Alert routing and triggers",          to: null,              icon: Bell, future: true },
    ],
  },
  {
    key: "platform",
    icon: Settings2,
    label: "Platform",
    description: "Scan config, org branding, and system health",
    items: [
      { label: "Activity",     description: "Scan history and job queue",       to: "/admin/activity", icon: Activity },
      { label: "Organization", description: "Branding, name, and accent color", to: "/admin/settings", icon: Building2 },
      { label: "System",       description: "Health and diagnostics",           to: null,              icon: Server,        future: true },
      { label: "Audit Log",    description: "Administrative action history",    to: null,              icon: ClipboardList, future: true },
    ],
  },
]

function CategoryCard({
  category,
  stats,
}: {
  category: AdminCategory
  stats: Record<string, number | undefined>
}) {
  const Icon = category.icon
  return (
    <Card>
      <CardContent className="pt-6 flex flex-col gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-primary/10 shrink-0">
            <Icon className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h2 className="text-base font-semibold leading-tight">{category.label}</h2>
            <p className="text-xs text-muted-foreground mt-0.5">{category.description}</p>
          </div>
        </div>

        <div className="border-t" />

        <div className="flex flex-col gap-0.5 -mx-2">
          {category.items.map(item => {
            const ItemIcon = item.icon
            const count = item.statsKey ? stats[item.statsKey] : undefined

            if (!item.to || item.future) {
              return (
                <div
                  key={item.label}
                  className={cn("flex items-center gap-3 px-3 py-2 rounded-md", item.future && "opacity-40")}
                >
                  <ItemIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                  <span className="flex-1 text-sm text-muted-foreground">{item.label}</span>
                  {item.future && (
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4">Soon</Badge>
                  )}
                </div>
              )
            }

            return (
              <Link
                key={item.label}
                to={item.to}
                className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-accent group transition-colors"
              >
                <ItemIcon className="h-4 w-4 text-muted-foreground shrink-0" />
                <span className="flex-1 text-sm">{item.label}</span>
                {count !== undefined && (
                  <span className="text-xs text-muted-foreground tabular-nums">{count}</span>
                )}
                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-60 transition-opacity" />
              </Link>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}

export default function Admin() {
  const { data: users }      = useQuery({ queryKey: ["users"],      queryFn: () => api.get<unknown[]>("/users/"),        staleTime: 60_000 })
  const { data: targets }    = useQuery({ queryKey: ["targets"],    queryFn: () => api.get<unknown[]>("/targets/"),      staleTime: 60_000 })
  const { data: connectors } = useQuery({ queryKey: ["connectors"], queryFn: () => api.get<unknown[]>("/connectors/"),  staleTime: 60_000 })
  const { data: tagRules }   = useQuery({ queryKey: ["tag-rules"],  queryFn: () => api.get<unknown[]>("/tags/rules"),   staleTime: 60_000 })

  const stats: Record<string, number | undefined> = {
    users:       users?.length,
    targets:     targets?.length,
    connectors:  connectors?.length,
    "tag-rules": tagRules?.length,
  }

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Admin</h1>
        <p className="text-sm text-muted-foreground mt-1">Manage your Constellus deployment</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {CATEGORIES.map(cat => (
          <CategoryCard key={cat.key} category={cat} stats={stats} />
        ))}
      </div>
    </div>
  )
}
