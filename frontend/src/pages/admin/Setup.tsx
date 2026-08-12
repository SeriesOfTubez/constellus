import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { CheckCircle2, ChevronRight, Loader2, SkipForward, Zap } from "lucide-react"
import { Logo } from "@/components/Logo"
import { ThemeToggle } from "@/components/ThemeToggle"
import { ConnectorConfigFields, fillConfigValues } from "@/components/ConnectorConfigFields"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { Skeleton } from "@/components/ui/skeleton"
import { api, ApiError, type ConnectorSummary, type User, type TokenResponse } from "@/lib/api"
import { CORE_IMPACT_COPY } from "@/lib/connector-copy"
import { useAuthStore } from "@/lib/auth"
import { cn } from "@/lib/utils"

const STEPS = ["Welcome", "Admin Account", "Connect data sources", "Done"]

// Curated allowlist of connectors to surface during first-run setup — keeps
// the step focused (no notification channels, no SSO, etc.). To add a future
// connector to setup, just append its registry id here; everything else
// (name, description, schema, the core/optional split) is derived from
// GET /connectors/ at render time.
const SETUP_CONNECTOR_IDS = ["vulncheck", "naabu", "nuclei", "banner_grab"]

type SetupCardStatus = "idle" | "saved" | "skipped"

function ConnectorSetupCard({
  connector,
  values,
  onChange,
  status,
  saving,
  onSave,
  onSkip,
}: {
  connector: ConnectorSummary
  values: Record<string, string | boolean>
  onChange: (key: string, value: string | boolean) => void
  status: SetupCardStatus
  saving: boolean
  onSave: () => void
  onSkip: () => void
}) {
  const copy = CORE_IMPACT_COPY[connector.id]

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="font-medium text-sm">{connector.name}</p>
            {connector.core && (
              <Badge variant="outline" className="border-primary/40 text-primary gap-1 text-[10px]">
                <Zap className="h-2.5 w-2.5" />
                Core
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground">{connector.description}</p>
          {copy && <p className="text-xs text-amber-600 dark:text-amber-400">{copy.short}</p>}
        </div>
        {status === "saved" && <Badge variant="success">Connected</Badge>}
        {status === "skipped" && <Badge variant="outline">Skipped — configure later</Badge>}
      </div>

      {status !== "saved" && (
        <>
          <ConnectorConfigFields schema={connector.config_schema} values={values} onChange={onChange} />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={onSkip} disabled={saving}>
              <SkipForward className="h-3.5 w-3.5" />
              Skip
            </Button>
            <Button size="sm" onClick={onSave} disabled={saving}>
              {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
              Save
            </Button>
          </div>
        </>
      )}
    </div>
  )
}

function ConnectSourcesStep({ onContinue }: { onContinue: () => void }) {
  const qc = useQueryClient()
  const [values, setValues] = useState<Record<string, Record<string, string | boolean>>>({})
  const [status, setStatus] = useState<Record<string, SetupCardStatus>>({})
  const [savingId, setSavingId] = useState<string | null>(null)

  const { data: connectors, isLoading } = useQuery({
    queryKey: ["connectors"],
    queryFn: () => api.get<ConnectorSummary[]>("/connectors/"),
  })

  function valuesFor(connector: ConnectorSummary) {
    return values[connector.id] ?? fillConfigValues(connector.config_schema, {})
  }

  function setField(connector: ConnectorSummary, key: string, value: string | boolean) {
    setValues((v) => ({ ...v, [connector.id]: { ...valuesFor(connector), [key]: value } }))
  }

  const saveMutation = useMutation({
    mutationFn: (connector: ConnectorSummary) =>
      api.put(`/connectors/${connector.id}/config`, { config: valuesFor(connector) }),
    onMutate: (connector) => setSavingId(connector.id),
    onSuccess: (_data, connector) => {
      toast.success(`${connector.name} connected`)
      setStatus((s) => ({ ...s, [connector.id]: "saved" }))
      qc.invalidateQueries({ queryKey: ["connectors"] })
    },
    onError: (_err, connector) => toast.error(`Couldn't save ${connector.name} — you can configure it later from Admin → Connectors`),
    onSettled: () => setSavingId(null),
  })

  if (isLoading || !connectors) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Connect data sources</CardTitle>
          <CardDescription>Loading available connectors…</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-24 w-full" />)}
        </CardContent>
      </Card>
    )
  }

  const setupConnectors = SETUP_CONNECTOR_IDS
    .map((id) => connectors.find((c) => c.id === id))
    .filter((c): c is ConnectorSummary => !!c)
  const core = setupConnectors.filter((c) => c.core)
  const optional = setupConnectors.filter((c) => !c.core)

  function renderCard(connector: ConnectorSummary) {
    return (
      <ConnectorSetupCard
        key={connector.id}
        connector={connector}
        values={valuesFor(connector)}
        onChange={(key, value) => setField(connector, key, value)}
        status={status[connector.id] ?? "idle"}
        saving={savingId === connector.id}
        onSave={() => saveMutation.mutate(connector)}
        onSkip={() => setStatus((s) => ({ ...s, [connector.id]: "skipped" }))}
      />
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect data sources</CardTitle>
        <CardDescription>
          These power what Constellus can actually find and tell you. You can configure or change
          any of them later from Admin → Connectors — nothing here is permanent or required to continue.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {core.length > 0 && (
          <div className="space-y-3">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
              <Zap className="h-3 w-3 text-primary" />
              Core capabilities — results are noticeably thinner without these
            </p>
            <div className="space-y-3">{core.map(renderCard)}</div>
          </div>
        )}
        {optional.length > 0 && (
          <div className="space-y-3">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Optional</p>
            <div className="space-y-3">{optional.map(renderCard)}</div>
          </div>
        )}

        <div className="flex items-center justify-between pt-2">
          <button
            type="button"
            onClick={onContinue}
            className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground transition-colors"
          >
            Skip all for now — I'll configure these later
          </button>
          <Button onClick={onContinue}>
            Continue <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

export default function Setup() {
  const navigate = useNavigate()
  const { setAuth, setTokens } = useAuthStore()
  const [step, setStep] = useState(0)
  const [form, setForm] = useState({ full_name: "", email: "", password: "", confirm: "" })
  const [loading, setLoading] = useState(false)

  function update(field: string, value: string) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  async function createAccount() {
    if (form.password !== form.confirm) {
      toast.error("Passwords do not match")
      return
    }
    if (form.password.length < 8) {
      toast.error("Password must be at least 8 characters")
      return
    }
    setLoading(true)
    try {
      await api.post<User>("/auth/setup", {
        full_name: form.full_name,
        email: form.email,
        password: form.password,
      })
      const tokens = await api.post<TokenResponse>("/auth/login", {
        email: form.email,
        password: form.password,
      })
      setTokens(tokens)
      const user = await api.get<User>("/auth/me")
      setAuth(user, tokens)
      setStep(2)
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Setup failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <header className="flex items-center justify-between px-6 py-4">
        <Logo />
        <ThemeToggle />
      </header>

      <div className="flex flex-1 items-center justify-center p-6">
        <div className="w-full max-w-md space-y-6">
          {/* Step indicator */}
          <div className="space-y-3">
            <Progress value={((step + 1) / STEPS.length) * 100} className="h-1.5" />
            <div className="flex justify-between text-xs text-muted-foreground">
              {STEPS.map((s, i) => (
                <span key={s} className={cn(i <= step && "text-primary font-medium")}>{s}</span>
              ))}
            </div>
          </div>

          {/* Step 0: Welcome */}
          {step === 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-2xl">Welcome to Constellus</CardTitle>
                <CardDescription>
                  Let's get you set up. This wizard creates your first admin account. You'll
                  configure connectors, SSO, and secrets from the admin portal afterward.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="rounded-lg border bg-muted/50 p-4 space-y-2 text-sm text-muted-foreground">
                  <p className="font-medium text-foreground">What you'll need:</p>
                  <ul className="space-y-1 list-disc list-inside">
                    <li>An admin email address and password</li>
                    <li>A running PostgreSQL + TimescaleDB database</li>
                    <li>Connector credentials (configured after setup)</li>
                  </ul>
                </div>
                <Button className="w-full" onClick={() => setStep(1)}>
                  Get started <ChevronRight className="h-4 w-4" />
                </Button>
              </CardContent>
            </Card>
          )}

          {/* Step 1: Admin account */}
          {step === 1 && (
            <Card>
              <CardHeader>
                <CardTitle>Create your admin account</CardTitle>
                <CardDescription>
                  This is the first and only account with full admin access. You can invite other
                  users from the admin portal.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form
                  className="space-y-4"
                  onSubmit={(e) => {
                    e.preventDefault()
                    createAccount()
                  }}
                >
                  <div className="space-y-2">
                    <Label htmlFor="full_name">Full name</Label>
                    <Input
                      id="full_name"
                      placeholder="Jane Smith"
                      value={form.full_name}
                      onChange={(e) => update("full_name", e.target.value)}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="email">Email</Label>
                    <Input
                      id="email"
                      type="email"
                      placeholder="admin@example.com"
                      value={form.email}
                      onChange={(e) => update("email", e.target.value)}
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="password">Password</Label>
                    <Input
                      id="password"
                      type="password"
                      value={form.password}
                      onChange={(e) => update("password", e.target.value)}
                      required
                      minLength={8}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="confirm">Confirm password</Label>
                    <Input
                      id="confirm"
                      type="password"
                      value={form.confirm}
                      onChange={(e) => update("confirm", e.target.value)}
                      required
                    />
                  </div>
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? "Creating account…" : "Create account"}
                  </Button>
                </form>
              </CardContent>
            </Card>
          )}

          {/* Step 2: Connect data sources */}
          {step === 2 && <ConnectSourcesStep onContinue={() => setStep(3)} />}

          {/* Step 3: Done */}
          {step === 3 && (
            <Card>
              <CardHeader className="items-center text-center">
                <CheckCircle2 className="h-12 w-12 text-emerald-500 mb-2" />
                <CardTitle className="text-2xl">You're all set</CardTitle>
                <CardDescription>
                  Your admin account is created and you're signed in. Head to the dashboard to
                  start configuring Constellus.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Button className="w-full" onClick={() => navigate("/admin/connectors")}>
                  Configure connectors
                </Button>
                <Button variant="outline" className="w-full" onClick={() => navigate("/dashboard")}>
                  Go to dashboard
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
