import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { toast } from "sonner"
import { CheckCircle2, ChevronRight } from "lucide-react"
import { Logo } from "@/components/Logo"
import { ThemeToggle } from "@/components/ThemeToggle"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { api, ApiError, type User, type TokenResponse } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { cn } from "@/lib/utils"

const STEPS = ["Welcome", "Admin Account", "Done"]

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

          {/* Step 2: Done */}
          {step === 2 && (
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
