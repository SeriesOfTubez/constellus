import { useState } from "react"
import { useNavigate } from "react-router-dom"
import { toast } from "sonner"
import { Logo } from "@/components/Logo"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { api, ApiError, type User, type TokenResponse } from "@/lib/api"
import { useAuthStore } from "@/lib/auth"
import { useBranding } from "@/lib/branding-context"

export default function Login() {
  const navigate = useNavigate()
  const { setAuth, setTokens } = useAuthStore()
  const { org_name } = useBranding()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      const tokens = await api.post<TokenResponse>("/auth/login", { email, password })
      setTokens(tokens)
      const user = await api.get<User>("/auth/me")
      setAuth(user, tokens)
      navigate("/dashboard")
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Login failed")
    } finally {
      setLoading(false)
    }
  }

  const isCustomOrg = org_name !== "Constellus"

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <div className="flex flex-1 flex-col items-center justify-center p-6 gap-6">
        {/* Org branding — shown above the card when a custom org is configured */}
        {isCustomOrg && (
          <div className="flex flex-col items-center gap-3">
            <Logo showWordmark={false} className="[&_img]:h-12 [&_svg]:h-12 [&_svg]:w-12" />
            <span className="text-xl font-semibold">{org_name}</span>
          </div>
        )}

        <Card className="w-full max-w-sm">
          <CardHeader className="text-center">
            {!isCustomOrg && (
              <div className="flex justify-center mb-2">
                <Logo />
              </div>
            )}
            <CardTitle className="text-2xl">Welcome back</CardTitle>
            <CardDescription>
              Sign in to {isCustomOrg ? `${org_name}'s` : "your"} Constellus account
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="admin@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  autoComplete="email"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete="current-password"
                />
              </div>
              <Button type="submit" className="w-full" disabled={loading}>
                {loading ? "Signing in…" : "Sign in"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>

      <footer className="py-4 text-center text-xs text-muted-foreground">
        {isCustomOrg ? (
          <>Powered by <span className="font-medium">Constellus</span></>
        ) : (
          <Logo className="justify-center [&_svg]:h-4 [&_svg]:w-4 [&_span]:text-xs" />
        )}
      </footer>
    </div>
  )
}
