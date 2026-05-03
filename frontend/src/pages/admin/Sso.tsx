import { useEffect, useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ExternalLink, RefreshCw, Loader2, CheckCircle2, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Switch } from "@/components/ui/switch"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type SamlConfig, type IdpMetadataPreview } from "@/lib/api"

export default function Sso() {
  const qc = useQueryClient()
  const [metadataUrl, setMetadataUrl] = useState("")
  const [preview, setPreview] = useState<IdpMetadataPreview | null>(null)
  const [spEntityId, setSpEntityId] = useState("")
  const [spAcsUrl, setSpAcsUrl] = useState("")
  const [jitProvisioning, setJitProvisioning] = useState(true)
  const [localFallback, setLocalFallback] = useState(true)

  const { data: config, isLoading } = useQuery({
    queryKey: ["saml-config"],
    queryFn: () => api.get<SamlConfig>("/auth/saml/config").catch(() => null),
  })

  // Sync form when config loads
  useEffect(() => {
    if (config) {
      setMetadataUrl(config.metadata_url)
      setSpEntityId(config.sp_entity_id)
      setSpAcsUrl(config.sp_acs_url)
      setJitProvisioning(config.jit_provisioning)
      setLocalFallback(config.allow_local_fallback)
    }
  }, [config])

  const previewMutation = useMutation({
    mutationFn: () =>
      api.get<IdpMetadataPreview>(
        `/auth/saml/config/preview-metadata?metadata_url=${encodeURIComponent(metadataUrl)}`
      ),
    onSuccess: (r) => setPreview(r),
    onError: () => toast.error("Failed to fetch metadata"),
  })

  const saveMutation = useMutation({
    mutationFn: () => {
      const payload = {
        metadata_url: metadataUrl,
        sp_entity_id: spEntityId,
        sp_acs_url: spAcsUrl,
        jit_provisioning: jitProvisioning,
        allow_local_fallback: localFallback,
      }
      return config
        ? api.patch<SamlConfig>("/auth/saml/config", payload)
        : api.post<SamlConfig>("/auth/saml/config", payload)
    },
    onSuccess: () => {
      toast.success("SSO configuration saved")
      qc.invalidateQueries({ queryKey: ["saml-config"] })
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) => api.patch("/auth/saml/config", { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saml-config"] }),
    onError: () => toast.error("Failed to update SSO status"),
  })

  const refreshMutation = useMutation({
    mutationFn: () => api.post("/auth/saml/config/refresh-metadata"),
    onSuccess: () => {
      toast.success("Metadata refreshed")
      qc.invalidateQueries({ queryKey: ["saml-config"] })
    },
    onError: () => toast.error("Failed to refresh metadata"),
  })

  if (isLoading) {
    return (
      <div className="p-6 max-w-2xl mx-auto space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">SAML SSO</h1>
          <p className="text-sm text-muted-foreground mt-1">Configure single sign-on via SAML 2.0</p>
        </div>
        {config && (
          <div className="flex items-center gap-3">
            <span className="text-sm text-muted-foreground">{config.enabled ? "Enabled" : "Disabled"}</span>
            <Switch
              checked={config.enabled}
              onCheckedChange={(v) => toggleMutation.mutate(v)}
              disabled={toggleMutation.isPending}
            />
          </div>
        )}
      </div>

      {/* IdP Metadata */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Identity Provider</CardTitle>
          <CardDescription>Enter your IdP metadata URL. Sextant fetches and caches the XML.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Metadata URL</Label>
            <div className="flex gap-2">
              <Input
                value={metadataUrl}
                onChange={(e) => {
                  setMetadataUrl(e.target.value)
                  setPreview(null)
                }}
                placeholder="https://your-idp.example.com/metadata"
                className="flex-1"
              />
              <Button
                variant="outline"
                onClick={() => previewMutation.mutate()}
                disabled={!metadataUrl || previewMutation.isPending}
              >
                {previewMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Preview"}
              </Button>
            </div>
          </div>

          {preview && (
            <div
              className={`rounded-lg border p-4 text-sm space-y-2 ${
                preview.valid
                  ? "border-emerald-500/30 bg-emerald-500/5"
                  : "border-destructive/30 bg-destructive/5"
              }`}
            >
              <div className="flex items-center gap-2 font-medium">
                {preview.valid ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                ) : (
                  <XCircle className="h-4 w-4 text-destructive" />
                )}
                {preview.valid ? "Metadata valid" : "Metadata invalid"}
              </div>
              {preview.valid && (
                <>
                  <p className="text-muted-foreground">
                    Entity ID:{" "}
                    <span className="text-foreground font-mono text-xs">{preview.entity_id}</span>
                  </p>
                  <p className="text-muted-foreground">
                    SSO URL:{" "}
                    <span className="text-foreground font-mono text-xs break-all">{preview.sso_url}</span>
                  </p>
                  {preview.certificate_subject && (
                    <Badge variant="success">{preview.certificate_subject}</Badge>
                  )}
                </>
              )}
              {preview.error && <p className="text-destructive">{preview.error}</p>}
            </div>
          )}

          {config?.metadata_fetched_at && (
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>Cached: {new Date(config.metadata_fetched_at).toLocaleString()}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => refreshMutation.mutate()}
                disabled={refreshMutation.isPending}
              >
                <RefreshCw className="h-3 w-3" />
                Refresh metadata
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* SP Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Service Provider</CardTitle>
          <CardDescription>Configure how Sextant identifies itself to your IdP.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>SP Entity ID</Label>
            <Input
              value={spEntityId}
              onChange={(e) => setSpEntityId(e.target.value)}
              placeholder="https://sextant.example.com"
            />
          </div>
          <div className="space-y-2">
            <Label>Assertion Consumer Service URL</Label>
            <Input
              value={spAcsUrl}
              onChange={(e) => setSpAcsUrl(e.target.value)}
              placeholder="https://sextant.example.com/api/auth/saml/acs"
            />
            <p className="text-xs text-muted-foreground flex items-center gap-1">
              <ExternalLink className="h-3 w-3" /> Register this URL in your IdP
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Options */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Options</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <p className="text-sm font-medium">JIT provisioning</p>
              <p className="text-xs text-muted-foreground">Auto-create accounts for new SSO users (Viewer role)</p>
            </div>
            <Switch checked={jitProvisioning} onCheckedChange={setJitProvisioning} />
          </div>
          <Separator />
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <p className="text-sm font-medium">Allow local fallback</p>
              <p className="text-xs text-muted-foreground">Keep password login available during SSO rollout</p>
            </div>
            <Switch checked={localFallback} onCheckedChange={setLocalFallback} />
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button
          onClick={() => saveMutation.mutate()}
          disabled={saveMutation.isPending || !metadataUrl || !spEntityId || !spAcsUrl}
        >
          {saveMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
          {config ? "Save changes" : "Enable SSO"}
        </Button>
      </div>
    </div>
  )
}
