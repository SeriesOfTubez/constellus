import { createContext, useContext, useEffect } from "react"
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"
import { applyBranding, BRANDING_DEFAULTS, type OrgBranding } from "@/lib/branding"

const BrandingContext = createContext<OrgBranding>(BRANDING_DEFAULTS)

export function BrandingProvider({ children }: { children: React.ReactNode }) {
  const { data } = useQuery({
    queryKey: ["org-branding"],
    queryFn: () => api.get<OrgBranding>("/settings/branding"),
    staleTime: 5 * 60 * 1000,
  })

  useEffect(() => {
    applyBranding(data ?? BRANDING_DEFAULTS)
  }, [data])

  return (
    <BrandingContext.Provider value={data ?? BRANDING_DEFAULTS}>
      {children}
    </BrandingContext.Provider>
  )
}

export const useBranding = () => useContext(BrandingContext)
