export type OrgBranding = {
  org_name: string
  org_logo_url: string | null
  org_brand_accent: string
  org_name_color: string | null
}

export const BRANDING_DEFAULTS: OrgBranding = {
  org_name: "Constellus",
  org_logo_url: null,
  org_brand_accent: "#8b7bf0",
  org_name_color: null,
}

export const ACCENT_PALETTE: { name: string; value: string }[] = [
  { name: "Violet",  value: "#8b7bf0" },
  { name: "Indigo",  value: "#6366f1" },
  { name: "Purple",  value: "#a855f7" },
  { name: "Fuchsia", value: "#d946ef" },
  { name: "Cyan",    value: "#06b6d4" },
  { name: "Teal",    value: "#14b8a6" },
]

function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return m
    ? { r: parseInt(m[1], 16), g: parseInt(m[2], 16), b: parseInt(m[3], 16) }
    : null
}

/** Apply org branding as CSS var overrides on :root. Safe to call multiple times. */
export function applyBranding(b: OrgBranding): void {
  const rgb = hexToRgb(b.org_brand_accent)
  if (!rgb) return
  const { r, g, b: bv } = rgb
  // Lighten 40% toward white for the logo glow
  const glow = [r, g, bv]
    .map((c) => Math.round(c + (255 - c) * 0.4).toString(16).padStart(2, "0"))
    .join("")

  const root = document.documentElement
  root.style.setProperty("--brand", b.org_brand_accent)
  root.style.setProperty("--brand-dim", `rgba(${r}, ${g}, ${bv}, 0.14)`)
  root.style.setProperty("--logo-glow", `#${glow}`)
  // Shadcn --primary and --ring follow the brand accent so buttons/focus rings stay on-brand
  root.style.setProperty("--primary", b.org_brand_accent)
  root.style.setProperty("--ring", b.org_brand_accent)
  // Org name colour — falls back to brand accent when not set
  root.style.setProperty("--org-name-color", b.org_name_color || b.org_brand_accent)
}
