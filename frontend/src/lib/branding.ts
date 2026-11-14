export type OrgBranding = {
  org_name: string
  org_logo_url: string | null
  org_brand_accent: string
  org_name_color: string | null
}

export const BRANDING_DEFAULTS: OrgBranding = {
  org_name: "Constellus",
  org_logo_url: null,
  org_brand_accent: "#66d0df",
  org_name_color: null,
}

// Curated, not a picker: all OKLCH L 0.80 / C 0.10 at hues 40 degrees or more from every
// severity hue (Lime is the one named exception, at 37); the backend allowlist in
// api/settings.py holds the same four and a backend test keeps them equal.
export const ACCENT_PALETTE: { name: string; value: string }[] = [
  { name: "Cyan",   value: "#66d0df" },
  { name: "Lime",   value: "#aeca82" },
  { name: "Violet", value: "#c7aff5" },
  { name: "Pink",   value: "#e3a6dc" },
]

function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex)
  return m
    ? { r: parseInt(m[1], 16), g: parseInt(m[2], 16), b: parseInt(m[3], 16) }
    : null
}

/** Move each channel `amount` (0..1) of the way toward white; returns a 6-digit lowercase hex. */
function lighten(rgb: { r: number; g: number; b: number }, amount: number): string {
  const hex = [rgb.r, rgb.g, rgb.b]
    .map((c) => Math.round(c + (255 - c) * amount).toString(16).padStart(2, "0"))
    .join("")
  return `#${hex}`
}

/**
 * Apply org branding as CSS var overrides on :root. Safe to call multiple times.
 * Sets --brand, --brand-dim, --logo-glow, --link, --primary, --ring and --org-name-color.
 * --primary-foreground is deliberately static in CSS: every curated accent is L 0.80,
 * so one dark foreground serves all of them.
 */
export function applyBranding(b: OrgBranding): void {
  const rgb = hexToRgb(b.org_brand_accent)
  if (!rgb) return
  const root = document.documentElement
  root.style.setProperty("--brand", b.org_brand_accent)
  root.style.setProperty("--brand-dim", `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.1)`)
  root.style.setProperty("--logo-glow", lighten(rgb, 0.4))
  root.style.setProperty("--link", lighten(rgb, 0.15))
  // Shadcn --primary and --ring follow the brand accent so buttons/focus rings stay on-brand
  root.style.setProperty("--primary", b.org_brand_accent)
  root.style.setProperty("--ring", b.org_brand_accent)
  // Org name colour — falls back to brand accent when not set
  root.style.setProperty("--org-name-color", b.org_name_color || b.org_brand_accent)
}
