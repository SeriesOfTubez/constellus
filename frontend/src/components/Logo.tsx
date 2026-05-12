import { cn } from "@/lib/utils"

interface LogoProps {
  className?: string
  showWordmark?: boolean
}

export function Logo({ className, showWordmark = true }: LogoProps) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" className="h-8 w-8 shrink-0">
        <defs>
          <linearGradient id="logo-g" x1="8" y1="4" x2="40" y2="44" gradientUnits="userSpaceOnUse">
            <stop stopColor="#60a5fa" />
            <stop offset="1" stopColor="#06b6d4" />
          </linearGradient>
        </defs>

        {/* Spokes to center — varying lengths make distances obvious */}
        <line x1="14" y1="5"  x2="24" y2="26" stroke="url(#logo-g)" strokeWidth="1.3" strokeLinecap="round" opacity="0.65" />
        <line x1="33" y1="6"  x2="24" y2="26" stroke="url(#logo-g)" strokeWidth="1.3" strokeLinecap="round" opacity="0.65" />
        <line x1="44" y1="17" x2="24" y2="26" stroke="url(#logo-g)" strokeWidth="1.3" strokeLinecap="round" opacity="0.65" />
        <line x1="43" y1="35" x2="24" y2="26" stroke="url(#logo-g)" strokeWidth="1.3" strokeLinecap="round" opacity="0.65" />
        <line x1="27" y1="42" x2="24" y2="26" stroke="url(#logo-g)" strokeWidth="1.3" strokeLinecap="round" opacity="0.65" />
        <line x1="8"  y1="37" x2="24" y2="26" stroke="url(#logo-g)" strokeWidth="1.3" strokeLinecap="round" opacity="0.65" />
        <line x1="6"  y1="18" x2="24" y2="26" stroke="url(#logo-g)" strokeWidth="1.3" strokeLinecap="round" opacity="0.65" />

        {/* Outer nodes — deliberately different distances from center */}
        <circle cx="14" cy="5"  r="2.4" fill="url(#logo-g)" />                  {/* far, upper-left */}
        <circle cx="33" cy="6"  r="1.8" fill="url(#logo-g)" opacity="0.85" />   {/* far, upper-right */}
        <circle cx="44" cy="17" r="2"   fill="url(#logo-g)" opacity="0.9" />    {/* medium-far, right */}
        <circle cx="43" cy="35" r="1.5" fill="url(#logo-g)" opacity="0.75" />   {/* medium, lower-right */}
        <circle cx="27" cy="42" r="2.2" fill="url(#logo-g)" opacity="0.9" />    {/* close, bottom */}
        <circle cx="8"  cy="37" r="1.6" fill="url(#logo-g)" opacity="0.8" />    {/* medium, lower-left */}
        <circle cx="6"  cy="18" r="2"   fill="url(#logo-g)" opacity="0.85" />   {/* medium-far, left */}

        {/* Central hub — brightest, largest */}
        <circle cx="24" cy="26" r="3.5" fill="url(#logo-g)" />
      </svg>
      {showWordmark && (
        <span className="text-lg font-bold tracking-tight bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
          Constellus
        </span>
      )}
    </div>
  )
}
