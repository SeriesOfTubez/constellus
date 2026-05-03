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
          <linearGradient id="logo-g" x1="24" y1="4" x2="24" y2="44" gradientUnits="userSpaceOnUse">
            <stop stopColor="#60a5fa" />
            <stop offset="1" stopColor="#06b6d4" />
          </linearGradient>
        </defs>
        <line x1="24" y1="9" x2="8" y2="40" stroke="url(#logo-g)" strokeWidth="2.5" strokeLinecap="round" />
        <line x1="24" y1="9" x2="40" y2="40" stroke="url(#logo-g)" strokeWidth="2.5" strokeLinecap="round" />
        <path d="M8 40 Q24 47 40 40" stroke="url(#logo-g)" strokeWidth="2.5" strokeLinecap="round" fill="none" />
        <line x1="24" y1="9" x2="32" y2="37" stroke="url(#logo-g)" strokeWidth="1.5" strokeLinecap="round" opacity="0.75" />
        <circle cx="24" cy="9" r="3" fill="url(#logo-g)" />
      </svg>
      {showWordmark && (
        <span className="text-lg font-bold tracking-tight bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
          Sextant
        </span>
      )}
    </div>
  )
}
