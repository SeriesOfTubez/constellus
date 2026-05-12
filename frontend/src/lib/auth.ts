import { create } from "zustand"
import { persist } from "zustand/middleware"
import type { User, TokenResponse } from "@/lib/api"

interface AuthState {
  user: User | null
  tokens: TokenResponse | null
  setAuth: (user: User, tokens: TokenResponse) => void
  setTokens: (tokens: TokenResponse) => void
  clearAuth: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      tokens: null,
      setAuth: (user, tokens) => set({ user, tokens }),
      setTokens: (tokens) => set((s) => ({ ...s, tokens })),
      clearAuth: () => set({ user: null, tokens: null }),
    }),
    { name: "constellus-auth" }
  )
)
