/// <reference types="vite/client" />

// `punycode` (the userland package, browser-safe) ships no types. We only use
// toUnicode/toASCII for IDN apex display — declare the minimal surface here
// rather than pulling in @types/punycode for two functions.
declare module "punycode" {
  export function toUnicode(domain: string): string
  export function toASCII(domain: string): string
}
