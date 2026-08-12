// Impact-framed copy for "core" connectors — surfaced as a badge tooltip in
// Admin → Connectors and as cards in the first-run setup wizard. Two lengths:
// `short` for card/badge real estate, `long` for tooltip expansion / docs.
// Keyed by connector id (matches REGISTRY keys in backend/app/api/connectors.py).
export const CORE_IMPACT_COPY: Record<string, { short: string; long: string }> = {
  naabu: {
    short: "No live port data — you'll only see what Shodan and DNS already guessed.",
    long:
      "Without an active port scanner, Constellus only reports what passive sources " +
      "(Shodan, certs, DNS) already knew — no live view of what's actually open on " +
      "your assets right now, and the Open Ports panel stays empty.",
  },
  nuclei: {
    short: "No CVEs, no misconfig checks, no exposed panels — Findings stays nearly empty.",
    long:
      "Without active scanning, Constellus can't detect CVEs, exposed panels, default " +
      "credentials, or misconfigurations — you'll only see what passive enrichment " +
      "infers from banners. The Findings page stays mostly empty.",
  },
  banner_grab: {
    short: "No service versions — EOL detection and severity tuning fall back to generic guesses.",
    long:
      "Without service-version banners, EOL detection and exposure severity-tuning " +
      "can't run — e.g. Constellus can't tell a hardened SFTP-only SSH server from a " +
      "risky default config, and falls back to generic severities.",
  },
  vulncheck: {
    short: "No CVSS/EPSS/KEV context — the Risk Score and Trajectory verdicts can't run.",
    long:
      "Without a vulnerability-intelligence source, CVEs won't carry CVSS/EPSS/KEV " +
      "context, and the Constellus Risk Score and Trajectory verdicts can't compute — " +
      "you'll see raw findings with no prioritization.",
  },
}
