# Contributing to Constellus

## About this project

Constellus is designed and maintained by a security practitioner with experience across security engineering, network security, DevOps, AppSec, and security architecture.

**This project uses AI-assisted development.** The implementation is written with [Claude](https://claude.ai) (Anthropic) as a coding assistant. The architecture decisions, security requirements, threat model, connector design, and domain logic are authored by the human maintainer. Claude translates those requirements into working code, accelerating development while keeping the security practitioner in control of every design decision.

This is disclosed openly because:

- Transparency is a core principle of this project
- AI-generated code has different failure modes than human-written code and reviewers deserve to know
- The security community should be able to make an informed decision about whether to trust or contribute to this codebase

What this means for contributors: the same scrutiny you would apply to any code applies here. The security pipeline is non-negotiable, code review matters, and domain expertise is valued more than volume.

---

## Development principles

### Security first
- No feature ships without passing the full security pipeline (Gitleaks, Semgrep, Trivy, Checkov, Hadolint)
- HIGH and CRITICAL findings block merges — no exceptions
- Dependencies must be actively maintained. Unmaintained libraries are replaced, not patched around
- Secrets never touch the codebase. `.env` is gitignored; the pre-commit hook catches violations

### Actively maintained dependencies only
Before adding a dependency, verify:
- Last release within 12 months
- Repository is not archived
- No open CVEs without an upstream fix
- Transitive dependencies are not pinned to EOL versions

An unmaintained dependency that blocks security fixes will be replaced outright, not worked around.

### Honest about what's built
The README and documentation reflect the current state of the software, not the roadmap. Features listed as "Planned" are not implemented. Features listed as "Built" work today.

### No security theatre
Every security control exists because it catches real things or prevents real incidents — not for compliance checkbox purposes. Controls that create noise without value get removed.

### Transaction ownership
SQLAlchemy sessions have one owner and one boundary. Decided in planning#163,
because it had never been decided and that ambiguity was its own bug class.

1. **The session's owner commits; helpers flush.** Whoever opened the session —
   `get_db` for a request, `SessionLocal()` in a background job — owns the
   boundary. A service handed a `Session` it did not open calls `db.flush()` to
   make its writes visible inside the transaction, never `db.commit()`.
2. **Every `except` that intends to continue must `db.rollback()` first.**
   SQLAlchemy does not auto-rollback a failed flush/execute. A handler that logs
   and carries on without rolling back leaves the transaction aborted, so the
   *next* unrelated statement raises `PendingRollbackError` — and the failure
   surfaces far from its cause, typically inside the handler meant to record it.
3. **A fail-soft step is its own unit of work.** Where one step may fail without
   failing the whole job, each step gets
   `try: step(); db.commit()` / `except: db.rollback(); record()`. Without the
   explicit commit, a step that writes but does not commit has its work silently
   discarded by the *next* step's rollback.

Migration is incomplete and new instances should not be added: several analyzer
helpers still commit sessions they do not own, and `core/logging.py`'s
`DBLogHandler` commits once per log record in the scan hot path.

---

## Getting started

```bash
git clone https://github.com/SeriesOfTubez/constellus.git
cd constellus
cp .env.example .env  # set SECRET_KEY at minimum: openssl rand -hex 32
pre-commit install    # required — activates secret scanning and Dockerfile linting on commit
docker compose up -d
```

See the [Quick Start](https://constellus.readthedocs.io/en/latest/getting-started/quickstart/) for the full setup.

---

## Before opening a PR

- Run `pre-commit run --all-files` and resolve any findings
- Ensure your changes are reflected in the docs if they affect user-visible behaviour
- For significant changes, open an issue first to discuss the approach

## Security pipeline

All PRs run automatically:

| Check | Tool | Blocks merge |
|---|---|---|
| Secret scanning | Gitleaks | Yes |
| SAST | Semgrep | Yes (HIGH/CRITICAL) |
| Dependency CVEs | Trivy | Yes (HIGH/CRITICAL, fixed only) |
| IaC | Checkov | Yes |
| Dockerfile | Hadolint | Yes |
| Image CVE scan | Trivy | Yes (HIGH/CRITICAL, fixed only) |

## SBOM

A Software Bill of Materials (CycloneDX format) is generated on every CI run and attached as a workflow artifact. This covers both the source dependency tree and the built container image.

---

## Responsible disclosure

To report a security vulnerability, please open a [GitHub Security Advisory](https://github.com/SeriesOfTubez/constellus/security/advisories/new) rather than a public issue. Do not include exploit details in public issues.
