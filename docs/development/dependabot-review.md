# Reviewing Dependabot PRs

Dependabot opens PRs weekly (Mondays) across the ecosystems configured in
[`.github/dependabot.yml`](https://github.com/SeriesOfTubez/constellus/blob/dev/.github/dependabot.yml):
pip (`/backend`), npm (`/frontend`), GitHub Actions (`/`), and Docker base images
(`/backend`, `/frontend`). All target the `dev` branch and use cooldown windows
(3/5/60 days for patch/minor/major on pip and npm; a flat 7-day cooldown
elsewhere) so a freshly-published version has to sit for a bit before Dependabot
opens a PR for it.

Review is split in two tiers, by semver bump size.

## Patch & minor — automatic

[`.github/workflows/dependabot-automerge.yml`](https://github.com/SeriesOfTubez/constellus/blob/dev/.github/workflows/dependabot-automerge.yml)
runs on every `pull_request` event where the actor is `dependabot[bot]`. It reads
the update type via `dependabot/fetch-metadata`, and for
`version-update:semver-patch` or `version-update:semver-minor`, runs:

```bash
gh pr merge --auto --squash <pr-url>
```

`--auto` queues the merge but doesn't force it — GitHub still requires the
branch-protection required checks (Security Scan, Build & Image Scan, Frontend
Typecheck, etc.) to pass first. No human or AI review happens for these; the
CI gate is the only safety net, which is fine for patch/minor bumps.

## Major version bumps — Claude Code Routine

Major bumps are deliberately excluded from auto-merge — a breaking change needs
judgment about whether this codebase actually hits the changed surface. That
judgment is delegated to a scheduled **Claude Code Routine** (claude.ai/code —
distinct from a GitHub Actions workflow; it runs as a Claude agent, not CI).

| | |
|---|---|
| Name | `Constellus: review major Dependabot updates` |
| Trigger ID | `trig_01DySPvazarsZa3gHTX7N7MS` |
| Schedule | Daily, `0 12 * * *` (12:00 UTC) |
| Model | `claude-opus-5` |
| Tools granted | `Bash`, `Read`, `Grep`, `Glob` — **no `Write`/`Edit`** |
| Source | `github.com/SeriesOfTubez/constellus` |

The no-`Write`/`Edit` restriction is intentional: the routine can inspect the
repo and act on GitHub via `gh`, but it can never modify code directly.

**What it does each run:**

1. Lists open PRs authored by `dependabot[bot]` (`gh pr list --author "app/dependabot"`).
2. Classifies each by parsing the leading version component out of the PR
   title. Patch/minor bumps are skipped entirely — that's the auto-merge
   workflow's job, and the routine is told not to touch or comment on them.
3. For each **major** bump:
   - Reads the PR body (Dependabot embeds release notes/changelog/commit list).
   - Checks CI via `gh pr checks` against three required checks: **Security
     Scan**, **Build & Image Scan**, **Frontend Typecheck**. If any are
     failing or pending, it leaves a short "waiting on CI" comment and stops —
     no approve, no merge, tries again next run.
   - Greps the actual codebase for how the bumped package is used (imports,
     API calls, config keys), and cross-references that against the specific
     breaking changes called out in the changelog.
4. **Decides MERGE only with high confidence** the breaking changes don't
   touch how this codebase uses the package, and all three checks are green —
   then leaves an approving review explaining why, and merges with
   `gh pr merge --auto --squash` (still `--auto`, so GitHub's required-check
   gate remains the final backstop even after the routine's own judgment call).
5. **Otherwise HOLDs** — including "changelog is vague," "can't find a
   changelog," or any other genuine uncertainty — and leaves a comment for a
   human explaining specifically what's uncertain. No approval, no merge.
   Missing a same-day merge costs nothing; a bad major-version merge into
   `dev` is a real risk, so the routine is instructed to default to holding.
6. Checks existing PR comments before adding a new one, so a PR already on
   HOLD doesn't get re-commented every day unless something material changed.

**Scope discipline:** only open, `dependabot[bot]`-authored, major-version PRs.
Never patch/minor (already automated), never non-Dependabot PRs or issues.

### Inspecting or changing the routine

The routine's full prompt lives in the trigger config on claude.ai, not in
this repo. To view recent runs or edit the prompt/schedule, go to
[claude.ai/code](https://claude.ai/code) → Routines, or use the
`RemoteTrigger` API (`get`, `list_runs`, `get_run_log`, `update`) from a
Claude Code session with trigger ID `trig_01DySPvazarsZa3gHTX7N7MS`.

### Known gap — ecosystem coverage

The routine's own background text describes pip coverage for `/backend`,
`/docs`, and `/scanner-worker`. `dependabot.yml` currently only defines a pip
ecosystem for `/backend`. Both `docs/requirements.txt` and
`scanner-worker/requirements.txt` exist but aren't tracked by Dependabot at
all yet — add `pip` entries for those two directories in `dependabot.yml`
(matching the `/backend` cooldown config), or correct the routine's prompt if
that coverage isn't actually wanted.
