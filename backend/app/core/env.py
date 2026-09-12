"""Loads the deployment-wide `.env` into the process environment.

Imported for its side effect by both `app.core.config` (which validates the
app's own settings) and `app.core.secrets` (which reads connector
credentials). It is its own module precisely so neither of those has to
import the other, and so the load happens for whichever of them is reached
first — `secrets` is importable without `config`, and a connector that only
needed `get_secret()` used to silently see nothing (planning#157).

Why a dotenv load and not `Settings(env_file=...)`: the repo-root `.env` is
a SHARED file (see `.env.example`). It carries this app's settings AND every
connector credential, and the two are read by different consumers.
pydantic-settings ingests a dotenv file wholesale, and `extra="forbid"` —
its default, deliberately kept — then rejects every key `Settings` does not
itself declare. Loading the file into `os.environ` here instead means
`Settings` validates only what it owns (unknown environment variables are
simply not matched, unlike unknown dotenv keys), while the connector keys
stay visible to `get_secret()`.

This mirrors what docker-compose already does via `env_file: .env`, where
the same keys arrive as real environment variables and `Settings` has never
complained. `override=False` keeps a genuine environment variable winning
over the file, so compose/CI/shell exports stay authoritative.

Trade-off accepted: a typo'd key in `.env` is now silently ignored rather
than raising. That is already true of every deployed path (compose, CI, a
shell export), so this makes local development behave like production
rather than introducing a new blind spot.
"""

from pathlib import Path

from dotenv import load_dotenv

# app/core/env.py -> app/core -> app -> backend -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = _REPO_ROOT / ".env"

load_dotenv(ENV_FILE, override=False)
