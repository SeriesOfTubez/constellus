"""Backend test package.

## This suite refuses to run against a non-test database

Importing anything under `app.tests` fails unless `DATABASE_URL` names a
database whose name ends in `_test`. The check lives here, in the package
`__init__`, rather than in `conftest.py` because there are **two** ways into
this suite and `conftest.py` only covers one of them:

  - `pytest app/tests/...`            — loads conftest.py
  - `python -m app.tests.<module>`    — does NOT load conftest.py

Most test files in this suite are directly runnable that way (see each file's
own docstring), so a guard in `conftest.py` alone would leave the second door
open. Both import the package, so this is the one chokepoint that covers both.

## Why this is enforced rather than written in a README

Until 2026-09-20 this suite ran against the **development** database, and the
lineage planning#163 / #188 / #189 / #191 / #193 / #199 is that single fact
wearing six different hats: mutation of real rows, invisible read dependencies,
rows no cleanup could structurally reach, rows no cleanup ever existed for,
leaked targets, and cross-file address collisions made non-deterministic by
accumulated residue. One of them (#189) produced a wrong statistic — "87% of
decisions die at scope:unresolved_asset" — that steered the roadmap through
three hand-offs before anyone re-ran the query behind it.

The committed cleanups were never the problem. A full run against a freshly
migrated database leaves **zero** rows behind in every table (verified
2026-09-20, 604 tests). The residue came from development iterations and failed
runs accumulating in a database that was never thrown away. So the fix is not
better cleanups; it is a database that does not survive the run.

## How the database is chosen

`settings.database_url` is the EFFECTIVE value: `app.core.env` loads the
repo-root `.env` with `override=False`, so a real environment variable wins
over the file. Pointing `DATABASE_URL` at a `_test` database is therefore all
it takes — which is what `backend/scripts/test.ps1` / `test.sh` do (recreating
and migrating it first), and what CI does via its throwaway service container.
"""

from urllib.parse import urlparse

from app.core.config import settings

_DB_NAME = urlparse(settings.database_url).path.lstrip("/")

if not _DB_NAME.endswith("_test"):
    raise RuntimeError(
        f"Refusing to run the test suite against database {_DB_NAME!r}.\n"
        "\n"
        "This suite creates, mutates and deletes rows in whatever database it is\n"
        "pointed at, and it is only safe against a disposable one. The database\n"
        "name must end in '_test'.\n"
        "\n"
        "Run the suite with:\n"
        "    backend/scripts/test.ps1        (PowerShell)\n"
        "    backend/scripts/test.sh         (bash)\n"
        "\n"
        "Those recreate and migrate a throwaway database first. To point somewhere\n"
        "else yourself, export DATABASE_URL before invoking pytest or a test module.\n"
        "See this file's docstring for why this is enforced rather than documented."
    )
