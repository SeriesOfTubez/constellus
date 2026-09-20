# Run the backend test suite against a throwaway database.
#
# The suite mutates and deletes rows in whatever database it is pointed at, so
# it runs against a disposable one that is recreated from scratch every time.
# `app/tests/__init__.py` enforces that with a hard failure if the database
# name does not end in `_test` — see its header for the six-issue history that
# rule exists to close.
#
# Recreating is cheap: all migrations from empty take ~5s, and the full suite
# ~40s. There is deliberately no "reuse the database if it exists" flag — that
# option is how residue accumulated in the first place.
#
# Any arguments are passed through to pytest:
#     .\scripts\test.ps1
#     .\scripts\test.ps1 app/tests/test_probe_authorisation.py -x
#
# Note: this repo runs Windows PowerShell 5.1, so no `&&`, no ternary, and
# native-exe stderr is NOT redirected (2>&1 on a native command wraps each line
# in an ErrorRecord and falsifies $?).

# Deliberately NOT `Stop`. Windows PowerShell 5.1 wraps every stderr line from
# a native executable in an ErrorRecord (NativeCommandError); under `Stop` that
# becomes a terminating error even when the process exited 0. alembic logs its
# INFO lines to stderr, so `Stop` here fails the run on a perfectly successful
# migration. Correctness is kept by checking $LASTEXITCODE after each native
# call instead, which is the actual exit status rather than a guess at it.
$ErrorActionPreference = "Continue"

$DbName = if ($env:CONSTELLUS_TEST_DB) { $env:CONSTELLUS_TEST_DB } else { "constellus_test" }
$DbUser = if ($env:CONSTELLUS_DB_USER) { $env:CONSTELLUS_DB_USER } else { "constellus" }
$DbPass = if ($env:CONSTELLUS_DB_PASSWORD) { $env:CONSTELLUS_DB_PASSWORD } else { "constellus" }
$DbHost = if ($env:CONSTELLUS_DB_HOST) { $env:CONSTELLUS_DB_HOST } else { "localhost" }
$DbPort = if ($env:CONSTELLUS_DB_PORT) { $env:CONSTELLUS_DB_PORT } else { "5432" }

$BackendDir = Split-Path -Parent $PSScriptRoot
# Prefer the repo venv over whatever `python` is on PATH. The backend container
# cannot run pytest at all — its runtime image uninstalls pip and carries no dev
# dependencies — so the venv is the only local interpreter that has them.
$Py = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { $Py = "python" }
$RepoRoot = Split-Path -Parent $BackendDir
Set-Location $BackendDir

Write-Host "==> Recreating $DbName"
# WITH (FORCE) terminates lingering connections (PG13+; the stack is PG18).
# Without it a stray psql session from a previous debugging run blocks the drop.
docker compose -f "$RepoRoot\docker-compose.yml" exec -T db `
    psql -U $DbUser -d postgres `
    -c "DROP DATABASE IF EXISTS $DbName WITH (FORCE);" `
    -c "CREATE DATABASE $DbName OWNER $DbUser;" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to recreate $DbName (is the db container up?)" }

$env:DATABASE_URL = "postgresql://${DbUser}:${DbPass}@${DbHost}:${DbPort}/${DbName}"

Write-Host "==> Migrating"
& $Py -m alembic upgrade head | Out-Null
if ($LASTEXITCODE -ne 0) { throw "alembic upgrade head failed" }

Write-Host "==> Running pytest against $DbName"
if ($args.Count -gt 0) {
    & $Py -m pytest @args -q
} else {
    & $Py -m pytest app/tests -q
}
exit $LASTEXITCODE
