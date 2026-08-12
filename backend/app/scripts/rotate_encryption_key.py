"""
One-time connector-config re-encryption (planning#85).

Before this change, the Fernet key that encrypts stored connector
credentials (Shodan/Tenable/Wiz/FortiManager/etc. API keys) was derived as
`sha256(secret_key)` — byte-identical to the JWT signing key. The fix
domain-separates them via `sha256(f"{secret_key}:connector-encryption")`.
That's a different key, so every config encrypted under the old derivation
needs to be decrypted under the old scheme and re-encrypted under the new
one, or it silently "loses" its config (get_decrypted_config swallows
decrypt failures and returns {}).

Idempotent — a row that already decrypts under the new key is left alone.

Lives inside the `app` package because the dev bind mount is
`./backend/app:/app/app` (see reenrich.py for the same note).

Usage (from the backend container):
    docker compose exec backend python -m app.scripts.rotate_encryption_key
    docker compose exec backend python -m app.scripts.rotate_encryption_key --dry-run
"""

import argparse
import logging

from cryptography.fernet import InvalidToken

from app.core.database import SessionLocal
from app.models.connector_config import ConnectorConfig
from app.services.connector_config import _fernet

log = logging.getLogger("rotate_encryption_key")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Re-encrypt stored connector configs under the new domain-separated key.")
    parser.add_argument("--dry-run", action="store_true", help="report what would change without writing")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    new_fernet = _fernet()
    old_fernet = _fernet(context=None)

    db = SessionLocal()
    try:
        rows = db.query(ConnectorConfig).filter(ConnectorConfig.config_encrypted.isnot(None)).all()
        migrated = already_current = failed = 0

        for row in rows:
            token = row.config_encrypted.encode()

            try:
                new_fernet.decrypt(token)
                already_current += 1
                continue
            except InvalidToken:
                pass

            try:
                plaintext = old_fernet.decrypt(token)
            except InvalidToken:
                log.error("Could not decrypt config for connector %r under the old OR new key — "
                          "left untouched, will need manual reconfiguration.", row.connector_id)
                failed += 1
                continue

            if args.dry_run:
                log.info("[dry-run] would migrate connector %r", row.connector_id)
            else:
                row.config_encrypted = new_fernet.encrypt(plaintext).decode()
            migrated += 1

        if not args.dry_run and migrated:
            db.commit()

        log.info("Done. migrated=%d already_current=%d failed=%d%s",
                  migrated, already_current, failed, " (dry-run, no writes)" if args.dry_run else "")
        return 1 if failed else 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
