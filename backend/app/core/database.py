from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings

engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """Request-scoped unit of work.

    The request handler owns the transaction boundary (see the
    "Transaction ownership" convention in CONTRIBUTING.md). On an unhandled
    exception the session's transaction may already be aborted, and
    SQLAlchemy does not auto-rollback; returning that session to the pool
    without rolling back leaks a poisoned transaction to whoever gets the
    connection next, who then fails with a PendingRollbackError that has
    nothing to do with their own request.
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
