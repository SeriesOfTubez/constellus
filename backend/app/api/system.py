from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.user import is_first_run

router = APIRouter()


@router.get("/status")
def status(db: Session = Depends(get_db)):
    return {
        "first_run": is_first_run(db),
        "version": "0.1.0",
    }
