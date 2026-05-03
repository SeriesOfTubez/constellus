from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def list_findings():
    return []
