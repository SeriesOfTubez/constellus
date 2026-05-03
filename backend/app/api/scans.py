from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def list_scans():
    return []


@router.post("/")
def create_scan():
    return {"status": "not implemented"}
