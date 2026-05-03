from fastapi import APIRouter

router = APIRouter()


@router.post("/login")
def login():
    return {"status": "not implemented"}


@router.post("/logout")
def logout():
    return {"status": "not implemented"}
