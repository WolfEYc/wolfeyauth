from fastapi import APIRouter

from . import console, login

router = APIRouter()

router.include_router(login.router)
router.include_router(console.router)
