from fastapi import APIRouter

from . import token, clients, scopes, access

router = APIRouter(
    prefix="/api",
)

router.include_router(token.router)
router.include_router(clients.router)
router.include_router(scopes.router)
router.include_router(access.router)
