from fastapi import FastAPI
from contextlib import asynccontextmanager
import app.auth as auth
from app.routers import clients, token, scopes, access


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth.update_private_key()
    auth.update_public_key()
    await auth.pool.open()
    yield

    await auth.pool.close()


tags_metadata = [
    {
        "name": "token",
        "description": "POST your login here!, snag a JWT token and include it in your Bearer header to make authenticated req",
    },
    {
        "name": "clients",
        "description": "Client defines a unique identifier for a machine or human, with additional metadata",
    },
    {
        "name": "scopes",
        "description": "Scope defines an authorization for a client",
    },
    {
        "name": "access",
        "description": "Access defines a scope a client has access to",
    },
]

app = FastAPI(lifespan=lifespan, title="AuthWolfey", openapi_tags=tags_metadata)

app.include_router(token.router)
app.include_router(clients.router)
app.include_router(scopes.router)
app.include_router(access.router)
