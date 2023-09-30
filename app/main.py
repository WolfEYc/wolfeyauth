import logging
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles

load_dotenv()

from app.internal import db
from fastapi import FastAPI
from contextlib import asynccontextmanager
import app.internal.auth as auth
from app.routers import api, frontend


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth.update_private_key()
    auth.update_public_key()
    await db.pool.open()
    yield

    await db.pool.close()


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
    {"name": "login", "description": "frontend form to log in"},
    {"name": "console", "description": "admin console"},
]

app = FastAPI(lifespan=lifespan, title="AuthWolfey", openapi_tags=tags_metadata)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(api.router)
app.include_router(frontend.router)
