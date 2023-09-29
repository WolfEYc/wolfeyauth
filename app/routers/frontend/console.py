from fastapi import APIRouter
from app.dependencies import BrowserBasicAuthDep
from templates import templates

router = APIRouter(tags=["console"])


@router.get("/")
async def index(client: BrowserBasicAuthDep):
    return templates.TemplateResponse("console.html", client.model_dump())
