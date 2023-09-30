from fastapi import APIRouter, Request
from app.dependencies import BrowserBasicAuthDep
from app.routers.frontend.templates import templates

router = APIRouter(tags=["console"])


@router.get("/")
async def index(request: Request, client: BrowserBasicAuthDep):
    ctx = client.model_dump()
    ctx["request"] = request
    return templates.TemplateResponse("console.html", ctx)
