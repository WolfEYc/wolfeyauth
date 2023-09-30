from typing import Annotated
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from app.dependencies import add_reserved
from app.internal import auth
from app.internal.auth import RUNTIME, TOKEN_LIFETIME_SECONDS, Runtime
from app.routers.frontend.templates import templates

router = APIRouter(
    prefix="/login",
    tags=["login"],
)

TOKEN_KEY = "access_token"


@router.get("", response_class=HTMLResponse)
async def login_page(request: Request, response: Response, logout: bool = False):
    if logout:
        response.delete_cookie(TOKEN_KEY)
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/submit", response_class=HTMLResponse)
async def submit_creds(
    request: Request,
    response: Response,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    await add_reserved(form)
    login_result = await auth.login(form)
    if not isinstance(login_result, str):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": login_result.name},
            status_code=400,
            block_name="error",
        )
    response.set_cookie(
        key=TOKEN_KEY,
        value=login_result,
        max_age=TOKEN_LIFETIME_SECONDS,
        httponly=True,
        samesite="strict",
        domain=request.url.hostname,
        secure=RUNTIME != Runtime.DEV,
    )
    response.headers["Location"] = "/"
    response.status_code = 302
