from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status

from app.internal import auth

router = APIRouter(
    prefix="/token",
    tags=["token"],
)


class Token(BaseModel):
    access_token: str
    token_type: str


@router.post("")
async def create_token(form: Annotated[OAuth2PasswordRequestForm, Depends()]):
    login_result = await auth.login(form.username, form.password, form.scopes)
    if not isinstance(login_result, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=login_result.name,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Token(access_token=login_result, token_type="bearer")
