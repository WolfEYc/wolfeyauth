from typing import Annotated
from fastapi import Cookie, Depends, Form, HTTPException, Request, Security, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
    SecurityScopes,
)

from app.internal import access, auth
from app.internal.clients import AuthenticateResult

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="api/token",
    scopes={
        "basic": "Basic access, allow for creation of your own scopes and access",
        "admin": "Can disable or delete BASIC clients, scopes, and access",
        "CHAD": "Can do literally anything",
        "unobtainable_scope": "useful for testing a scope which nobody should have access to",
    },
)  # use token authentication


def authorize_client_api(
    security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2_scheme)]
):
    try:
        client = auth.authorize_token(token, security_scopes.scopes)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

    return client


async def try_edit_user(sub: str, admin: auth.client):
    if (
        sub != admin.clientname
        and not admin.is_chad()
        and await access.check_access(sub, "admin")
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{admin.clientname} must be a CHAD disable {sub}",
        )


def try_grant_access(admin: auth.client, service: str):
    if service in access.RESERVED_SCOPES and not admin.is_chad():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{admin.clientname} must be a CHAD to grant access to {service}",
        )


async def add_reserved(form: OAuth2PasswordRequestForm):
    owned_reserved_scopes = await access.get_reserved_access(form.username)
    scopes = set(form.scopes).union(owned_reserved_scopes)
    scopes.add("basic")
    form.scopes = list(scopes)


async def cookie_auth(
    security_scopes: SecurityScopes,
    access_token: Annotated[str | None, Cookie()] = None,
):
    if access_token is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            detail="No cookie!",
            headers={"Location": "/login"},
        )
    try:
        client = auth.authorize_token(access_token, security_scopes.scopes)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            detail=str(e),
            headers={"Location": "/login"},
        )

    return client


StrForm = Annotated[str, Form()]
BoolForm = Annotated[bool, Form()]

BasicAuthDep = Annotated[auth.client, Security(authorize_client_api, scopes=["basic"])]
AdminDep = Annotated[auth.client, Security(authorize_client_api, scopes=["admin"])]
CHADep = Annotated[auth.client, Security(authorize_client_api, scopes=["CHAD"])]


BrowserBasicAuthDep = Annotated[auth.client, Security(cookie_auth, scopes=["basic"])]
BrowserAdminDep = Annotated[auth.client, Security(cookie_auth, scopes=["admin"])]
BrowserCHADep = Annotated[auth.client, Security(cookie_auth, scopes=["CHAD"])]
