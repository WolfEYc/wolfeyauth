from typing import Annotated
from fastapi import Depends, Form, HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes

from app.internal import access, auth

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        "basic": "Basic access, allow for creation of your own scopes and access",
        "admin": "Can disable or delete BASIC clients, scopes, and access",
        "CHAD": "Can do literally anything",
        "unobtainable_scope": "useful for testing a scope which nobody should have access to",
    },
)  # use token authentication

RESERVED_SCOPES = ["admin", "CHAD"]


def authorize_client(
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
    if service in RESERVED_SCOPES and not admin.is_chad():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{admin.clientname} must be a CHAD to grant access to {service}",
        )


StrForm = Annotated[str, Form()]
BoolForm = Annotated[bool, Form()]

BasicAuthDep = Annotated[auth.client, Security(authorize_client, scopes=["basic"])]
AdminDep = Annotated[auth.client, Security(authorize_client, scopes=["admin"])]
CHADep = Annotated[auth.client, Security(authorize_client, scopes=["CHAD"])]
