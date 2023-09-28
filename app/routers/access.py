from fastapi import APIRouter, HTTPException, status
from app import auth
from app.dependencies import AdminDep, BasicAuthDep, StrForm, try_grant_access

router = APIRouter(
    prefix="/scopes",
    tags=["scopes"],
)


@router.post("/access", status_code=status.HTTP_201_CREATED, tags=["access"])
async def create_access(clientname: StrForm, scope: StrForm, client: AdminDep):
    try_grant_access(client, scope)
    try:
        await auth.create_access(clientname, scope)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    return {
        "scope": scope,
        "new_client": clientname,
        "caller": client.clientname,
    }


@router.get("/access", response_model=auth.AccessList, tags=["access"])
async def read_access(
    client: BasicAuthDep, client_filter: str = "", scope_filter: str = ""
):
    return await auth.filter_access(client_filter, scope_filter)


@router.delete("/access", tags=["access"])
async def delete_access(clientname: StrForm, scope: StrForm, client: AdminDep):
    is_subject_admin = await auth.check_access(clientname, "admin")
    if is_subject_admin and not client.is_chad():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only CHADs can delete admin access",
        )
    try:
        await auth.delete_access(client=clientname, scope=scope)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    return {"client": clientname, "scope": scope, "caller": client.clientname}
