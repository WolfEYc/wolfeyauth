from fastapi import APIRouter, HTTPException, status
from app.internal import access
from app.dependencies import AdminDep, BasicAuthDep, StrForm, try_grant_access

router = APIRouter(
    prefix="/access",
    tags=["access"],
)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_access(clientname: StrForm, scope: StrForm, client: AdminDep):
    try_grant_access(client, scope)
    try:
        await access.create_access(clientname, scope)
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


@router.get("/", response_model=access.AccessList)
async def read_access(
    client: BasicAuthDep, client_filter: str = "", scope_filter: str = ""
):
    return await access.filter_access(client_filter, scope_filter)


@router.delete("/")
async def delete_access(clientname: StrForm, scope: StrForm, client: AdminDep):
    is_subject_admin = await access.check_access(clientname, "admin")
    if is_subject_admin and not client.is_chad():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only CHADs can delete admin access",
        )
    try:
        await access.delete_access(client=clientname, scope=scope)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    return {"client": clientname, "scope": scope, "caller": client.clientname}
