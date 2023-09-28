from fastapi import APIRouter, HTTPException, status
from app import auth
from app.dependencies import AdminDep, BasicAuthDep, StrForm

router = APIRouter(
    prefix="/scopes",
    tags=["scopes"],
)


@router.post("/scopes", status_code=status.HTTP_201_CREATED, tags=["scopes"])
async def create_scope(name: StrForm, admin: AdminDep):
    try:
        await auth.create_scope(name, admin.clientname)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    return {"scope": name, "caller": admin.clientname}


@router.get("/scopes", response_model=auth.ScopesList, tags=["scopes"])
async def read_scopes(
    client: BasicAuthDep, scope_filter: str = "", owner_filter: str = ""
):
    return await auth.filter_scope(scope_filter, owner_filter)


@router.delete("/scopes", tags=["scopes"])
async def delete_scope(scope: StrForm, client: AdminDep):
    owner = await auth.read_scope_owner(scope)
    if owner != client.clientname and not client.is_chad():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You must be the owner or a CHAD to delete this scope",
        )
    try:
        await auth.delete_scope(scope)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    return {"scope": scope, "caller": client.clientname}
