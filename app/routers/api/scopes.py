from fastapi import APIRouter, HTTPException, status
from app.internal import scopes
from app.dependencies import AdminDep, BasicAuthDep, StrForm

router = APIRouter(
    prefix="/scopes",
    tags=["scopes"],
)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scope(name: StrForm, admin: AdminDep):
    try:
        await scopes.create_scope(name, admin.clientname)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    return {"scope": name, "caller": admin.clientname}


@router.get("", response_model=scopes.ScopesList)
async def read_scopes(
    client: BasicAuthDep, scope_filter: str = "", owner_filter: str = ""
):
    return await scopes.filter_scope(scope_filter, owner_filter)


@router.delete("")
async def delete_scope(scope: StrForm, client: AdminDep):
    owner = await scopes.read_scope_owner(scope)
    if owner != client.clientname and not client.is_chad():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You must be the owner or a CHAD to delete this scope",
        )
    try:
        await scopes.delete_scope(scope)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )

    return {"scope": scope, "caller": client.clientname}
