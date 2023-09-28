from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from app import auth
from app.dependencies import AdminDep, BasicAuthDep, BoolForm, StrForm, try_edit_user

router = APIRouter(
    prefix="/clients",
    tags=["clients"],
)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_client(new_client_name: StrForm, client: AdminDep):
    try:
        key = await auth.create_client(new_client_name)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    return {"client": new_client_name, "key": key, "caller": client.clientname}


@router.get("/me")
def read_me(client: BasicAuthDep):
    return client


class clientInfo(BaseModel):
    clientname: str
    disabled: bool


@router.get("/{clientname}", response_model=clientInfo)
async def read_client(clientname: str, client: BasicAuthDep):
    res = await auth.read_client(clientname)
    if res is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{clientname} not found"
        )
    return clientInfo(clientname=res.name, disabled=res.disabled)


@router.get("/", response_model=list[str])
async def read_clients(
    client: BasicAuthDep, clientname_filter: str = "", disabled: bool = False
):
    clients = await auth.filter_client(clientname_filter, disabled)
    return clients


@router.put("/{clientname}/disable")
async def update_client_disabled(subject: str, disabled: BoolForm, admin: AdminDep):
    await try_edit_user(subject, admin)
    try:
        await auth.set_disabled_client(subject, disabled)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    return {"subject": subject, "disabled": disabled, "caller": admin.clientname}


@router.put("/{clientname}/resetkey")
async def update_client_key(sub: str, admin: AdminDep):
    await try_edit_user(sub, admin)
    try:
        key = await auth.reset_client_key(sub)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return key


@router.delete("/")
async def delete_client(sub: StrForm, admin: AdminDep):
    await try_edit_user(sub, admin)
    try:
        await auth.delete_client(sub)
    except:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="client not found"
        )

    return {"client": sub, "caller": admin.clientname}
