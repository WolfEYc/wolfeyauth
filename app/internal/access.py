from pydantic import BaseModel
from app.internal.db import apc, filterize


async def create_access(client: str, scope: str):
    async with apc() as c:
        await c.execute(
            """--sql
            INSERT INTO access
            VALUES(%(clientname)s, %(scopename)s)
            """,
            {"clientname": client, "scopename": scope},
        )


async def check_access(client: str, scope: str) -> bool:
    async with apc() as c:
        await c.execute(
            """--sql
            SELECT EXISTS (
                SELECT 1
                FROM access
                WHERE clientname = %(clientname)s
                    AND scopename = %(scopename)s
            )
            """,
            {"clientname": client, "scopename": scope},
        )
        res = await c.fetchone()
        return res is not None


async def read_access(client: str) -> list[str]:
    async with apc() as c:
        await c.execute(
            """--sql
            SELECT scopename
            FROM access
            WHERE clientname = %(clientname)s
            """,
            {"clientname": client},
        )
        scopes = await c.fetchall()
    return [scope[0] for scope in scopes]


async def has_all_scopes(client: str, scopes_req: list[str]) -> bool:
    has_scopes = await read_access(client)
    return all(scope in has_scopes for scope in scopes_req)


async def has_any_scopes(client: str, scopes_req: list[str]) -> bool:
    has_scopes = await read_access(client)
    return any(scope in has_scopes for scope in scopes_req)


class AccessList(BaseModel):
    scopes: list[str]
    clients: list[str]


async def filter_access(client: str, scope: str) -> AccessList:
    client = filterize(client)
    scope = filterize(scope)
    async with apc() as c:
        await c.execute(
            """--sql
            SELECT scopename, clientname
            FROM access
            WHERE LOWER(clientname) LIKE %(client)s
                AND LOWER(scopename) LIKE %(scope)s
            LIMIT 30
            """,
            {"client": client, "scope": scope},
        )
        res = await c.fetchall()
    if len(res) == 0:
        return AccessList(scopes=[], clients=[])
    scopes, clients = zip(*res)
    return AccessList(scopes=scopes, clients=clients)


async def delete_access(client: str, scope: str):
    async with apc() as c:
        await c.execute(
            """--sql
            DELETE FROM access
            WHERE clientname = %(clientname)s
                AND scopename = %(scopename)s
            """,
            {"clientname": client, "scopename": scope},
        )
        if c.rowcount == 0:
            raise Exception(f"{client}'s access to {scope} not found!")
