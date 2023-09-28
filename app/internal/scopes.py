from pydantic import BaseModel
from app.internal.access import create_access
from app.internal.db import apc, filterize


async def create_scope(name: str, owner: str):
    async with apc() as c:
        await c.execute(
            """--sql
            INSERT INTO scope
            VALUES(%(name)s, %(owner)s)
            """,
            {"name": name, "owner": owner},
        )
    await create_access(owner, name)


async def read_scope_owner(scope: str) -> str | None:
    async with apc() as c:
        await c.execute(
            """--sql
            SELECT owner
            FROM scope
            WHERE name = %(scope)s
            """,
            {"scope": scope},
        )
        res = await c.fetchone()
    if res is None:
        return None
    return res[0]


class ScopesList(BaseModel):
    scopes: list[str]
    owners: list[str]


async def filter_scope(name: str, owner: str) -> ScopesList:
    name = filterize(name)
    owner = filterize(owner)
    async with apc() as c:
        await c.execute(
            """--sql
            SELECT *
            FROM scope
            WHERE name LIKE %(name)s
                AND owner LIKE %(owner)s
            LIMIT 30;
            """,
            {"name": name, "owner": owner},
        )
        res = await c.fetchall()
    if len(res) == 0:
        return ScopesList(scopes=[], owners=[])
    scopes, owners = zip(*res)
    return ScopesList(scopes=scopes, owners=owners)  # type: ignore


async def delete_scope(name: str):
    async with apc() as c:
        await c.execute(
            """--sql
            DELETE FROM scope
            WHERE name = %(name)s
            """,
            {"name": name},
        )
        if c.rowcount == 0:
            raise Exception(f"{name} not found!")
