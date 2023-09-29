from enum import Enum
from secrets import token_hex
from pydantic import BaseModel
from app.internal.db import apc, filterize
from psycopg.rows import class_row
from passlib.context import CryptContext

hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")


class DBclient(BaseModel):
    name: str
    hashedkey: str
    disabled: bool


async def create_client(name: str):
    key = token_hex(32)
    hashedkey = hasher.hash(key)
    async with apc() as c:
        await c.execute(
            """--sql
            INSERT INTO client
            VALUES (%(name)s, %(hashedkey)s, DEFAULT)
            """,
            {"name": name, "hashedkey": hashedkey},
        )
    return key


async def read_client(name: str) -> DBclient | None:
    async with apc() as c:
        c.row_factory = class_row(DBclient)
        await c.execute(
            """--sql
            SELECT name, hashedkey, disabled
            FROM client
            WHERE name = %(name)s
            """,
            {"name": name},
        )
        return await c.fetchone()


class AuthenticateResult(Enum):
    SUCCESS = 0
    client_NOT_FOUND = 1
    INVALID_KEY = 2
    client_DISABLED = 3
    NOT_AUTHORIZED = 4


async def authenticate_client(name: str, key: str):
    client = await read_client(name)
    if client is None:
        return AuthenticateResult.client_NOT_FOUND
    if client.disabled:
        return AuthenticateResult.client_DISABLED
    if not hasher.verify(key, client.hashedkey):
        return AuthenticateResult.INVALID_KEY
    return AuthenticateResult.SUCCESS


async def filter_clients(name: str, disabled: bool) -> list[str]:
    name = filterize(name)
    async with apc() as c:
        await c.execute(
            """--sql
            SELECT name
            FROM client
            WHERE LOWER(name) LIKE %(name)s
            AND disabled = %(disabled)s
            LIMIT 30
            """,
            {"name": name, "disabled": disabled},
        )
        clients = await c.fetchall()
    return [client[0] for client in clients]


async def set_disabled_client(name: str, disabled: bool):
    async with apc() as c:
        await c.execute(
            """--sql
            UPDATE client
            SET disabled = %(disabled)s
            WHERE name = %(name)s
            """,
            {"name": name, "disabled": disabled},
        )
        if c.rowcount == 0:
            raise Exception(f"{name} not found!")


async def reset_client_key(name: str) -> str:
    key = token_hex(32)
    hashedkey = hasher.hash(key)
    async with apc() as c:
        await c.execute(
            """--sql
            UPDATE client
            SET hashedkey = %(hashedkey)s
            WHERE name = %(name)s
            """,
            {"name": name, "hashedkey": hashedkey},
        )
    return key


async def delete_client(name: str):
    async with apc() as c:
        await c.execute(
            """--sql
            DELETE FROM client
            WHERE name = %(name)s
            """,
            {"name": name},
        )
        if c.rowcount == 0:
            raise Exception(f"{name} not found!")
