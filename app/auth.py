from contextlib import asynccontextmanager
from secrets import token_hex
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
import os
import jwt
from enum import Enum
from passlib.context import CryptContext
from psycopg_pool import AsyncConnectionPool
from pydantic import BaseModel
from dotenv import load_dotenv
from psycopg.rows import class_row

load_dotenv()

private_key: bytes
public_key: bytes
hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

TOKEN_LIFETIME_MINUTES = 30
DB_URL = os.environ["DATABASE_URL"]
AUTH_ISSUER = os.environ["AUTH_ISSUER"]
PRIVATE_KEY_PATH = os.environ["PRIVATE_KEY_PATH"]
pool = AsyncConnectionPool(DB_URL, open=False)


@asynccontextmanager
async def apc():
    """
    Async Pool Cursor
    """
    async with pool.connection() as con:
        async with con.cursor() as cur:
            yield cur


async def pc():
    pool.connection()


def filterize(to_filterize: str):
    return f"%{to_filterize.lower()}%"


def get_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=bytes(os.environ["PRIVATE_KEY_PASSWORD"], encoding="utf-8"),
        ).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


def update_private_key():
    global private_key
    optional_private_key = get_private_key()
    if optional_private_key is None:
        raise Exception("Failed to get private key!")
    private_key = optional_private_key


def get_public_key():
    with open("cert/public_key.pub", "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read()).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def update_public_key():
    global public_key
    optional_public_key = get_public_key()
    if optional_public_key is None:
        raise Exception("Failed to get public key!")
    public_key = optional_public_key


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


class DBclient(BaseModel):
    name: str
    hashedkey: str
    disabled: bool


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


async def filter_client(name: str, disabled: bool) -> list[str]:
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


async def read_scopes(client: str) -> list[str]:
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


async def has_all_scopes(client: str, scopes_req: list[str]) -> bool:
    has_scopes = await read_scopes(client)
    return all(scope in has_scopes for scope in scopes_req)


async def has_any_scopes(client: str, scopes_req: list[str]) -> bool:
    has_scopes = await read_scopes(client)
    return any(scope in has_scopes for scope in scopes_req)


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


def create_token(client: str, scopes: list[str]):
    expires = datetime.now(tz=timezone.utc) + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
    payload = {"sub": client, "iss": AUTH_ISSUER, "aud": scopes, "exp": expires}
    return jwt.encode(payload, private_key, algorithm="RS256")


async def login(client: str, key: str, scopes: list[str]):
    """
    Performs authentication + token creation
    Conforms to OAuth2 RFC
    RS256 for central auth scope
    """

    authentication_res = await authenticate_client(client, key)
    if authentication_res != AuthenticateResult.SUCCESS:
        return authentication_res

    has_scopes = await has_all_scopes(client, scopes)
    if not has_scopes:
        return AuthenticateResult.NOT_AUTHORIZED

    token = create_token(client, scopes)
    return token


class client(BaseModel):
    clientname: str
    scopes: list[str]

    def has_scope(self, scope: str):
        return self.scopes.count(scope) != 0

    def is_chad(self):
        return self.has_scope("CHAD")

    def is_admin(self):
        return self.has_scope("admin")


def authorize_token(token: str, scopes: list[str]):
    """
    Other scopes can reuse this logic for authorization.
    This follows standard OAuth2 RFC
    """
    token_bytes = bytes(token, encoding="utf-8")
    payload = jwt.decode(
        token_bytes,
        public_key,
        issuer=AUTH_ISSUER,
        audience=scopes,
        algorithms=["RS256"],
        options={"require": ["exp", "iss", "sub", "aud"]},
    )

    return client(clientname=payload.get("sub"), scopes=payload.get("aud"))
