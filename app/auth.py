from contextlib import asynccontextmanager
from secrets import token_hex
from typing import Any, TypeAlias, Union
from psycopg import AsyncConnection, AsyncCursor
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

pool = AsyncConnectionPool(DB_URL, open=False)


@asynccontextmanager
async def apc():
    async with pool.connection() as con:
        async with con.cursor() as cur:
            yield cur


async def pc():
    pool.connection()


def get_private_key():
    with open("app/cert/private_key.pem", "rb") as key_file:
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
    with open("app/cert/public_key.pub", "rb") as key_file:
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


async def create_user(name: str):
    key = token_hex(32)
    hashedkey = hasher.hash(key)
    async with apc() as c:
        await c.execute("INSERT INTO user VALUES (%s, %s, NULL)", (name, hashedkey))
    return key


async def set_disabled_user(name: str, disabled: bool):
    async with apc() as c:
        await c.execute(
            """
            UPDATE user
            SET disabled = %(disabled)s
            WHERE name = %(name)s
            """,
            {"name": name, "disabled": disabled},
        )
        if c.rowcount == 0:
            raise Exception(f"{name} not found!")


class DBUser(BaseModel):
    name: str
    hashkey: str
    disabled: bool


async def read_user(name: str) -> DBUser | None:
    async with apc() as c:
        c.row_factory = class_row(DBUser)
        await c.execute(
            """
            SELECT *
            FROM user
            WHERE name = %(name)s
            """,
            {"name": name},
        )
        user = await c.fetchone()
        return user


async def filter_user(name: str, disabled: bool) -> list[str]:
    async with apc() as c:
        await c.execute(
            """
            SELECT name
            FROM user
            WHERE LOWER(name) LIKE %(name)s
            AND disabled = %(disabled)s
            LIMIT 30
            """,
            {"name": name, "disabled": disabled},
        )
        users = await c.fetchall()
        return [user[0] for user in users]


async def delete_user(name: str):
    async with apc() as c:
        await c.execute(
            """--sql
            DELETE FROM user
            WHERE name = %(name)s
            """,
            {"name": name},
        )
        if c.rowcount == 0:
            raise Exception(f"{name} not found!")


async def create_scope(name: str, owner: str):
    async with apc() as c:
        await c.execute(
            """
            INSERT INTO scope
            VALUES(%(name)s, %(owner)s)
            """,
            {"name": name, "owner": owner},
        )
    await create_access(owner, name)


async def filter_scope(name: str, owner: str):
    async with apc() as c:
        await c.execute(
            """
            SELECT *
            FROM scope
            WHERE name LIKE :name
                AND owner LIKE :owner
            LIMIT 30
            """,
        )


async def delete_scope(name: str):
    async with apc() as c:
        await c.execute(
            """
            DELETE FROM scope
            WHERE name = %(name)s
            """,
            {"name": name},
        )
        if c.rowcount == 0:
            raise Exception(f"{name} not found!")


class AuthenticateResult(Enum):
    SUCCESS = 0
    USER_NOT_FOUND = 1
    INVALID_KEY = 2
    USER_DISABLED = 3
    NOT_AUTHORIZED = 4


async def authenticate_user(name: str, key: str):
    user = await read_user(name)
    if user is None:
        return AuthenticateResult.USER_NOT_FOUND
    if user.disabled:
        return AuthenticateResult.USER_DISABLED
    if not hasher.verify(key, user.hashkey):
        return AuthenticateResult.INVALID_KEY
    return AuthenticateResult.SUCCESS


async def read_scopes(user: str) -> list[str]:
    async with apc() as c:
        await c.execute(
            """
            SELECT scopename
            FROM access
            WHERE username = %(username)s
            """,
            {"username": user},
        )
        scopes = await c.fetchall()
        return [scope[0] for scope in scopes]


async def has_all_scopes(user: str, scopes_req: list[str]) -> bool:
    has_scopes = await read_scopes(user)
    return all(scope in has_scopes for scope in scopes_req)


async def has_any_scopes(user: str, scopes_req: list[str]) -> bool:
    has_scopes = await read_scopes(user)
    return any(scope in has_scopes for scope in scopes_req)


async def create_access(user: str, scope: str):
    async with apc() as c:
        await c.execute(
            """
            INSERT INTO access
            VALUES(%(username)s, %(scopename)s)
            """,
            {"username": user, "scopename": scope},
        )


async def check_access(user: str, scope: str) -> bool:
    async with apc() as c:
        await c.execute(
            """
            SELECT EXISTS (
                SELECT 1
                FROM access
                WHERE username = %(username)s
                    AND scopename = %(scopename)s
            )
            """,
            {"username": user, "scopename": scope},
        )
        res = await c.fetchone()
        return res is not None


async def delete_access(user: str, scope: str):
    async with apc() as c:
        await c.execute(
            """
        DELETE FROM access
        WHERE username = %(username)s
            AND scopename = %(scopename)s
        """,
            {"username": user, "scopename": scope},
        )
        if c.rowcount == 0:
            raise Exception(f"{user}'s access to {scope} not found!")


def create_token(user: str, scopes: list[str]):
    expires = datetime.now(tz=timezone.utc) + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
    payload = {"sub": user, "iss": AUTH_ISSUER, "aud": scopes, "exp": expires}
    return jwt.encode(payload, private_key, algorithm="RS256")


async def login(user: str, key: str, scopes: list[str]):
    """
    Performs authentication + token creation
    Conforms to OAuth2 RFC
    RS256 for central auth scope
    """

    authentication_res = await authenticate_user(user, key)
    if authentication_res != AuthenticateResult.SUCCESS:
        return authentication_res

    has_scopes = await has_all_scopes(user, scopes)
    if not has_scopes:
        return AuthenticateResult.NOT_AUTHORIZED

    token = create_token(user, scopes)
    return token


class User(BaseModel):
    username: str
    scopes: list[str]

    def has_scope(self, scope: str):
        return self.scopes.count(scope) != 0

    def is_chad(self):
        return self.has_scope("CHAD")

    def is_admin(self):
        return self.has_scope("admin")


def verify_token(token: str):
    token_bytes = bytes(token, encoding="utf-8")
    payload = jwt.decode(
        token_bytes,
        public_key,
        issuer=AUTH_ISSUER,
        algorithms=["RS256"],
        options={"require": ["exp", "iss", "sub", "aud"]},
    )

    return User(username=payload.get("sub"), scopes=payload.get("aud"))


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

    return User(username=payload.get("sub"), scopes=payload.get("aud"))
