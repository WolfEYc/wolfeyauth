from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta, timezone
import os
import jwt
from enum import Enum
from pydantic import BaseModel
from app.internal.clients import read_client
from passlib.context import CryptContext

from app.internal.scopes import has_all_scopes

hasher = CryptContext(schemes=["bcrypt"], deprecated="auto")

private_key: bytes
public_key: bytes


TOKEN_LIFETIME_MINUTES = 30
AUTH_ISSUER = os.environ["AUTH_ISSUER"]
PRIVATE_KEY_PATH = os.environ["PRIVATE_KEY_PATH"]
PUBLIC_KEY_PATH = os.environ["PUBLIC_KEY_PATH"]


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
    with open(PUBLIC_KEY_PATH, "rb") as key_file:
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
