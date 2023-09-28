from contextlib import asynccontextmanager
import os
from psycopg_pool import AsyncConnectionPool

DB_URL = os.environ["DATABASE_URL"]
pool = AsyncConnectionPool(DB_URL, open=False)


@asynccontextmanager
async def apc():
    """
    Async Pool Cursor
    """
    async with pool.connection() as con:
        async with con.cursor() as cur:
            yield cur


def filterize(to_filterize: str):
    return f"%{to_filterize.lower()}%"
