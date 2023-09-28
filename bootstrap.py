import asyncio
from app.internal import clients, db
import app.internal.auth as auth


async def main():
    await db.pool.open()
    try:
        wolfey_key = await clients.create_client("wolfey")
        print("key:", wolfey_key)
        await auth.create_scope("basic", "wolfey")
        await auth.create_scope("admin", "wolfey")
        await auth.create_scope("CHAD", "wolfey")
    except:
        print("Already bootstrapped! Moving on...")

    await db.pool.close()


asyncio.run(main())
