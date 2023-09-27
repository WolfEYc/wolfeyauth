import asyncio
import app.auth as auth


async def main():
    await auth.pool.open()
    try:
        wolfey_key = await auth.create_client("wolfey")
        print("key:", wolfey_key)
        await auth.create_scope("basic", "wolfey")
        await auth.create_scope("admin", "wolfey")
        await auth.create_scope("CHAD", "wolfey")
    except:
        print("Already bootstrapped! Moving on...")

    await auth.pool.close()


asyncio.run(main())
