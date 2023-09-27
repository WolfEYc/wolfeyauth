import app.auth as auth


async def bootstrap():
    async with auth.pool.connection() as w:
        try:
            wolfey_key = await auth.create_user(w, "wolfey")
            await auth.create_scope(w, "basic", "wolfey")
            await auth.create_scope(w, "admin", "wolfey")
            await auth.create_scope(w, "CHAD", "wolfey")
            print("key:", wolfey_key)
        except:
            print("Already bootstrapped! Moving on...")
