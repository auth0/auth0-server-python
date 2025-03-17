# Configuring the Store

The auth0-server-python library provides abstract base classes for storing session data (via a `State Store`) and for storing short-lived transaction data (via a `Transaction Store`). However, it doesn’t force a particular storage mechanism – you can pick cookies, a server-side database/cache, or anything else that suits your application.

Your `auth0-fastapi` layer (or your custom integration) is responsible for instantiating these stores and passing them to the `ServerClient` (in **auth0-server-python**) or to the `AuthClient` wrapper (in **auth0-fastapi**). This guide shows how to do exactly that.

## 1.Store Configuration Basics

### Abstract Base Classes

In `auth0-server-python`, you have:

1. `TransactionStore` – holds short-lived data for ongoing Auth0 flows (PKCE code_verifier, state param, etc.).

2. StateStore – holds user “session” data over longer periods (ID token, refresh token, user profile, etc.).

Each store implements `set`, `get`, and `delete`. The `StateStore` adds an optional `delete_by_logout_token` for backchannel logout scenarios.

### Passing Store Options

When you **start** or **complete** an Auth0 flow, you can pass a `store_options` dictionary with extra data (like the FastAPI `Request` and `Response`) that the store can use for reading/writing cookies. For example:

```python
store_options = {"request": request, "response": response}
await auth_client.start_login(app_state={"returnTo": "/profile"}, store_options=store_options)
```
## 2.Stateless Store (All Data in Cookies)
### When to Use It
A **stateless** store puts **all** the session data directly in the cookie – typically encrypted. It’s easy to set up but limited by cookie size constraints and overhead on each request. For small to medium session data, it can be sufficient.

### Example: `StatelessStateStore` and `CookieTransactionStore` in FastAPI
If you’re using auth0-fastapi, you already have:

1. `StatelessStateStore` – stores the session data (ID tokens, refresh tokens, etc.) in an encrypted cookie.
2. `CookieTransactionStore` – stores short-lived transaction data (PKCE code_verifier) in another encrypted cookie.

```python
from store.abstract import StateStore, TransactionStore

class StatelessStateStore(StateStore):
    def __init__(self, secret: str, cookie_name: str = "_a0_session"):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name

    async def set(self, identifier, state, remove_if_expires=False, options=None):
        # 1. Use self.encrypt to encrypt `state`.
        # 2. Store in a cookie named self.cookie_name
        #    typically using options["response"].set_cookie(...)
        pass

    async def get(self, identifier, options=None):
        # 1. Retrieve cookie from options["request"].cookies
        # 2. Decrypt with self.decrypt(...)
        pass

    async def delete(self, identifier, options=None):
        # Clear or expire the cookie
        pass

    # delete_by_logout_token can be no-op or raise NotImplementedError if purely stateless

```
**Transaction store** is similar, just specialized for short-lived data.

### Usage
```python
from auth0_fastapi.auth.auth_client import AuthClient
from auth0_fastapi.stores.stateless_state_store import StatelessStateStore
from auth0_fastapi.stores.cookie_transaction_store import CookieTransactionStore

stateless_store = StatelessStateStore(secret="YOUR_SECRET")
cookie_tx_store = CookieTransactionStore(secret="YOUR_SECRET")

auth_client = AuthClient(
    config=...,
    state_store=stateless_store,
    transaction_store=cookie_tx_store
)
```
When users log in:
```python
@app.get("/auth/login")
async def login(request: Request, response: Response):
    store_options = {"request": request, "response": response}
    redirect_url = await request.app.state.auth_client.start_login(
        store_options=store_options
    )
    return RedirectResponse(url=redirect_url)
```
All session data is now **fully** in cookies, so there’s no need for a server-side session DB.

## 3.Stateful Store (Server-Side Sessions)
### When to Use It
A **stateful** approach stores only a **session ID** in the cookie, while the actual user/session data (ID tokens, refresh tokens) lives in a server-based store (e.g., Redis, Postgres). This avoids cookie size limits and can handle large amounts of data.

### 3.1. Redis-Based Example
Let’s walk through a `RedisStateStore` that inherits from `StateStore`:
```python
import aioredis
from typing import Any, Dict, Optional
from store.abstract import StateStore

class RedisStateStore(StateStore):
    """
    A stateful store that uses Redis to store session data.
    The cookie holds just a session_id; the rest of the data is in Redis.
    """

    def __init__(self, secret: str, redis_url: str = "redis://localhost:6379", cookie_name: str = "_a0_session"):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name
        self.redis_client = aioredis.from_url(redis_url)

    async def set(
        self, 
        identifier: str, 
        state: Dict[str, Any],  
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        if not options or "response" not in options:
            raise ValueError("Response object is required for setting a cookie in RedisStateStore.")
        
        response = options["response"]

        # Generate or reuse a session_id. If remove_if_expires is True, you might want to re-generate.
        # For simplicity, let's re-generate a new session_id each time. You could also store it once.
        session_id = identifier  # or use secrets.token_urlsafe(), etc.

        # Store the actual user data in Redis under `session_id`.
        # If you want encryption at rest, you can do:
        #    encrypted_data = self.encrypt(session_id, state)
        #    await self.redis_client.set(session_id, encrypted_data)
        # For demo, let's store it as JSON without encryption:
        import json
        await self.redis_client.set(session_id, json.dumps(state))

        # Now set a cookie in the response with just the session_id
        # (You can choose an expiration or not).
        response.set_cookie(
            key=self.cookie_name,
            value=session_id,
            httponly=True,
            samesite="Lax",
            max_age=3600,  # 1 hour example
            path="/"
        )

    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        if not options or "request" not in options:
            raise ValueError("Request object is required to read cookies in RedisStateStore.")

        request = options["request"]
        session_id = request.cookies.get(self.cookie_name)
        if not session_id:
            return None

        # Retrieve from Redis
        raw_data = await self.redis_client.get(session_id)
        if not raw_data:
            return None
        
        # If you used self.encrypt(...) on set, call self.decrypt(...) here.
        import json
        return json.loads(raw_data)

    async def delete(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        if not options or "response" not in options:
            raise ValueError("Response object is required to clear cookies in RedisStateStore.")

        response = options["response"]
        request = options["request"]
        session_id = request.cookies.get(self.cookie_name)

        # Remove from Redis
        if session_id:
            await self.redis_client.delete(session_id)

        # Clear the cookie
        response.delete_cookie(self.cookie_name)

    async def delete_by_logout_token(
        self, 
        claims: Dict[str, Any], 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        For backchannel logout, look up and remove sessions that match `sid` or `sub`.
        This might require scanning your Redis store or having an index that maps sid -> session_id.
        """
        # Example: if you store 'sid' inside the session data, you could do:
        #   1) iterate over all keys or maintain a mapping. We'll do a naive approach:
        #   2) parse each session for matching sub/sid.
        # This is a simple approach; for large scale, add indexing or a specialized lookup.

        keys = await self.redis_client.keys("*")
        for k in keys:
            raw_data = await self.redis_client.get(k)
            if raw_data:
                import json
                session_data = json.loads(raw_data)
                # If your session_data stores an internal dict with `sid` or `sub`
                internal = session_data.get("internal", {})
                if internal.get("sid") == claims.get("sid") and session_data.get("user", {}).get("sub") == claims.get("sub"):
                    await self.redis_client.delete(k)

```
#### Usage in FastAPI
```python
from auth0_fastapi.auth.auth_client import AuthClient
from your_module.redis_state_store import RedisStateStore
from auth0_fastapi.stores.cookie_transaction_store import CookieTransactionStore

redis_state_store = RedisStateStore(
    secret="YOUR_APP_SECRET",
    redis_url="redis://localhost:6379",
    cookie_name="_a0_session"
)

transaction_store = CookieTransactionStore(secret="YOUR_APP_SECRET")

auth_client = AuthClient(
    config=config,  # your Auth0Config
    state_store=redis_state_store,
    transaction_store=transaction_store
)
```
Now your user’s session data is in **Redis**, and only a minimal session ID is in the cookie.

### 3.2. Postgres-Based Example
If you prefer a **SQL database** for session data, here’s a `PostgresStateStore` example using [asyncpg](https://github.com/MagicStack/asyncpg)

```python
import asyncpg
from typing import Any, Dict, Optional
from store.abstract import StateStore

class PostgresStateStore(StateStore):
    """
    A stateful store that uses Postgres to store session data.
    The cookie holds just a session_id; the rest of the data is in Postgres.
    """

    def __init__(self, secret: str, dsn: str, cookie_name: str = "_a0_session"):
        super().__init__({"secret": secret})
        self.dsn = dsn  # "postgresql://user:password@host:port/dbname"
        self.cookie_name = cookie_name
        self.pool = None  # We'll initialize a connection pool later.

    async def init_pool(self):
        """Create a connection pool. Call this once on startup."""
        if not self.pool:
            self.pool = await asyncpg.create_pool(dsn=self.dsn)

    async def set(
        self, 
        identifier: str, 
        state: Dict[str, Any], 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        if not options or "response" not in options:
            raise ValueError("Response object is required for setting a cookie in PostgresStateStore.")
        
        response = options["response"]
        session_id = identifier  # Or generate a random ID (e.g. secrets.token_urlsafe())

        async with self.pool.acquire() as conn:
            # Optionally encrypt `state`:
            # encrypted_data = self.encrypt(session_id, state)
            # For simplicity, store as JSON
            import json
            data_json = json.dumps(state)

            # Insert or update the session
            await conn.execute(
                """
                INSERT INTO auth_sessions(session_id, session_data)
                VALUES($1, $2)
                ON CONFLICT (session_id) DO UPDATE SET session_data=excluded.session_data
                """,
                session_id,
                data_json
            )

        # Set the cookie containing session_id
        response.set_cookie(
            key=self.cookie_name,
            value=session_id,
            httponly=True,
            samesite="Lax",
            max_age=86400,  # 1 day example
            path="/"
        )

    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        if not options or "request" not in options:
            raise ValueError("Request object is required to read cookies in PostgresStateStore.")

        request = options["request"]
        session_id = request.cookies.get(self.cookie_name)
        if not session_id:
            return None

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT session_data FROM auth_sessions WHERE session_id = $1",
                session_id
            )
            if not row:
                return None
            # If you used encryption, do self.decrypt(...)
            import json
            return json.loads(row["session_data"])

    async def delete(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        if not options or "response" not in options:
            raise ValueError("Response object is required to clear cookies in PostgresStateStore.")
        
        response = options["response"]
        request = options["request"]
        session_id = request.cookies.get(self.cookie_name)

        if session_id:
            async with self.pool.acquire() as conn:
                await conn.execute("DELETE FROM auth_sessions WHERE session_id = $1", session_id)

        response.delete_cookie(self.cookie_name)

    async def delete_by_logout_token(
        self, 
        claims: Dict[str, Any], 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Backchannel logout: find sessions that match sub/sid and remove them.
        This might require storing sub/sid in the DB row for quick lookups.
        """
        async with self.pool.acquire() as conn:
            # If you store 'sid' or 'user.sub' in a separate column, you can do:
            await conn.execute(
                """
                DELETE FROM auth_sessions
                WHERE (session_data->'internal'->>'sid') = $1
                  AND (session_data->'user'->>'sub') = $2
                """,
                claims.get("sid"),
                claims.get("sub")
            )
```
#### Usage in FastAPI
```python
from auth0_fastapi.auth.auth_client import AuthClient
from your_module.postgres_state_store import PostgresStateStore
from auth0_fastapi.stores.cookie_transaction_store import CookieTransactionStore

pg_store = PostgresStateStore(
    secret="YOUR_SECRET",
    dsn="postgresql://user:pass@localhost:5432/mydb",
    cookie_name="_a0_session"
)

await pg_store.init_pool()  # do this in an @app.on_event("startup") if using FastAPI

transaction_store = CookieTransactionStore(secret="YOUR_SECRET")

auth_client = AuthClient(
    config=config,
    state_store=pg_store,
    transaction_store=transaction_store
)

```
## 4. Passing Store Options in a FastAPI Endpoint

Often you need `request` and `response` objects to set or clear cookies. In your route:

```python
@app.get("/auth/login")
async def login(request: Request, response: Response):
    store_options = {"request": request, "response": response}
    auth_url = await auth_client.start_login(
        store_options=store_options
    )
    return RedirectResponse(auth_url)
```
Likewise for logout or completing the login callback:
```python
@app.get("/auth/callback")
async def callback(request: Request, response: Response):
    store_options = {"request": request, "response": response}
    session_data = await auth_client.complete_login(
        str(request.url), 
        store_options=store_options
    )
    ...
```
The store sees `store_options["request"]` and `store_options["response"]`—it can handle cookies or read HTTP headers as needed.

## 5. Handling Backchannel Logout

If you want to support **OIDC Backchannel Logout**:

- For **stateless** stores, you might just remove the cookie or do nothing.
- For **stateful** stores, you often need to find all sessions referencing a sub or sid from the logout token and remove them. That’s what the `delete_by_logout_token` method in `StateStore` is for.

```python
@app.post("/auth/backchannel-logout")
async def backchannel_logout(request: Request):
    body = await request.json()
    logout_token = body.get("logout_token")
    await auth_client.handle_backchannel_logout(logout_token)
    return Response(status_code=204)

```
The store’s `delete_by_logout_token` method is where you’d do a DB lookup by `sid` or `sub` to invalidate sessions.

## 6. Best Practices
1. **Choose Stateless** for simplicity (everything in cookies) or **Stateful** for more flexibility (cookies store an ID; actual data in a DB).
2. **Encrypt** your data if you store tokens or personal info in cookies (stateless). If you store them in a DB, ensure your DB environment is secure.
3. **Large Data** or **multiple tokens** often suggests **stateful** storage—avoid hitting cookie size limits or overhead.