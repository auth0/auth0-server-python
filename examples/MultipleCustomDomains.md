# Multiple Custom Domains (MCD)

MCD lets you resolve the Auth0 domain per request while keeping a single `ServerClient` instance. This is useful when your application uses multiple custom domains configured on the same Auth0 tenant.

> **Important:** MCD supports multiple custom domains on a **single Auth0 tenant**. It does not support connecting to multiple Auth0 tenants from a single application. Each custom domain must belong to the same Auth0 tenant. Using domains from different Auth0 tenants is not supported and will result in authentication failures.

**Example:**
- `https://brand-1.yourapp.com` → Custom domain: `login.brand-1.com`
- `https://brand-2.yourapp.com` → Custom domain: `login.brand-2.com`

MCD is enabled by providing a **domain resolver function** instead of a static domain string.

See [Security Best Practices](#security-best-practices) for important guidance on configuring your resolver safely.

## Configuration Methods

### Method 1: Static Domain (Single Domain)

For applications with a single Auth0 domain:

```python
from auth0_server_python import ServerClient

client = ServerClient(
    domain="login.yourapp.com",  # Static string
    client_id="your_client_id",
    client_secret="your_client_secret",
    secret="your_encryption_secret"
)
```

### Method 2: Dynamic Domain Resolver (MCD)

For MCD support, provide a domain resolver function that receives a `DomainResolverContext`:

```python
from auth0_server_python import ServerClient
from auth0_server_python.auth_types import DomainResolverContext

# Map your app hostnames to Auth0 custom domains
DOMAIN_MAP = {
    "brand-1.yourapp.com": "login.brand-1.com",
    "brand-2.yourapp.com": "login.brand-2.com",
}
DEFAULT_DOMAIN = "login.yourapp.com"

async def domain_resolver(context: DomainResolverContext) -> str:
    """
    Resolve Auth0 domain based on request hostname.

    Args:
        context: Contains request_url and request_headers

    Returns:
        Auth0 domain string (e.g., "login.brand-1.com")
    """
    # Extract hostname from request headers
    if not context.request_headers:
        return DEFAULT_DOMAIN

    host = context.request_headers.get('host', DEFAULT_DOMAIN)
    host_without_port = host.split(':')[0]

    # Look up Auth0 domain
    return DOMAIN_MAP.get(host_without_port, DEFAULT_DOMAIN)

client = ServerClient(
    domain=domain_resolver,  # Callable function
    client_id="your_client_id",
    client_secret="your_client_secret",
    secret="your_encryption_secret"
)
```

## DomainResolverContext

The `DomainResolverContext` object provides request information to your resolver:

| Property | Type | Description |
|----------|------|-------------|
| `request_url` | `Optional[str]` | Full request URL (e.g., "https://brand-1.yourapp.com/auth/login") |
| `request_headers` | `Optional[dict[str, str]]` | Request headers dictionary |

**Common headers:**
- `host`: Request hostname (e.g., "brand-1.yourapp.com")
- `x-forwarded-host`: Original host when behind proxy/load balancer

**Example usage:**

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    # Check if we have request headers
    if not context.request_headers:
        return DEFAULT_DOMAIN

    # Use x-forwarded-host if behind proxy, otherwise use host
    host = (context.request_headers.get('x-forwarded-host') or
            context.request_headers.get('host', ''))

    # Remove port number if present
    hostname = host.split(':')[0].lower()

    # Look up in mapping
    return DOMAIN_MAP.get(hostname, DEFAULT_DOMAIN)
```

## Passing store_options

In resolver mode, pass `store_options` to each SDK call so the resolver can inspect the
current request and select the correct domain. If `store_options` are omitted, the resolver
receives empty context (`request_url=None`, `request_headers=None`).

All public SDK methods that interact with sessions or Auth0 endpoints accept `store_options`.
Here is an example using `get_user()`:

```python
# In your route handler, pass the framework request via store_options
store_options = {"request": request, "response": response}

# The SDK calls your domain_resolver with a DomainResolverContext
# built from the request in store_options
user = await client.get_user(store_options=store_options)
```

The same pattern applies to `get_session()`, `get_access_token()`, `start_interactive_login()`,
`logout()`, and all other session-aware methods.

## Redirect URI Requirements

In resolver mode, the SDK does not infer `redirect_uri` from the request. You must provide it
explicitly:

- Set a default `redirect_uri` when constructing `ServerClient`, or
- Pass `redirect_uri` in `authorization_params` for each login call.

Framework wrappers like `auth0-fastapi` handle this automatically by constructing the
`redirect_uri` from the incoming request's host and scheme.

> **Note:** In resolver mode, MCD needs an ID token in the callback so the SDK can validate
> the `iss` claim. The `openid` scope is required to receive an ID token. Ensure `openid` is
> included in your `authorization_params.scope`.

## Resolver Patterns

### Database Lookup (SQLAlchemy)

Resolve domains from a database using async SQLAlchemy:

```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy import text

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/mydb")

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]

    async with AsyncSession(engine) as session:
        result = await session.execute(
            text("SELECT auth0_domain FROM tenants WHERE slug = :slug"),
            {"slug": subdomain}
        )
        row = result.fetchone()
        if row:
            return row[0]

    return DEFAULT_DOMAIN
```

### Database Lookup with In-Memory Cache

Avoid hitting the database on every request by caching the domain map:

```python
import time

_domain_cache = {}
_cache_ttl = 300  # 5 minutes

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]

    now = time.time()
    cached = _domain_cache.get(subdomain)
    if cached and cached["expires_at"] > now:
        return cached["domain"]

    # Cache miss - fetch from database
    async with AsyncSession(engine) as session:
        result = await session.execute(
            text("SELECT auth0_domain FROM tenants WHERE slug = :slug"),
            {"slug": subdomain}
        )
        row = result.fetchone()
        domain = row[0] if row else DEFAULT_DOMAIN

    _domain_cache[subdomain] = {"domain": domain, "expires_at": now + _cache_ttl}
    return domain
```

### Redis Lookup

Use Redis for shared domain configuration across multiple app instances:

```python
import redis.asyncio as redis

redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]

    # Key format: "tenant:brand-1" -> "login.brand-1.com"
    domain = await redis_client.get(f"tenant:{subdomain}")
    if domain:
        return domain

    return DEFAULT_DOMAIN
```

### Redis with Hash Map

Store all domain mappings in a single Redis hash:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]

    # All domains in one hash: HGET tenant_domains brand-1 -> "login.brand-1.com"
    domain = await redis_client.hget("tenant_domains", subdomain)
    if domain:
        return domain

    return DEFAULT_DOMAIN
```

### Path-Based Resolution

Resolve from URL path instead of hostname:

```python
from urllib.parse import urlparse

async def domain_resolver(context: DomainResolverContext) -> str:
    if context.request_url:
        path = urlparse(context.request_url).path
        # URL pattern: /brand/brand-1/auth/login
        parts = path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "brand":
            name = parts[1]
            return DOMAIN_MAP.get(name, DEFAULT_DOMAIN)

    return DEFAULT_DOMAIN
```

### Custom Header Resolution

Use a custom header set by your API gateway or load balancer:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    headers = context.request_headers or {}

    # API gateway sets X-Brand-Id header
    brand_id = headers.get("x-brand-id")
    if brand_id:
        return DOMAIN_MAP.get(brand_id, DEFAULT_DOMAIN)

    # Fallback to host header
    host = headers.get("host", "").split(":")[0]
    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)
```

## Error Handling

### DomainResolverError

The domain resolver should return a valid Auth0 domain string. Invalid returns will raise `DomainResolverError`:

```python
from auth0_server_python.error import DomainResolverError

async def domain_resolver(context: DomainResolverContext) -> str:
    try:
        domain = lookup_domain_from_db(context)

        if not domain:
            # Return default instead of None
            return DEFAULT_DOMAIN

        return domain  # Must be a non-empty string

    except Exception as e:
        # Log error and return default
        logger.error(f"Domain resolution failed: {e}")
        return DEFAULT_DOMAIN
```

**Invalid return values that raise `DomainResolverError`:**
- `None`
- Empty string `""`
- Non-string types (int, list, dict, etc.)

**Exceptions raised by your resolver:**
- Automatically wrapped in `DomainResolverError`
- Original exception accessible via `.original_error`

## Session Behavior in Resolver Mode

In resolver mode, sessions are bound to the domain that created them. On each request, the SDK compares the session's stored domain against the current resolved domain. If the domains do not match:

- `get_user()` and `get_session()` return `None`.
- `get_access_token()` raises `AccessTokenError` (code `MISSING_SESSION_DOMAIN` or `DOMAIN_MISMATCH`).
- `get_access_token_for_connection()` raises `AccessTokenForConnectionError` (same codes as above).
- `start_link_user()` and `start_unlink_user()` raise `StartLinkUserError`.
- Token refresh uses the session's stored domain, not the current request domain.

All domain mismatch errors use the message: **"Session domain does not match the current domain."**

> **Note:** If a login was started before the switch to resolver mode and completes after, the SDK falls back to the current resolved domain for token exchange. The resulting session will store the resolved domain and work normally going forward.

## Legacy Sessions and Migration

When moving from a static domain setup to resolver mode, existing sessions can continue
to work if the resolver returns the same Auth0 domain that was used for those legacy sessions.

The SDK uses a three-tier fallback to determine the session's domain:

1. **`session.domain`** — new sessions created after MCD was enabled store this field.
2. **Static domain** — if a static `domain` string was configured, it is used as a fallback.
3. **User's issuer claim** — the hostname is extracted from the `iss` claim in the user's
   ID token (e.g., `https://login.brand-1.com/` yields `login.brand-1.com`).

This means legacy sessions created before MCD support will still work as long as the
resolver returns a domain that matches one of the fallback values. In most cases, the
issuer claim already matches the Auth0 domain, so no re-authentication is needed.

If the resolver returns a different domain that does not match any tier, the SDK treats
the session as belonging to another domain and the user will need to sign in again. This
is intentional to keep sessions isolated per domain.

## Discovery Cache

The SDK caches OIDC metadata and JWKS per domain in memory (LRU eviction, 600-second TTL, up to 100 domains). This avoids repeated network calls when serving multiple domains. The cache is shared across all requests to the same `ServerClient` instance.

Most applications can keep the defaults, but you may want to adjust in these cases:
- Increase `max_entries` if one process handles more than 100 distinct Auth0 domains during the TTL window. This is most common in MCD deployments that work with many custom domains.
- Decrease `max_entries` if memory usage matters more than avoiding repeated discovery.
- Increase TTL if the same domains are reused frequently and you want to reduce repeated discovery and JWKS fetches after cache entries expire.
- Decrease TTL if you want the SDK to pick up Auth0 metadata or signing key changes sooner.

Rule of thumb: set `max_entries` to cover the number of distinct Auth0 domains a single process is expected to use during the TTL window, with some headroom.

## Security Best Practices

> **The domain resolver is a security-critical component.** A misconfigured resolver can lead to authentication bypass on the relying party (RP) or expose the application to Server-Side Request Forgery (SSRF). The SDK trusts the resolved domain to fetch OIDC metadata and verification keys. It is the customer's responsibility to ensure the resolver cannot be influenced by untrusted input.

**Single Tenant Limitation:**
The domain resolver is intended solely for multiple custom domains belonging to the same Auth0 tenant. It is not a supported mechanism for connecting multiple Auth0 tenants to a single application.

### Use an Allowlist in Your Resolver

The SDK passes request headers to your domain resolver via `DomainResolverContext`. These headers come directly from the HTTP request and can be spoofed by an attacker (e.g., `Host: evil.com` or `X-Forwarded-Host: evil.com`).

The SDK uses the resolved domain to fetch OIDC metadata and JWKS. If an attacker can influence the resolved domain, they could point the SDK at an OIDC provider they control.

**Always use a mapping or allowlist — never construct domains from raw header values:**

```python
# Safe: allowlist lookup — unknown hosts fall back to default
DOMAIN_MAP = {
    "brand-1.yourapp.com": "login.brand-1.com",
    "brand-2.yourapp.com": "login.brand-2.com",
}

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)
```

```python
# Risky: constructs domain from raw input — attacker can influence resolved domain
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    subdomain = host.split(".")[0]
    return f"login.{subdomain}.com"  # attacker sends Host: evil.yourapp.com → login.evil.com
```

### Secure Proxy Requirement

When using Multiple Custom Domains (MCD), your application must be deployed behind a secure reverse proxy (e.g., Cloudflare, Nginx, or AWS ALB). The proxy must be configured to sanitize and overwrite `Host` and `X-Forwarded-Host` headers before they reach your application.

Without a trusted proxy layer to validate these headers, an attacker can manipulate the domain resolution process. This can result in authentication bypass or Server-Side Request Forgery (SSRF).

### Trust Forwarded Headers Only Behind a Proxy

If your application is directly exposed to the internet (not behind a reverse proxy), do not trust `x-forwarded-host` or `x-forwarded-proto` — any client can set these headers.

Only use forwarded headers when your application runs behind a trusted reverse proxy (nginx, AWS ALB, Cloudflare, etc.) that sets these headers and strips any client-provided values.

```python
# Only trust x-forwarded-host if behind a trusted proxy
async def domain_resolver(context: DomainResolverContext) -> str:
    headers = context.request_headers or {}

    if BEHIND_TRUSTED_PROXY:
        host = headers.get("x-forwarded-host") or headers.get("host", "")
    else:
        host = headers.get("host", "")

    host = host.split(":")[0]
    return DOMAIN_MAP.get(host, DEFAULT_DOMAIN)
```
