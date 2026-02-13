# Multiple Custom Domains (MCD) Guide

This guide explains how to implement Multiple Custom Domain (MCD) support using the Auth0 Python SDKs.

## What is MCD?

Multiple Custom Domains (MCD) allows your application to use multiple custom domains configured on the same Auth0 tenant, each serving a different branded experience from a single application codebase.

**Example:**
- `https://acme.yourapp.com` → Custom domain: `auth.acme.com`
- `https://globex.yourapp.com` → Custom domain: `auth.globex.com`

## Configuration Methods

### Method 1: Static Domain (Single Domain)

For applications with a single Auth0 domain:

```python
from auth0_server_python import ServerClient

client = ServerClient(
    domain="your-tenant.auth0.com",  # Static string
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

# Map your app hostnames to Auth0 domains
DOMAIN_MAP = {
    "acme.yourapp.com": "acme.auth0.com",
    "globex.yourapp.com": "globex.auth0.com",
}
DEFAULT_DOMAIN = "default.auth0.com"

async def domain_resolver(context: DomainResolverContext) -> str:
    """
    Resolve Auth0 domain based on request hostname.
    
    Args:
        context: Contains request_url and request_headers
        
    Returns:
        Auth0 domain string (e.g., "acme.auth0.com")
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
| `request_url` | `Optional[str]` | Full request URL (e.g., "https://acme.yourapp.com/auth/login") |
| `request_headers` | `Optional[dict[str, str]]` | Request headers dictionary |

**Common headers:**
- `host`: Request hostname (e.g., "acme.yourapp.com")
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

## Resolver Patterns

### Database Lookup (SQLAlchemy)

Resolve domains from a database using async SQLAlchemy:

```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy import text

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/mydb")

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    tenant = host.split(".")[0]

    async with AsyncSession(engine) as session:
        result = await session.execute(
            text("SELECT auth0_domain FROM tenants WHERE slug = :slug"),
            {"slug": tenant}
        )
        row = result.fetchone()
        if row:
            return row[0]

    return DEFAULT_DOMAIN
```

### Database Lookup with In-Memory Cache

Avoid hitting the database on every request by caching the tenant map:

```python
import time

_tenant_cache = {}
_cache_ttl = 300  # 5 minutes

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    tenant = host.split(".")[0]

    now = time.time()
    cached = _tenant_cache.get(tenant)
    if cached and cached["expires_at"] > now:
        return cached["domain"]

    # Cache miss - fetch from database
    async with AsyncSession(engine) as session:
        result = await session.execute(
            text("SELECT auth0_domain FROM tenants WHERE slug = :slug"),
            {"slug": tenant}
        )
        row = result.fetchone()
        domain = row[0] if row else DEFAULT_DOMAIN

    _tenant_cache[tenant] = {"domain": domain, "expires_at": now + _cache_ttl}
    return domain
```

### Redis Lookup

Use Redis for shared tenant configuration across multiple app instances:

```python
import redis.asyncio as redis

redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    tenant = host.split(".")[0]

    # Key format: "tenant:acme" -> "acme.auth0.com"
    domain = await redis_client.get(f"tenant:{tenant}")
    if domain:
        return domain

    return DEFAULT_DOMAIN
```

### Redis with Hash Map

Store all tenant mappings in a single Redis hash:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    host = context.request_headers.get("host", "").split(":")[0]
    tenant = host.split(".")[0]

    # All tenants in one hash: HGET tenant_domains acme -> "acme.auth0.com"
    domain = await redis_client.hget("tenant_domains", tenant)
    if domain:
        return domain

    return DEFAULT_DOMAIN
```

### Path-Based Resolution

Resolve tenant from URL path instead of hostname:

```python
from urllib.parse import urlparse

async def domain_resolver(context: DomainResolverContext) -> str:
    if context.request_url:
        path = urlparse(context.request_url).path
        # URL pattern: /tenant/acme/auth/login
        parts = path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "tenant":
            tenant = parts[1]
            return DOMAIN_MAP.get(tenant, DEFAULT_DOMAIN)

    return DEFAULT_DOMAIN
```

### Custom Header Resolution

Use a custom header set by your API gateway or load balancer:

```python
async def domain_resolver(context: DomainResolverContext) -> str:
    headers = context.request_headers or {}

    # API gateway sets X-Tenant-Id header
    tenant_id = headers.get("x-tenant-id")
    if tenant_id:
        return DOMAIN_MAP.get(tenant_id, DEFAULT_DOMAIN)

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