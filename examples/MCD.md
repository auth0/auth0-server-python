# Multiple Custom Domains (MCD) Guide

This guide explains how to implement Multiple Custom Domain (MCD) support using the Auth0 Python SDKs.

## What is MCD?

Multiple Custom Domains (MCD) allows your application to serve different organizations or tenants from different hostnames, each mapping to a different Auth0 tenant/domain.

**Example:**
- `https://acme.yourapp.com` → Auth0 tenant: `acme.auth0.com`
- `https://globex.yourapp.com` → Auth0 tenant: `globex.auth0.com`

Each tenant gets its own branded login experience while using a single application codebase.

## Configuration Methods

### Method 1: Static Domain (Single Tenant)

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