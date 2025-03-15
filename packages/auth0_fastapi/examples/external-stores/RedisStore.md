# Examples
## Integration of Third Party Storage
### Redis Store
## Setting Up Redis Store
### Installation
```bash
pip install redis
```

### Extending Base Store
```python
class RedisStore(BaseStore):
    """
    Redis-based session storage implementation.
    """
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        prefix: str = "auth0_session:",
        ttl: Optional[int] = None,
        **kwargs
    ):
        """
        Initialize Redis store.
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            prefix: Key prefix for session data
            ttl: Time to live for session data in seconds
            **kwargs: Additional Redis connection arguments
        """
        self.prefix = prefix
        self.ttl = ttl
        try:
            self.redis = redis.Redis(
                host=host,
                port=port,
                db=db,
                password=password,
                decode_responses=True,
                **kwargs
            )
            # Test connection
            self.redis.ping()
        except RedisError as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            raise
```
### Usage Example
```python
from auth_client import AuthClient
from auth_client.stores import RedisStore
# Create a Redis store
redis_store = RedisStore(
    host="redis.example.com",
    port=6379,
    password="your_redis_password",
    ttl=3600  # 1 hour session TTL
)
# Initialize AIAuth with Redis store
auth_client = AuthClient(config, state_store=custom_state_store)

```
### Environment Variable Configuration
Redis connection can be configured using environment variables:
- `REDIS_HOST`: Redis server hostname (default: "localhost")
- `REDIS_PORT`: Redis server port (default: 6379)
- `REDIS_PASSWORD`: Redis password (default: None)
- `REDIS_DB`: Redis database number (default: 0)
- `REDIS_PREFIX`: Key prefix for session data (default: "auth0_session:")
- `REDIS_TTL`: Session time-to-live in seconds (default: 86400)
