# Examples
## Integration of Third Party Storage
### Postgres Store
## Setting Up Postgres Store
### Installation
```bash
pip install psycopg2-binary
```

### Extending Base Store
```python
class PostgresStore(BaseStore):
    """
    Postgres-based session storage implementation.
    """
    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        dbname: str = "auth_sessions",
        user: str = "postgres",
        password: str = "password",
        table: str = "sessions",
        ttl: Optional[int] = None,
        **kwargs
    ):
        """
        Initialize Postgres store.
        Args:
            host: Postgres host
            port: Postgres port
            dbname: Database name
            user: Postgres username
            password: Postgres password
            table: Table name for session storage
            ttl: Optional TTL for session records
            **kwargs: Additional psycopg2 connection arguments
        """
        self.table = table
        self.ttl = ttl

        try:
            self.conn = psycopg2.connect(
                host=host,
                port=port,
                dbname=dbname,
                user=user,
                password=password,
                **kwargs
            )
            self._ensure_table_exists()
        except OperationalError as e:
            logger.error(f"Failed to connect to PostgreSQL: {str(e)}")
            raise

    def _ensure_table_exists(self):
        """
        Create the sessions table if it doesn't exist.
        """
        with self.conn.cursor() as cursor:
            cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {self.table} (
                session_id VARCHAR(255) PRIMARY KEY,
                data JSONB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
            """)
            self.conn.commit()
```
### Usage Example
```python
from auth_client import Auth
from auth_client.stores import PostgresStore

#Create a Postgres store
postgres_store = PostgresStore(
    host="postgres.example.com",
    port=5432,
    dbname="auth_sessions",
    user="your_db_user",
    password="your_db_password",
    table="sessions",
    ttl=3600  # Optional TTL - 1 hour
)
# Initialize AIAuth with Redis store
auth = Auth(store=<store_name>)

```
### Environment Variable Configuration
Postgres connection can be configured using environment variables:
- `POSTGRES_HOST`: Postgres server hostname (default: "localhost")
- `POSTGRES_PORT`:  Postgres server port (default: 5432)
- `POSTGRES_DB`: Postgres database name (default: "auth_sessions")
- `POSTGRES_USER`: Postgres username (default: "postgres")
- `POSTGRES_PASSWORD`: Postgres password (default: "password")
- `POSTGRES_TABLE`: Table name for session data (default: "sessions")
- `POSTGRES_TTL`: Session time-to-live in seconds (optional)
