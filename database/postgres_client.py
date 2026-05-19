"""PostgreSQL Client - اتصال قاعدة البيانات الاحترافي"""
import asyncio, json, logging
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False

logger = logging.getLogger(__name__)

class PostgresClient:
    def __init__(self, dsn: str = None):
        self.dsn = dsn or "postgresql://huntermind:huntermind@localhost:5432/huntermind"
        self.pool = None
    
    async def connect(self):
        if not ASYNCPG_AVAILABLE:
            logger.warning("asyncpg not installed - using fallback")
            return
        try:
            self.pool = await asyncpg.create_pool(self.dsn, min_size=2, max_size=10, command_timeout=30)
            logger.info("PostgreSQL connected")
        except Exception as e:
            logger.warning(f"PostgreSQL unavailable: {e}")
    
    async def execute(self, query: str, *args) -> Any:
        if self.pool:
            async with self.pool.acquire() as conn:
                return await conn.execute(query, *args)
        return None
    
    async def fetch(self, query: str, *args) -> List[Dict]:
        if self.pool:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, *args)
                return [dict(r) for r in rows]
        return []
    
    async def fetchrow(self, query: str, *args) -> Optional[Dict]:
        if self.pool:
            async with self.pool.acquire() as conn:
                row = await conn.fetchrow(query, *args)
                return dict(row) if row else None
        return None
    
    async def close(self):
        if self.pool:
            await self.pool.close()
    
    def is_connected(self) -> bool:
        return self.pool is not None

_default_client = None

async def get_postgres_client() -> PostgresClient:
    global _default_client
    if _default_client is None:
        _default_client = PostgresClient()
        await _default_client.connect()
    return _default_client
