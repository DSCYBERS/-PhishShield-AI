"""
Redis configuration and initialization
"""

import redis.asyncio as redis
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)

# Redis connection pool
redis_pool = None

async def init_redis():
    """Initialize Redis connection"""
    global redis_pool
    try:
        redis_pool = redis.ConnectionPool.from_url(
            settings.REDIS_URL,
            decode_responses=True
        )
        logger.info("Redis initialized")
    except Exception as e:
        logger.error(f"Redis initialization failed: {e}")
        raise

async def get_redis():
    """Get Redis connection"""
    return redis.Redis(connection_pool=redis_pool)
