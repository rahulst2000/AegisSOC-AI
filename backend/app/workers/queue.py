import json
import logging
import time
from collections import deque
from typing import Any

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger(__name__)

EVENT_QUEUE_KEY = "aegis:queue:events"
DETECTION_QUEUE_KEY = "aegis:queue:detections"

# In-memory fallback queue for zero-loss operation when Redis is unavailable
_in_memory_event_queue: deque[dict[str, Any]] = deque()
_in_memory_detection_queue: deque[dict[str, Any]] = deque()
_last_redis_error: str | None = None
_fallback_mode_active: bool = False
_last_redis_check_time: float = 0.0
_REDIS_RETRY_INTERVAL: float = 30.0


async def get_redis_client() -> aioredis.Redis | None:
    """Returns an async Redis client, or None if connection fails."""
    global _last_redis_error, _fallback_mode_active, _last_redis_check_time
    now = time.monotonic()
    if _fallback_mode_active and (now - _last_redis_check_time < _REDIS_RETRY_INTERVAL):
        return None

    _last_redis_check_time = now
    try:
        client = aioredis.from_url(
            settings.get_redis_url(),
            socket_timeout=1.0,
            socket_connect_timeout=1.0,
        )
        await client.ping()
        _last_redis_error = None
        _fallback_mode_active = False
        return client
    except Exception as exc:
        _last_redis_error = str(exc)
        _fallback_mode_active = True
        return None


async def enqueue_event_for_detection(event_id: str, tenant_id: str) -> bool:
    """
    Pushes an ingested event reference to the detection queue.
    If Redis is unavailable, safely routes to in-memory fallback without losing the event.
    """
    payload = {"event_id": event_id, "tenant_id": tenant_id}
    client = await get_redis_client()

    if client:
        try:
            await client.lpush(EVENT_QUEUE_KEY, json.dumps(payload))
            await client.aclose()
            return True
        except Exception as exc:
            logger.warning(f"Failed to enqueue event to Redis: {exc}. Storing in fallback queue.")
            _in_memory_event_queue.append(payload)
            return False
    else:
        # Resilient fallback mode
        _in_memory_event_queue.append(payload)
        return False


async def dequeue_event() -> dict[str, Any] | None:
    """Dequeues the next pending event from Redis or the fallback queue."""
    # First check fallback queue
    if _in_memory_event_queue:
        return _in_memory_event_queue.popleft()

    client = await get_redis_client()
    if not client:
        return None

    try:
        item = await client.rpop(EVENT_QUEUE_KEY)
        await client.aclose()
        if item:
            return json.loads(item)
    except Exception as exc:
        logger.error(f"Error reading from Redis event queue: {exc}")
    return None


async def enqueue_detection_for_correlation(detection_id: str, tenant_id: str) -> bool:
    """Pushes a detection result reference to the correlation queue."""
    payload = {"detection_id": detection_id, "tenant_id": tenant_id}
    client = await get_redis_client()

    if client:
        try:
            await client.lpush(DETECTION_QUEUE_KEY, json.dumps(payload))
            await client.aclose()
            return True
        except Exception as exc:
            logger.warning(f"Failed to enqueue detection to Redis: {exc}. Storing in fallback queue.")
            _in_memory_detection_queue.append(payload)
            return False
    else:
        _in_memory_detection_queue.append(payload)
        return False


async def dequeue_detection() -> dict[str, Any] | None:
    """Dequeues the next pending detection from Redis or the fallback queue."""
    if _in_memory_detection_queue:
        return _in_memory_detection_queue.popleft()

    client = await get_redis_client()
    if not client:
        return None

    try:
        item = await client.rpop(DETECTION_QUEUE_KEY)
        await client.aclose()
        if item:
            return json.loads(item)
    except Exception as exc:
        logger.error(f"Error reading from Redis detection queue: {exc}")
    return None


async def get_queue_health() -> dict[str, Any]:
    """Exposes queue status, connection health, and fallback metrics."""
    client = await get_redis_client()
    redis_connected = client is not None
    redis_event_count = 0
    redis_detection_count = 0

    if client:
        try:
            redis_event_count = await client.llen(EVENT_QUEUE_KEY)
            redis_detection_count = await client.llen(DETECTION_QUEUE_KEY)
            await client.aclose()
        except Exception as exc:
            logger.debug("Failed to query Redis queue lengths: %s", exc)

    return {
        "redis_connected": redis_connected,
        "fallback_mode": _fallback_mode_active,
        "last_error": _last_redis_error,
        "redis_pending_events": redis_event_count,
        "redis_pending_detections": redis_detection_count,
        "fallback_pending_events": len(_in_memory_event_queue),
        "fallback_pending_detections": len(_in_memory_detection_queue),
    }
