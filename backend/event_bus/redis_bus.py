"""
Redis Streams implementation of EventBus.

CRITICAL INVARIANT:
This file is the ONLY file in the entire SentinelX codebase allowed to import
redis or redis.asyncio.

Stream name: "sentinelx.events"
Consumer group: "sentinelx-consumers"
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import AsyncGenerator

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from event_bus.base import EventBus
from events.models import NormalizedEvent

logger = logging.getLogger(__name__)

DEFAULT_STREAM_NAME = "sentinelx.events"
DEFAULT_CONSUMER_GROUP = "sentinelx-consumers"


def create_redis_client(url: str) -> aioredis.Redis:  # type: ignore[type-arg]
    """Create a raw async Redis client for non-event-bus concerns.

    Used by core.container for auth-related Redis usage (login rate
    limiting, token revocation) that has nothing to do with the event bus.
    This function exists so that callers never need `import redis`
    themselves — this module remains the sole permitted import site.
    """
    return aioredis.from_url(url, decode_responses=True)


class RedisEventBus(EventBus):
    """EventBus implementation backed by Redis Streams.

    Uses XADD for publishing, XREADGROUP for consuming, and XACK for acknowledging.
    Generates a unique consumer name per instance if not provided.
    """

    def __init__(
        self,
        redis_client: aioredis.Redis,  # type: ignore[type-arg]
        stream_name: str = DEFAULT_STREAM_NAME,
        poll_block_ms: int = 1000,
        yield_delay_s: float = 0.05,
    ) -> None:
        self._redis = redis_client
        self._stream_name = stream_name
        self._poll_block_ms = poll_block_ms
        self._yield_delay_s = yield_delay_s
        self._instance_id = str(uuid.uuid4())[:8]

    @classmethod
    def from_url(cls, url: str, stream_name: str = DEFAULT_STREAM_NAME) -> RedisEventBus:
        """Create RedisEventBus instance from a Redis URL string."""
        client = aioredis.from_url(url, decode_responses=False)
        return cls(redis_client=client, stream_name=stream_name)

    async def close(self) -> None:
        """Close underlying Redis connection."""
        await self._redis.aclose()  # type: ignore[attr-defined]

    def generate_consumer_name(self, prefix: str = "worker") -> str:
        """Generate a per-worker consumer name (never hardcoded globally)."""
        return f"{prefix}-{self._instance_id}-{uuid.uuid4().hex[:6]}"

    async def publish(self, event: NormalizedEvent) -> None:
        """Publish a NormalizedEvent to Redis Streams via XADD."""
        payload = event.model_dump_json()
        await self._redis.xadd(
            self._stream_name,
            fields={"event_id": event.event_id, "data": payload},
        )
        logger.debug(
            "Published event %s to stream %s", event.event_id, self._stream_name
        )

    async def _ensure_consumer_group(self, group: str) -> None:
        """Create consumer group if it doesn't already exist."""
        try:
            await self._redis.xgroup_create(
                name=self._stream_name,
                groupname=group,
                id="0",
                mkstream=True,
            )
        except ResponseError as err:
            if "BUSYGROUP" not in str(err):
                raise

    async def consume(
        self,
        consumer_group: str = DEFAULT_CONSUMER_GROUP,
        consumer_name: str | None = None,
    ) -> AsyncGenerator[tuple[str, NormalizedEvent], None]:
        """Yield (message_id, NormalizedEvent) from Redis stream.

        Guarantees:
        - Yields control via asyncio.sleep on empty polls to prevent event-loop starvation.
        - Malformed messages are NOT silently XACK'd — they raise or log as un-acked.
        """
        await self._ensure_consumer_group(consumer_group)
        c_name = consumer_name or self.generate_consumer_name()

        while True:
            try:
                entries = await self._redis.xreadgroup(
                    groupname=consumer_group,
                    consumername=c_name,
                    streams={self._stream_name: ">"},
                    count=10,
                    block=self._poll_block_ms,
                )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error reading from Redis Stream: %s", exc)
                await asyncio.sleep(self._yield_delay_s)
                continue

            if not entries:
                # Empty poll: yield control explicitly to avoid starving asyncio loop
                await asyncio.sleep(self._yield_delay_s)
                continue

            for stream_key, message_list in entries:
                for msg_id_bytes, message_dict in message_list:
                    msg_id = (
                        msg_id_bytes.decode()
                        if isinstance(msg_id_bytes, bytes)
                        else str(msg_id_bytes)
                    )
                    raw_data = message_dict.get(b"data") or message_dict.get("data")
                    if not raw_data:
                        logger.error("Message %s missing data payload; not XACKing", msg_id)
                        continue

                    if isinstance(raw_data, bytes):
                        raw_data = raw_data.decode("utf-8")

                    try:
                        parsed_json = json.loads(raw_data)
                        event = NormalizedEvent(**parsed_json)
                        yield msg_id, event
                    except Exception as parse_err:
                        logger.error(
                            "Failed to parse event from msg %s: %s. Message NOT XACK'd.",
                            msg_id,
                            parse_err,
                        )
                        # Malformed message is NOT silently XACK'd
                        continue

    async def ack(
        self,
        consumer_group: str = DEFAULT_CONSUMER_GROUP,
        message_id: str = "",
    ) -> None:
        """Acknowledge message processing via XACK."""
        if not message_id:
            return
        await self._redis.xack(self._stream_name, consumer_group, message_id)
