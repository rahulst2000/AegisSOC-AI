import asyncio
import logging
import uuid
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.engine import DetectionEngine
from app.detection.models import DetectionResult
from app.models.event import SecurityEvent
from app.workers.queue import dequeue_event, enqueue_detection_for_correlation

logger = logging.getLogger(__name__)


class DetectionWorker:
    """
    Asynchronous background worker consuming ingested security events from the queue,
    running detection evaluation, and enqueueing verified detections for correlation.
    """

    def __init__(self, engine: DetectionEngine | None = None) -> None:
        self.engine = engine or DetectionEngine()

    async def process_next_event(self, db: AsyncSession) -> list[DetectionResult]:
        """Pulls and processes a single event task from the queue."""
        item = await dequeue_event()
        if not item:
            return []

        try:
            event_id = uuid.UUID(item["event_id"])
            tenant_id = uuid.UUID(item["tenant_id"])
        except (KeyError, ValueError) as exc:
            logger.error(f"Malformed queue payload {item}: {exc}")
            return []

        # Fetch SecurityEvent bounded strictly to tenant_id
        stmt = select(SecurityEvent).where(
            SecurityEvent.id == event_id,
            SecurityEvent.tenant_id == tenant_id,
        )
        res = await db.execute(stmt)
        event = res.scalars().first()
        if not event:
            logger.warning(f"Event {event_id} not found for tenant {tenant_id}")
            return []

        # Run detection engine
        detections = await self.engine.evaluate_events(db=db, tenant_id=tenant_id, events=[event])

        # Enqueue generated detections for correlation
        for det in detections:
            await enqueue_detection_for_correlation(
                detection_id=str(det.id),
                tenant_id=str(det.tenant_id),
            )

        return detections

    async def process_batch(self, db: AsyncSession, max_items: int = 50) -> list[DetectionResult]:
        """Processes up to max_items events from the queue in a batch."""
        all_detections: list[DetectionResult] = []
        for _ in range(max_items):
            detections = await self.process_next_event(db)
            if not detections and not all_detections:
                break
            all_detections.extend(detections)
        return all_detections

    async def run_worker_loop(
        self,
        session_factory: Callable[[], AsyncSession],
        stop_event: asyncio.Event | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        """Continuous background execution loop."""
        logger.info("DetectionWorker daemon loop started.")
        while stop_event is None or not stop_event.is_set():
            try:
                async with session_factory() as session:
                    processed = await self.process_next_event(session)
                    if not processed:
                        await asyncio.sleep(poll_interval)
            except Exception as exc:
                logger.error(f"Error in DetectionWorker loop: {exc}", exc_info=True)
                await asyncio.sleep(poll_interval)
