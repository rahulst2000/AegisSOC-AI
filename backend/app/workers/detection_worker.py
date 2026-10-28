import asyncio
import logging
import uuid
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.engine import DetectionEngine
from app.detection.models import DetectionResult
from app.models.event import SecurityEvent
from app.models.evidence import Evidence
from app.workers.queue import dequeue_event, enqueue_detection_for_correlation

logger = logging.getLogger(__name__)


class DetectionWorker:
    """
    Asynchronous background worker consuming ingested security events from the queue,
    running detection evaluation, and enqueueing verified detections for correlation.
    """

    def __init__(self, engine: DetectionEngine | None = None) -> None:
        self.engine = engine or DetectionEngine()
        self._evaluated_event_ids: set[uuid.UUID] = set()

    async def process_next_event(
        self,
        db: AsyncSession,
        tenant_id: uuid.UUID | None = None,
    ) -> list[DetectionResult]:
        """Pulls and processes a single event task from the queue or DB fallback."""
        item = await dequeue_event()
        event: SecurityEvent | None = None
        target_tenant_id: uuid.UUID | None = tenant_id

        if item:
            try:
                event_id = uuid.UUID(item["event_id"])
                item_tenant_id = uuid.UUID(item["tenant_id"])
            except (KeyError, ValueError) as exc:
                logger.error(f"Malformed queue payload {item}: {exc}")
                return []

            if target_tenant_id and item_tenant_id != target_tenant_id:
                from app.workers.queue import enqueue_event_for_detection

                await enqueue_event_for_detection(str(event_id), str(item_tenant_id))
            else:
                target_tenant_id = item_tenant_id
                # Fetch SecurityEvent bounded strictly to tenant_id
                stmt = select(SecurityEvent).where(
                    SecurityEvent.id == event_id,
                    SecurityEvent.tenant_id == target_tenant_id,
                )
                res = await db.execute(stmt)
                event = res.scalars().first()
                if not event:
                    logger.warning(f"Event {event_id} not found for tenant {target_tenant_id}")

        if not event:
            # Resilient self-healing fallback when Redis is absent or on container restart:
            # Scan for SecurityEvents not yet resolved into an incident
            resolved_event_ids_stmt = select(Evidence.event_id).where(Evidence.incident_id.is_not(None))
            query = select(SecurityEvent).where(SecurityEvent.id.not_in(resolved_event_ids_stmt))
            if target_tenant_id:
                query = query.where(SecurityEvent.tenant_id == target_tenant_id)
            stmt = query.order_by(SecurityEvent.timestamp.asc()).limit(50)
            res = await db.execute(stmt)
            all_events = list(res.scalars().all())
            unprocessed = [e for e in all_events if e.id not in self._evaluated_event_ids]
            if not unprocessed:
                return []
            event = unprocessed[0]
            target_tenant_id = event.tenant_id

        self._evaluated_event_ids.add(event.id)

        # Run detection engine
        detections = await self.engine.evaluate_events(db=db, tenant_id=target_tenant_id, events=[event])

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
            except asyncio.CancelledError:
                logger.info("DetectionWorker received cancellation signal.")
                break
            except Exception as exc:
                logger.error(f"Error in DetectionWorker loop: {exc}", exc_info=True)
                await asyncio.sleep(poll_interval)
