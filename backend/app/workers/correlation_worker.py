import asyncio
import logging
import uuid
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.correlator import Correlator
from app.detection.models import DetectionResult
from app.models.incident import Incident
from app.workers.queue import dequeue_detection

logger = logging.getLogger(__name__)


class CorrelationWorker:
    """
    Asynchronous background worker consuming generated detections from the queue,
    executing multi-vector correlation, and updating/creating Incidents.
    """

    def __init__(self, correlator: Correlator | None = None) -> None:
        self.correlator = correlator or Correlator()

    async def process_next_detection(
        self,
        db: AsyncSession,
        tenant_id: uuid.UUID | None = None,
    ) -> list[Incident]:
        """Pulls and correlates a single detection task from the queue or DB fallback."""
        item = await dequeue_detection()
        detection: DetectionResult | None = None
        target_tenant_id: uuid.UUID | None = tenant_id

        if item:
            try:
                detection_id = uuid.UUID(item["detection_id"])
                item_tenant_id = uuid.UUID(item["tenant_id"])
            except (KeyError, ValueError) as exc:
                logger.error(f"Malformed detection queue payload {item}: {exc}")
                return []

            if target_tenant_id and item_tenant_id != target_tenant_id:
                from app.workers.queue import enqueue_detection_for_correlation

                await enqueue_detection_for_correlation(str(detection_id), str(item_tenant_id))
            else:
                target_tenant_id = item_tenant_id
                stmt = select(DetectionResult).where(
                    DetectionResult.id == detection_id,
                    DetectionResult.tenant_id == target_tenant_id,
                )
                res = await db.execute(stmt)
                detection = res.scalars().first()
                if not detection:
                    logger.warning(f"Detection {detection_id} not found for tenant {target_tenant_id}")

        if not detection:
            # Resilient self-healing fallback when Redis is absent or on container restart:
            # Scan for any un-correlated DetectionResult in the database
            query = select(DetectionResult)
            if target_tenant_id:
                query = query.where(DetectionResult.tenant_id == target_tenant_id)
            stmt = query.order_by(DetectionResult.timestamp.asc()).limit(50)
            res = await db.execute(stmt)
            all_dets = list(res.scalars().all())
            if not all_dets:
                return []

            for candidate in all_dets:
                inc_stmt = select(Incident).where(Incident.tenant_id == candidate.tenant_id)
                inc_res = await db.execute(inc_stmt)
                tenant_incs = list(inc_res.scalars().all())
                is_linked = any(str(candidate.id) in (inc.detection_ids or []) for inc in tenant_incs)
                if not is_linked:
                    detection = candidate
                    target_tenant_id = candidate.tenant_id
                    break

            if not detection or not target_tenant_id:
                return []

        incidents = await self.correlator.correlate_detections(
            db=db,
            tenant_id=target_tenant_id,
            detections=[detection],
        )
        return incidents

    async def process_batch(self, db: AsyncSession, max_items: int = 50) -> list[Incident]:
        """Processes up to max_items detection events from the queue."""
        all_incidents: list[Incident] = []
        for _ in range(max_items):
            incidents = await self.process_next_detection(db)
            if not incidents and not all_incidents:
                break
            all_incidents.extend(incidents)
        return all_incidents

    async def run_worker_loop(
        self,
        session_factory: Callable[[], AsyncSession],
        stop_event: asyncio.Event | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        """Continuous background execution loop."""
        logger.info("CorrelationWorker daemon loop started.")
        while stop_event is None or not stop_event.is_set():
            try:
                async with session_factory() as session:
                    processed = await self.process_next_detection(session)
                if not processed:
                    await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                logger.info("CorrelationWorker received cancellation signal.")
                break
            except Exception as exc:
                logger.error(f"Error in CorrelationWorker loop: {exc}", exc_info=True)
                await asyncio.sleep(poll_interval)
