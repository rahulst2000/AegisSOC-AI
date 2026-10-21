import logging
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.correlation_rules import CorrelationConfig
from app.correlation.incident_builder import build_or_update_incident, ensure_utc
from app.detection.models import DetectionResult
from app.models.event import SecurityEvent
from app.models.incident import Incident

logger = logging.getLogger(__name__)


class Correlator:
    """
    Correlation engine grouping detection results and security events across
    attacker dimensions (IP, user, host, time window) into unified incidents.
    Guarantees strict tenant isolation.
    """

    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self.config = config or CorrelationConfig()

    async def correlate_detections(
        self,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        detections: list[DetectionResult],
    ) -> list[Incident]:
        """
        Correlates detections for a tenant into incidents.
        Never correlates across tenant boundaries.
        """
        if not detections:
            return []

        # Enforce tenant isolation invariant
        for d in detections:
            if d.tenant_id != tenant_id:
                raise ValueError(
                    f"Cross-tenant correlation attempted: Detection {d.id} tenant {d.tenant_id} != {tenant_id}"
                )

        # Retrieve underlying SecurityEvents for all detections
        all_event_ids_str: set[str] = set()
        for d in detections:
            all_event_ids_str.update(d.event_ids or [])

        event_uuid_map: dict[str, uuid.UUID] = {}
        for eid in all_event_ids_str:
            try:
                event_uuid_map[eid] = uuid.UUID(eid)
            except ValueError:
                continue

        events_by_id: dict[str, SecurityEvent] = {}
        if event_uuid_map:
            stmt = select(SecurityEvent).where(
                SecurityEvent.tenant_id == tenant_id,
                SecurityEvent.id.in_(list(event_uuid_map.values())),
            )
            res = await db.execute(stmt)
            for evt in res.scalars().all():
                events_by_id[str(evt.id)] = evt

        # Cluster detections by entity (IP or Username or Host)
        # Key: cluster_key (e.g. "ip:192.168.1.100" or "user:admin" or "global:default")
        clusters: dict[str, list[DetectionResult]] = {}

        for d in detections:
            det_events = [events_by_id[eid] for eid in (d.event_ids or []) if eid in events_by_id]
            assigned_cluster = False

            # Cluster by source_ip
            for e in det_events:
                if e.source_ip:
                    clusters.setdefault(f"ip:{e.source_ip}", []).append(d)
                    assigned_cluster = True
                    break

            if assigned_cluster:
                continue

            # Fallback cluster by username
            for e in det_events:
                if e.username:
                    clusters.setdefault(f"user:{e.username}", []).append(d)
                    assigned_cluster = True
                    break

            if assigned_cluster:
                continue

            # Fallback cluster by rule/tenant
            clusters.setdefault(f"rule:{d.rule_id}", []).append(d)

        incidents: list[Incident] = []

        for _cluster_key, cluster_dets in clusters.items():
            # Deduplicate detections in cluster
            unique_dets: list[DetectionResult] = []
            seen_det_ids: set[uuid.UUID] = set()
            for cd in cluster_dets:
                if cd.id not in seen_det_ids:
                    seen_det_ids.add(cd.id)
                    unique_dets.append(cd)

            # Sort by timestamp
            unique_dets.sort(key=lambda x: ensure_utc(x.timestamp))

            # Check temporal window separation
            # If events within cluster are separated by more than correlation window, partition into sub-clusters
            window_minutes = self.config.DEFAULT_CORRELATION_WINDOW_MINUTES
            window_delta = timedelta(minutes=window_minutes)

            sub_clusters: list[list[DetectionResult]] = []
            current_sub: list[DetectionResult] = []

            for det in unique_dets:
                if not current_sub:
                    current_sub.append(det)
                else:
                    if ensure_utc(det.timestamp) - ensure_utc(current_sub[-1].timestamp) <= window_delta:
                        current_sub.append(det)
                    else:
                        sub_clusters.append(current_sub)
                        current_sub = [det]
            if current_sub:
                sub_clusters.append(current_sub)

            # Build or update incident for each sub-cluster
            for sub in sub_clusters:
                sub_event_ids: set[str] = set()
                for sd in sub:
                    sub_event_ids.update(sd.event_ids or [])

                sub_events = [events_by_id[eid] for eid in sub_event_ids if eid in events_by_id]
                incident = await build_or_update_incident(
                    db=db,
                    tenant_id=tenant_id,
                    detections=sub,
                    events=sub_events,
                    correlation_window_minutes=window_minutes,
                )
                incidents.append(incident)

        return incidents
