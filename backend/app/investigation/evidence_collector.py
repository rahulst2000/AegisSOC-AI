import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.timeline import get_incident_timeline as fetch_incident_timeline
from app.detection.mitre_mapper import MitreAttackCatalog
from app.detection.models import DetectionResult
from app.models.asset import Asset
from app.models.event import SecurityEvent
from app.models.incident import Incident


class EvidenceCollector:
    """
    Controlled, read-only evidence retrieval toolkit.
    Strictly tenant-scoped. Returns structured forensic records with evidence IDs.
    Does NOT allow raw SQL or arbitrary commands.
    """

    def __init__(self, db: AsyncSession, tenant_id: uuid.UUID):
        self.db = db
        self.tenant_id = tenant_id

    async def get_event(self, event_id: uuid.UUID | str) -> dict[str, Any] | None:
        """Retrieves a single SecurityEvent within the tenant."""
        try:
            parsed_id = uuid.UUID(str(event_id))
        except ValueError:
            return None

        stmt = select(SecurityEvent).where(
            SecurityEvent.id == parsed_id,
            SecurityEvent.tenant_id == self.tenant_id,
        )
        res = await self.db.execute(stmt)
        event = res.scalars().first()
        if not event:
            return None

        return {
            "id": str(event.id),
            "event_type": event.event_type,
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
            "destination_ip": (
                event.normalized_event.get("destination", {}).get("ip")
                if isinstance(event.normalized_event, dict)
                else None
            ),
            "user_name": event.username,
            "hostname": event.hostname,
            "severity": event.severity,
            "normalized_event": event.normalized_event,
            "raw_payload": event.raw_event,
        }

    async def search_events(
        self,
        event_type: str | None = None,
        source_ip: str | None = None,
        user_name: str | None = None,
        hostname: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Searches events within tenant by specific normalized criteria."""
        stmt = select(SecurityEvent).where(SecurityEvent.tenant_id == self.tenant_id)
        if event_type:
            stmt = stmt.where(SecurityEvent.event_type == event_type)
        if source_ip:
            stmt = stmt.where(SecurityEvent.source_ip == source_ip)
        if user_name:
            stmt = stmt.where(SecurityEvent.username == user_name)
        if hostname:
            stmt = stmt.where(SecurityEvent.hostname == hostname)

        stmt = stmt.order_by(SecurityEvent.timestamp.desc()).limit(min(limit, 100))
        res = await self.db.execute(stmt)
        events = res.scalars().all()

        return [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat(),
                "source_ip": e.source_ip,
                "destination_ip": (
                    e.normalized_event.get("destination", {}).get("ip")
                    if isinstance(e.normalized_event, dict)
                    else None
                ),
                "user_name": e.username,
                "hostname": e.hostname,
                "severity": e.severity,
                "normalized_event": e.normalized_event,
            }
            for e in events
        ]

    async def get_authentication_history(
        self,
        user_name: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieves authentication events for a user."""
        return await self.search_events(user_name=user_name, limit=limit)

    async def get_user_activity(
        self,
        user_name: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieves general activity for a specific user identity."""
        return await self.search_events(user_name=user_name, limit=limit)

    async def get_host_activity(
        self,
        hostname: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieves events occurring on a specific endpoint or asset."""
        return await self.search_events(hostname=hostname, limit=limit)

    async def get_ip_history(
        self,
        ip_address: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieves events originating from or destined to an IP address."""
        stmt = (
            select(SecurityEvent)
            .where(
                SecurityEvent.tenant_id == self.tenant_id,
                SecurityEvent.source_ip == ip_address,
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(min(limit, 100))
        )
        res = await self.db.execute(stmt)
        events = res.scalars().all()
        return [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat(),
                "source_ip": e.source_ip,
                "user_name": e.username,
                "hostname": e.hostname,
            }
            for e in events
        ]

    async def get_asset_details(
        self,
        hostname_or_ip: str,
    ) -> dict[str, Any] | None:
        """Retrieves registered asset metadata from tenant inventory."""
        stmt = select(Asset).where(
            Asset.tenant_id == self.tenant_id,
            (Asset.hostname == hostname_or_ip) | (Asset.ip_address == hostname_or_ip),
        )
        res = await self.db.execute(stmt)
        asset = res.scalars().first()
        if not asset:
            return None

        return {
            "id": str(asset.id),
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "asset_type": asset.asset_type,
            "criticality": asset.criticality,
            "os": asset.os,
        }

    async def get_previous_incidents(
        self,
        user_name: str | None = None,
        source_ip: str | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Retrieves historical incidents involving the same user or source IP."""
        stmt = select(Incident).where(Incident.tenant_id == self.tenant_id)
        stmt = stmt.order_by(Incident.created_at.desc()).limit(min(limit, 50))
        res = await self.db.execute(stmt)
        incidents = res.scalars().all()

        matched: list[dict[str, Any]] = []
        for inc in incidents:
            has_user = user_name and user_name in (inc.affected_users or [])
            has_ip = source_ip and source_ip in (inc.source_ips or [])
            if has_user or has_ip:
                matched.append(
                    {
                        "id": str(inc.id),
                        "title": inc.title,
                        "severity": inc.severity,
                        "risk_score": inc.risk_score,
                        "status": inc.status,
                        "created_at": inc.created_at.isoformat(),
                    }
                )
        return matched

    async def search_related_detections(
        self,
        rule_id: str | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieves related detection records within tenant."""
        stmt = select(DetectionResult).where(DetectionResult.tenant_id == self.tenant_id)
        if rule_id:
            stmt = stmt.where(DetectionResult.rule_id == rule_id)
        stmt = stmt.order_by(DetectionResult.timestamp.desc()).limit(min(limit, 50))
        res = await self.db.execute(stmt)
        dets = res.scalars().all()
        return [
            {
                "id": str(d.id),
                "rule_id": d.rule_id,
                "title": d.title,
                "severity": d.severity,
                "confidence": d.confidence,
                "mitre_techniques": d.mitre_techniques,
                "event_ids": d.event_ids,
                "timestamp": d.timestamp.isoformat(),
            }
            for d in dets
        ]

    def get_mitre_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Looks up MITRE ATT&CK technique details from static catalog."""
        tech = MitreAttackCatalog.get_technique(technique_id)
        if not tech:
            return None
        return {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "tactics": tech.tactics,
            "description": tech.description,
        }

    async def get_incident_timeline(self, incident_id: uuid.UUID) -> list[dict[str, Any]]:
        """Fetches unified chronological timeline for an incident."""
        return await fetch_incident_timeline(self.db, self.tenant_id, incident_id)
