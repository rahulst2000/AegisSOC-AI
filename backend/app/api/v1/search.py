"""Global Threat Search API across Events, Incidents, Alerts, Assets, Detections, and Intelligence."""

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.detection.models import DetectionResult
from app.intelligence.threat_intelligence import LocalCuratedThreatIntelProvider
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.security.roles import Role
from app.security.tenant import TenantContext

router = APIRouter(prefix="/search", tags=["Global Threat Search"])


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SECURITY_ENGINEER,
                    Role.SOC_L1,
                    Role.SOC_L2,
                    Role.GRC_ANALYST,
                    Role.SECURITY_MANAGER,
                    Role.CISO,
                ]
            )
        )
    ],
)
async def global_threat_search(
    q: str = Query(..., min_length=1, max_length=100, description="Global search query"),
    limit_per_category: int = Query(10, ge=1, le=50),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Persistent global search across all tenant-isolated security entities:
    Events, Incidents, Alerts, Assets, Detections, and Threat Intelligence.
    """
    clean_q = q.strip()
    term = f"%{clean_q}%"
    tenant_id = ctx.tenant_id

    # 1. Incidents
    inc_stmt = (
        select(Incident)
        .where(
            Incident.tenant_id == tenant_id,
            or_(
                Incident.title.ilike(term),
                Incident.description.ilike(term),
                Incident.severity.ilike(term),
                Incident.status.ilike(term),
                cast(Incident.id, String).ilike(term),
            ),
        )
        .order_by(Incident.created_at.desc())
        .limit(limit_per_category)
    )
    inc_res = await db.execute(inc_stmt)
    incidents = [
        {
            "id": str(inc.id),
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "risk_score": inc.risk_score,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "type": "INCIDENT",
        }
        for inc in inc_res.scalars().all()
    ]

    # 2. Events
    evt_stmt = (
        select(SecurityEvent)
        .where(
            SecurityEvent.tenant_id == tenant_id,
            or_(
                SecurityEvent.event_type.ilike(term),
                SecurityEvent.source.ilike(term),
                SecurityEvent.source_ip.ilike(term),
                SecurityEvent.hostname.ilike(term),
                SecurityEvent.username.ilike(term),
                cast(SecurityEvent.id, String).ilike(term),
            ),
        )
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit_per_category)
    )
    evt_res = await db.execute(evt_stmt)
    events = [
        {
            "id": str(evt.id),
            "event_type": evt.event_type,
            "source": evt.source,
            "severity": evt.severity,
            "source_ip": evt.source_ip,
            "hostname": evt.hostname,
            "username": evt.username,
            "timestamp": evt.timestamp.isoformat() if evt.timestamp else None,
            "type": "EVENT",
        }
        for evt in evt_res.scalars().all()
    ]

    # 3. Alerts
    alert_stmt = (
        select(Alert)
        .where(
            Alert.tenant_id == tenant_id,
            or_(
                Alert.detection_rule.ilike(term),
                Alert.severity.ilike(term),
                Alert.status.ilike(term),
                cast(Alert.id, String).ilike(term),
            ),
        )
        .order_by(Alert.created_at.desc())
        .limit(limit_per_category)
    )
    alert_res = await db.execute(alert_stmt)
    alerts = [
        {
            "id": str(alt.id),
            "detection_rule": alt.detection_rule,
            "severity": alt.severity,
            "status": alt.status,
            "created_at": alt.created_at.isoformat() if alt.created_at else None,
            "type": "ALERT",
        }
        for alt in alert_res.scalars().all()
    ]

    # 4. Assets
    asset_stmt = (
        select(Asset)
        .where(
            Asset.tenant_id == tenant_id,
            or_(
                Asset.hostname.ilike(term),
                Asset.ip_address.ilike(term),
                Asset.asset_type.ilike(term),
                cast(Asset.id, String).ilike(term),
            ),
        )
        .order_by(Asset.created_at.desc())
        .limit(limit_per_category)
    )
    asset_res = await db.execute(asset_stmt)
    assets = [
        {
            "id": str(ast.id),
            "hostname": ast.hostname,
            "ip_address": ast.ip_address,
            "asset_type": ast.asset_type,
            "criticality": ast.criticality,
            "status": ast.status,
            "type": "ASSET",
        }
        for ast in asset_res.scalars().all()
    ]

    # 5. Detections
    det_stmt = (
        select(DetectionResult)
        .where(
            DetectionResult.tenant_id == tenant_id,
            or_(
                DetectionResult.rule_id.ilike(term),
                DetectionResult.severity.ilike(term),
                cast(DetectionResult.id, String).ilike(term),
            ),
        )
        .order_by(DetectionResult.timestamp.desc())
        .limit(limit_per_category)
    )
    det_res = await db.execute(det_stmt)
    detections = [
        {
            "id": str(det.id),
            "rule_id": det.rule_id,
            "severity": det.severity,
            "timestamp": det.timestamp.isoformat() if det.timestamp else None,
            "type": "DETECTION",
        }
        for det in det_res.scalars().all()
    ]

    # 6. Threat Intelligence
    ti_provider = LocalCuratedThreatIntelProvider()
    intel_matches: list[dict[str, Any]] = []
    clean_lower = clean_q.lower()
    for ind_val, ind_info in ti_provider.KNOWN_INDICATORS.items():
        if clean_lower in ind_val.lower() or any(clean_lower in t.lower() for t in ind_info.get("tags", [])):
            intel_matches.append(
                {
                    "indicator": ind_val,
                    "threat_type": ind_info.get("threat_type", "SUSPICIOUS"),
                    "threat_score": ind_info.get("reputation_score", 50.0),
                    "tags": ind_info.get("tags", []),
                    "source": ind_info.get("source", "CURATED_THREAT_CATALOG"),
                    "type": "THREAT_INTEL",
                }
            )

    total = len(incidents) + len(events) + len(alerts) + len(assets) + len(detections) + len(intel_matches)

    return {
        "query": clean_q,
        "total_matches": total,
        "categories": {
            "incidents": incidents,
            "events": events,
            "alerts": alerts,
            "assets": assets,
            "detections": detections,
            "threat_intelligence": intel_matches,
        },
    }
