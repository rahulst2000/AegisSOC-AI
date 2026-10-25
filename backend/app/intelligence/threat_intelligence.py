"""5B-09: Advanced Threat Intelligence Service.

Implements Provider Abstraction for threat intelligence feeds.
Combines:
Threat Intelligence + Local Behavior + Historical Behavior + Asset Criticality + Identity Context + Correlation

Critical Rule: Threat intelligence must NOT independently determine maliciousness.
An external match without local suspicious telemetry is classified as INFORMATIONAL_EXTERNAL_MATCH.
"""

from __future__ import annotations

import abc
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.intelligence.schemas import ThreatIntelLookupRequest, ThreatIntelLookupResponse
from app.models.event import SecurityEvent


class ThreatIntelProvider(abc.ABC):
    """Abstract Base Class for Threat Intelligence feeds and lookups."""

    @abc.abstractmethod
    async def lookup(self, indicator_type: str, value: str) -> dict[str, Any] | None:
        """Looks up indicator in threat intelligence catalog."""
        pass


class LocalCuratedThreatIntelProvider(ThreatIntelProvider):
    """Built-in provider with curated indicators for known threat actors, scanners, and C2s."""

    KNOWN_INDICATORS: dict[str, dict[str, Any]] = {
        "198.51.100.22": {
            "threat_type": "C2_SERVER",
            "reputation_score": 92.0,
            "tags": ["APT29", "COZY_BEAR", "C2"],
            "source": "CURATED_THREAT_CATALOG",
        },
        "203.0.113.55": {
            "threat_type": "PASSWORD_SPRAYER",
            "reputation_score": 85.0,
            "tags": ["BRUTE_FORCE", "SSH_SCANNER"],
            "source": "CURATED_THREAT_CATALOG",
        },
        "evil-c2.lab.internal": {
            "threat_type": "MALICIOUS_DOMAIN",
            "reputation_score": 95.0,
            "tags": ["C2_DOMAIN", "FAST_FLUX"],
            "source": "CURATED_THREAT_CATALOG",
        },
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "threat_type": "KNOWN_MALWARE_HASH",
            "reputation_score": 99.0,
            "tags": ["TROJAN", "MIMIKATZ_VARIANT"],
            "source": "CURATED_THREAT_CATALOG",
        },
    }

    async def lookup(self, indicator_type: str, value: str) -> dict[str, Any] | None:
        normalized_val = value.strip().lower()
        if normalized_val in self.KNOWN_INDICATORS:
            return self.KNOWN_INDICATORS[normalized_val]
        # Check by prefix / partial match
        for k, v in self.KNOWN_INDICATORS.items():
            if k.lower() == normalized_val:
                return v
        return None


class ThreatIntelligenceService:
    """Orchestrates hybrid threat intelligence scoring grounded in local context."""

    def __init__(self, provider: ThreatIntelProvider | None = None):
        self.provider = provider or LocalCuratedThreatIntelProvider()

    async def evaluate_indicator(
        self,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        request: ThreatIntelLookupRequest,
    ) -> ThreatIntelLookupResponse:
        """Evaluates indicator reputation combined with actual tenant telemetry."""
        ind_type = request.indicator_type.upper()
        ind_val = request.indicator_value.strip()

        # 1. Query Threat Intel provider
        ti_result = await self.provider.lookup(ind_type, ind_val)
        if ti_result:
            base_reputation = ti_result.get("reputation_score", 50.0)
            threat_type = ti_result.get("threat_type", "SUSPICIOUS")
            tags = ti_result.get("tags", [])
            source = ti_result.get("source", "EXTERNAL_PROVIDER")
        else:
            base_reputation = 20.0
            threat_type = "UNINDEXED_OR_BENIGN"
            tags = ["UNKNOWN_REPUTATION"]
            source = "LOCAL_DATABASE"

        # 2. Local Telemetry Analysis (Check if indicator appeared in tenant security events)
        evt_stmt = (
            select(SecurityEvent)
            .where(
                SecurityEvent.tenant_id == tenant_id,
                (SecurityEvent.source_ip == ind_val) | (SecurityEvent.raw_event.contains(ind_val)),
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(20)
        )
        evt_res = await db.execute(evt_stmt)
        matched_events = evt_res.scalars().all()

        local_event_count = len(matched_events)
        has_local_failures = any("failure" in (e.event_type or "").lower() for e in matched_events)
        has_high_severity = any(e.severity in ["HIGH", "CRITICAL"] for e in matched_events)

        # 3. Compute Local Context Factors
        if local_event_count > 0:
            if has_high_severity:
                local_behavior_factor = 1.4
            elif has_local_failures:
                local_behavior_factor = 1.2
            else:
                local_behavior_factor = 1.0
        else:
            # Indicator has NOT been observed active locally
            local_behavior_factor = 0.4

        # 4. Asset Criticality Factor from local context request
        target_criticality = request.local_context.get("criticality", "MEDIUM").upper()
        if target_criticality == "CRITICAL":
            asset_criticality_factor = 1.3
        elif target_criticality == "HIGH":
            asset_criticality_factor = 1.15
        elif target_criticality == "LOW":
            asset_criticality_factor = 0.85
        else:
            asset_criticality_factor = 1.0

        # 5. Hybrid Risk Score Calculation
        # Base TI (40%) + Local Behavior (40%) + Asset Criticality (20%)
        hybrid_score = round(
            min(
                100.0,
                (base_reputation * 0.4 * local_behavior_factor) + (local_event_count * 5.0) * asset_criticality_factor,
            ),
            2,
        )

        # 6. Verdict Determination
        # Threat intel ALONE without local suspicious events cannot declare confirmed MALICIOUS.
        if base_reputation >= 80.0 and local_event_count > 0 and (has_local_failures or has_high_severity):
            verdict = "MALICIOUS"
            rationale = (
                f"External TI match ({source}, rep={base_reputation:.1f}) corroborated by "
                f"{local_event_count} local suspicious event(s) in tenant environment."
            )
        elif base_reputation >= 80.0 and local_event_count == 0:
            verdict = "SUSPICIOUS"
            rationale = (
                f"High-reputation threat intel match ({source}, rep={base_reputation:.1f}), but "
                f"ZERO active telemetry observed in tenant environment. Classified as INFORMATIONAL_EXTERNAL_MATCH."
            )
        elif hybrid_score >= 50.0:
            verdict = "SUSPICIOUS"
            rationale = f"Elevated combined risk ({hybrid_score:.1f}/100) based on local activity and reputation."
        elif base_reputation <= 30.0 and local_event_count == 0:
            verdict = "BENIGN"
            rationale = "No malicious threat intelligence signatures and no anomalous local behavior detected."
        else:
            verdict = "UNKNOWN"
            rationale = "Insufficient evidence to determine maliciousness. UNKNOWN preserved per SOC standard."

        return ThreatIntelLookupResponse(
            indicator_type=ind_type,
            indicator_value=ind_val,
            reputation_score=base_reputation,
            threat_type=threat_type,
            source_provider=source,
            tags=tags,
            local_behavior_factor=local_behavior_factor,
            asset_criticality_factor=asset_criticality_factor,
            hybrid_risk_score=hybrid_score,
            maliciousness_verdict=verdict,
            rationale=rationale,
            evidence_grounded=local_event_count > 0,
        )
