import hashlib
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.evaluator import evaluate_rule_against_events
from app.detection.evidence import link_event_evidence
from app.detection.models import DetectionResult, DetectionRule
from app.detection.registry import global_rule_registry
from app.models.alert import Alert
from app.models.event import SecurityEvent

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Core Detection Engine evaluating normalized security events against active rules.
    Maintains strict tenant boundaries, links verifiable evidence, and prevents duplicate alerts.
    """

    def __init__(self) -> None:
        pass

    async def load_rules(
        self,
        db: AsyncSession,
        tenant_id: uuid.UUID | None = None,
    ) -> list[DetectionRule]:
        """
        Loads enabled rules for a given tenant (global system rules + tenant-specific rules).
        Synchronizes them into global_rule_registry.
        """
        stmt = select(DetectionRule).where(
            DetectionRule.enabled.is_(True),
            or_(
                DetectionRule.tenant_id.is_(None),
                DetectionRule.tenant_id == tenant_id,
            ),
        )
        result = await db.execute(stmt)
        rules = list(result.scalars().all())

        for r in rules:
            global_rule_registry.register(r)

        return rules

    async def get_applicable_rules(
        self,
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> list[DetectionRule]:
        """Retrieves all active rules applicable to a tenant, falling back to DB if registry is empty."""
        rules = global_rule_registry.get_rules_for_tenant(tenant_id)
        if not rules:
            rules = await self.load_rules(db, tenant_id=tenant_id)
        return rules

    async def evaluate_events(
        self,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        events: list[SecurityEvent],
    ) -> list[DetectionResult]:
        """
        Evaluates a batch of events against active detection rules.
        Guarantees tenant isolation: events and detections are strictly scoped to tenant_id.
        """
        if not events:
            return []

        # Enforce tenant isolation invariant: all events must belong to tenant_id
        for evt in events:
            if evt.tenant_id != tenant_id:
                raise ValueError(
                    f"Cross-tenant evaluation detected: Event {evt.id} tenant {evt.tenant_id} != {tenant_id}"
                )

        applicable_rules = await self.get_applicable_rules(db, tenant_id)
        if not applicable_rules:
            return []

        detection_results: list[DetectionResult] = []

        for rule in applicable_rules:
            # Check if any event matches rule's event types (if specified)
            if rule.event_types:
                rule_types = {t.upper() for t in rule.event_types}
                # Also allow matching by category/service if event_type matches
                has_type_match = any(e.event_type.upper() in rule_types for e in events)
                if not has_type_match and "SECURITY_EVENT" not in rule_types:
                    continue

            # Check timeframe for sliding-window aggregation rules
            timeframe_minutes = rule.conditions.get("timeframe_minutes", 10)
            candidate_events = list(events)

            # If aggregation rule, pull additional recent events within the window for this tenant
            if rule.conditions.get("aggregation") and events:
                earliest_time = min(e.timestamp for e in events)
                latest_time = max(e.timestamp for e in events)
                cutoff = earliest_time - timedelta(minutes=timeframe_minutes)

                history_stmt = (
                    select(SecurityEvent)
                    .where(
                        SecurityEvent.tenant_id == tenant_id,
                        SecurityEvent.timestamp >= cutoff,
                        SecurityEvent.timestamp <= latest_time,
                        SecurityEvent.id.not_in([e.id for e in events]),
                    )
                    .order_by(SecurityEvent.timestamp.asc())
                )
                res = await db.execute(history_stmt)
                past_events = list(res.scalars().all())
                candidate_events = past_events + candidate_events

            # Safe AST evaluation
            matched_events = evaluate_rule_against_events(rule.conditions, candidate_events)
            if not matched_events:
                continue

            # Deterministic deduplication hash
            sorted_event_ids = sorted([str(e.id) for e in matched_events])
            hash_input = f"{tenant_id}:{rule.rule_id}:{','.join(sorted_event_ids)}"
            dedup_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

            # Check for existing detection with identical dedup hash
            existing_stmt = select(DetectionResult).where(
                DetectionResult.tenant_id == tenant_id,
                DetectionResult.dedup_hash == dedup_hash,
            )
            existing_res = await db.execute(existing_stmt)
            existing_detection = existing_res.scalars().first()

            if existing_detection:
                # Increment detection count for repeated processing without spawning duplicate alert
                existing_detection.detection_count += 1
                logger.info(
                    f"Deduplicated detection for rule {rule.rule_id} (count={existing_detection.detection_count})"
                )
                continue

            # Count previous occurrences of this rule for this tenant
            prev_occ_stmt = select(func.count(DetectionResult.id)).where(
                DetectionResult.tenant_id == tenant_id,
                DetectionResult.rule_id == rule.rule_id,
            )
            prev_occ_res = await db.execute(prev_occ_stmt)
            previous_occurrences = prev_occ_res.scalar() or 0

            # Timestamp reflects when the latest triggering evidence event occurred
            det_timestamp = max(e.timestamp for e in matched_events) if matched_events else datetime.now(UTC)
            if det_timestamp.tzinfo is None:
                det_timestamp = det_timestamp.replace(tzinfo=UTC)

            # Instantiate verifiable DetectionResult
            detection = DetectionResult(
                tenant_id=tenant_id,
                rule_id=rule.rule_id,
                title=rule.name,
                description=rule.description,
                severity=rule.severity,
                confidence=rule.confidence,
                event_ids=sorted_event_ids,
                mitre_tactics=rule.mitre_tactics,
                mitre_techniques=rule.mitre_techniques,
                detection_count=1,
                previous_occurrences=previous_occurrences,
                false_positive_status="UNREVIEWED",
                analyst_feedback={},
                dedup_hash=dedup_hash,
                timestamp=det_timestamp,
            )
            db.add(detection)
            await db.flush()

            # Attach verifiable Evidence for matched events
            for evt in matched_events:
                await link_event_evidence(
                    db=db,
                    tenant_id=tenant_id,
                    event=evt,
                    description=f"Evidence for detection '{rule.name}' ({rule.rule_id})",
                )

            # Generate Phase 1 compatible Alert record
            primary_event = matched_events[-1]
            alert = Alert(
                tenant_id=tenant_id,
                event_id=primary_event.id,
                detection_rule=rule.rule_id,
                severity=rule.severity,
                confidence=rule.confidence,
                status="OPEN",
            )
            db.add(alert)

            detection_results.append(detection)
            logger.info(
                f"Generated Detection {detection.id} for rule {rule.rule_id} with {len(matched_events)} evidence events"
            )

        if detection_results:
            await db.commit()
            for d in detection_results:
                await db.refresh(d)

        return detection_results
