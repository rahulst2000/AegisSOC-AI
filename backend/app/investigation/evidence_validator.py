import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.schemas import AIFinding, AIHypothesis
from app.core.logging import logger
from app.detection.evidence import compute_evidence_hash
from app.detection.mitre_mapper import MitreAttackCatalog
from app.models.asset import Asset
from app.models.event import SecurityEvent
from app.models.evidence import Evidence


class EvidenceValidationResult:
    def __init__(self, is_valid: bool, errors: list[str], verified_evidence_ids: list[str]):
        self.is_valid = is_valid
        self.errors = errors
        self.verified_evidence_ids = verified_evidence_ids


class EvidenceValidator:
    """
    Forensic validator verifying that all AI findings, hypotheses, and recommendations
    are grounded in real, untampered, tenant-isolated evidence records.
    """

    def __init__(self, db: AsyncSession, tenant_id: uuid.UUID):
        self.db = db
        self.tenant_id = tenant_id

    async def validate_event_evidence(
        self,
        event_id_str: str,
    ) -> tuple[bool, str | None, SecurityEvent | None]:
        """
        Validates an event ID:
        1. Exists
        2. Belongs to tenant
        3. Integrity hash matches stored record (if evidence record exists)
        """
        try:
            event_id = uuid.UUID(event_id_str)
        except ValueError:
            return False, f"Invalid event UUID format: {event_id_str}", None

        # Query event
        stmt = select(SecurityEvent).where(
            SecurityEvent.id == event_id,
            SecurityEvent.tenant_id == self.tenant_id,
        )
        res = await self.db.execute(stmt)
        event = res.scalars().first()
        if not event:
            return False, f"Event {event_id_str} does not exist for tenant {self.tenant_id}", None

        # Check linked Evidence records for hash tampering
        ev_stmt = select(Evidence).where(
            Evidence.event_id == event_id,
            Evidence.tenant_id == self.tenant_id,
        )
        ev_res = await self.db.execute(ev_stmt)
        evidence_record = ev_res.scalars().first()

        if evidence_record:
            computed = compute_evidence_hash(event)
            if evidence_record.integrity_hash != computed:
                msg = (
                    f"Evidence hash mismatch for event {event_id_str}. "
                    f"Expected {evidence_record.integrity_hash}, got {computed}"
                )
                return (
                    False,
                    msg,
                    event,
                )

        return True, None, event

    async def validate_findings(
        self,
        findings: list[AIFinding],
    ) -> list[AIFinding]:
        """
        Verifies each finding. If evidence is missing, cross-tenant, or tampered,
        downgrades the finding status to UNKNOWN.
        """
        validated_findings: list[AIFinding] = []

        for finding in findings:
            if not finding.evidence_ids:
                # Finding has zero evidence
                if finding.status in ("CONFIRMED", "LIKELY"):
                    logger.warning("Finding has no evidence. Forcing to UNKNOWN: %s", finding.finding)
                    summary = f"{finding.reasoning_summary} [Evidence validation: No supporting evidence attached]"
                    validated_findings.append(
                        AIFinding(
                            finding=finding.finding,
                            status="UNKNOWN",
                            evidence_ids=[],
                            confidence=min(finding.confidence, 0.2),
                            reasoning_summary=summary,
                        )
                    )
                else:
                    validated_findings.append(finding)
                continue

            verified_ids: list[str] = []
            has_error = False
            error_reasons: list[str] = []

            for eid in finding.evidence_ids:
                valid, err, _ = await self.validate_event_evidence(eid)
                if valid:
                    verified_ids.append(eid)
                else:
                    has_error = True
                    error_reasons.append(err or "Unknown validation error")

            if has_error or not verified_ids:
                logger.warning(
                    "Finding failed evidence validation: %s. Re-classifying as UNKNOWN.",
                    error_reasons,
                )
                err_text = "; ".join(error_reasons)
                validated_findings.append(
                    AIFinding(
                        finding=finding.finding,
                        status="UNKNOWN",
                        evidence_ids=verified_ids,
                        confidence=min(finding.confidence, 0.25),
                        reasoning_summary=f"{finding.reasoning_summary} [Validation errors: {err_text}]",
                    )
                )
            else:
                validated_findings.append(
                    AIFinding(
                        finding=finding.finding,
                        status=finding.status,
                        evidence_ids=verified_ids,
                        confidence=finding.confidence,
                        reasoning_summary=finding.reasoning_summary,
                    )
                )

        return validated_findings

    async def validate_hypotheses(
        self,
        hypotheses: list[AIHypothesis],
    ) -> list[AIHypothesis]:
        """
        Validates hypotheses: cannot be CONFIRMED without verified evidence.
        """
        validated: list[AIHypothesis] = []
        for hyp in hypotheses:
            verified_ids: list[str] = []
            for eid in hyp.evidence_ids:
                valid, _, _ = await self.validate_event_evidence(eid)
                if valid:
                    verified_ids.append(eid)

            status = hyp.status
            conf = hyp.confidence
            if status in ("CONFIRMED", "LIKELY") and not verified_ids:
                status = "UNKNOWN"
                conf = min(conf, 0.2)

            validated.append(
                AIHypothesis(
                    hypothesis_id=hyp.hypothesis_id,
                    title=hyp.title,
                    description=hyp.description,
                    status=status,
                    confidence=conf,
                    evidence_ids=verified_ids,
                    supporting_evidence=hyp.supporting_evidence if verified_ids else [],
                    contradicting_evidence=hyp.contradicting_evidence,
                    unknowns=hyp.unknowns if not verified_ids else hyp.unknowns,
                )
            )
        return validated

    async def validate_asset_exists(self, hostname_or_ip: str) -> bool:
        """Verifies if an asset exists in tenant inventory."""
        stmt = select(Asset).where(
            Asset.tenant_id == self.tenant_id,
            (Asset.hostname == hostname_or_ip) | (Asset.ip_address == hostname_or_ip),
        )
        res = await self.db.execute(stmt)
        return res.scalars().first() is not None

    def validate_mitre_technique(self, technique_id: str) -> bool:
        """Validates that a MITRE technique ID exists in authoritative catalog."""
        return MitreAttackCatalog.validate_technique_id(technique_id)
