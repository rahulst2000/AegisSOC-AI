"""5B-08: Organizational Security Memory.

Stores and retrieves historical learnings:
- INCIDENTS
- VALIDATED_ATTACK_PATTERNS
- ANALYST_DECISIONS
- L2_CONCLUSIONS
- FALSE_POSITIVES
- REMEDIATION_HISTORY
- RESPONSE_EFFECTIVENESS
- RECURRING_WEAKNESSES
- DETECTION_IMPROVEMENTS

Critical Rules:
1. Strictly Tenant Scoped: Tenant A memory NEVER appears in Tenant B context.
2. Auditable & Timestamped.
3. Evidence Linked: References incident IDs, event IDs, or audit logs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ValidationException
from app.intelligence.models import OrganizationalSecurityMemory
from app.intelligence.schemas import MemoryEntryCreate, MemoryEntryResponse


class OrganizationalMemoryService:
    """Manages tenant-scoped organizational security memory."""

    ALLOWED_CATEGORIES = {
        "INCIDENT",
        "VALIDATED_ATTACK_PATTERN",
        "ANALYST_DECISION",
        "L2_CONCLUSION",
        "FALSE_POSITIVE",
        "REMEDIATION_HISTORY",
        "RESPONSE_EFFECTIVENESS",
        "RECURRING_WEAKNESS",
        "DETECTION_IMPROVEMENT",
    }

    @classmethod
    async def record_memory(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        payload: MemoryEntryCreate,
        created_by: uuid.UUID | None = None,
    ) -> MemoryEntryResponse:
        """Stores a new verified learning entry for the tenant."""
        cat = payload.category.upper()
        if cat not in cls.ALLOWED_CATEGORIES:
            raise ValidationException(
                f"Invalid memory category '{payload.category}'. Supported: {', '.join(sorted(cls.ALLOWED_CATEGORIES))}"
            )

        if not payload.evidence_references:
            raise ValidationException(
                "Organizational security memory entries must include verifiable evidence references."
            )

        entry = OrganizationalSecurityMemory(
            tenant_id=tenant_id,
            category=cat,
            title=payload.title,
            summary=payload.summary,
            details=payload.details,
            tags=payload.tags,
            evidence_references=payload.evidence_references,
            confidence=max(0.1, min(1.0, payload.confidence)),
            created_by=created_by,
            created_at=datetime.now(UTC),
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)

        return MemoryEntryResponse(
            id=entry.id,
            tenant_id=entry.tenant_id,
            category=entry.category,
            title=entry.title,
            summary=entry.summary,
            details=entry.details,
            tags=entry.tags,
            evidence_references=entry.evidence_references,
            confidence=entry.confidence,
            created_at=entry.created_at,
        )

    @classmethod
    async def query_memory(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        category: str | None = None,
        tag: str | None = None,
        limit: int = 50,
    ) -> list[MemoryEntryResponse]:
        """Queries tenant-isolated security memory. Strictly filters by tenant_id."""
        stmt = (
            select(OrganizationalSecurityMemory)
            .where(OrganizationalSecurityMemory.tenant_id == tenant_id)
            .order_by(OrganizationalSecurityMemory.created_at.desc())
        )
        if category:
            stmt = stmt.where(OrganizationalSecurityMemory.category == category.upper())

        stmt = stmt.limit(min(limit, 100))
        res = await db.execute(stmt)
        entries = res.scalars().all()

        results: list[MemoryEntryResponse] = []
        for e in entries:
            if tag and tag not in (e.tags or []):
                continue
            results.append(
                MemoryEntryResponse(
                    id=e.id,
                    tenant_id=e.tenant_id,
                    category=e.category,
                    title=e.title,
                    summary=e.summary,
                    details=e.details,
                    tags=e.tags,
                    evidence_references=e.evidence_references,
                    confidence=e.confidence,
                    created_at=e.created_at,
                )
            )

        return results
