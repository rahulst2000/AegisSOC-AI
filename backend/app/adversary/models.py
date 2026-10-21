import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base

JsonType = JSON().with_variant(JSONB, "postgresql")


class AdversaryAssessment(Base):
    __tablename__ = "adversary_assessments"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    environment: Mapped[str] = mapped_column(String(50), default="LAB", nullable=False)
    authorized_scope: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False)
    scenario: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="DRAFT", index=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    authorized_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    tenant = relationship("Tenant")
    results = relationship(
        "AssessmentResult", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        Index("ix_adversary_assessments_tenant_status", "tenant_id", "status"),
        Index("ix_adversary_assessments_tenant_scenario", "tenant_id", "scenario"),
    )

    def __repr__(self) -> str:
        return f"<AdversaryAssessment id={self.id} scenario={self.scenario} status={self.status}>"


class AssessmentResult(Base):
    __tablename__ = "adversary_assessment_results"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("adversary_assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scenario_id: Mapped[str] = mapped_column(String(100), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    simulation_status: Mapped[str] = mapped_column(String(50), default="NOT_TESTED", nullable=False)
    detection_status: Mapped[str] = mapped_column(String(50), default="NOT_TESTED", nullable=False)
    correlation_status: Mapped[str] = mapped_column(String(50), default="NOT_TESTED", nullable=False)
    investigation_status: Mapped[str] = mapped_column(String(50), default="NOT_TESTED", nullable=False)
    response_status: Mapped[str] = mapped_column(String(50), default="NOT_TESTED", nullable=False)
    verification_status: Mapped[str] = mapped_column(String(50), default="NOT_TESTED", nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)
    finding_ids: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)
    cleanup_status: Mapped[str] = mapped_column(String(50), default="NOT_TESTED", nullable=False)
    overall_result: Mapped[str] = mapped_column(String(50), default="FAIL", nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)

    # Relationships
    assessment = relationship("AdversaryAssessment", back_populates="results")

    __table_args__ = (
        Index("ix_assessment_results_tenant_tech", "tenant_id", "technique_id"),
        Index("ix_assessment_results_tenant_overall", "tenant_id", "overall_result"),
    )

    def __repr__(self) -> str:
        return f"<AssessmentResult id={self.id} scenario={self.scenario_id} overall={self.overall_result}>"
