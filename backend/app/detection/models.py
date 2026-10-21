import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class DetectionRule(Base):
    """
    Detection Rule definition representing both global baseline system rules
    (tenant_id is NULL) and custom tenant-scoped rules (tenant_id is populated).
    """

    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    rule_id: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(String(50), default="1.0.0", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), index=True, default="MEDIUM", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.9, nullable=False)
    event_types: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    __table_args__ = (Index("ix_detection_rules_tenant_enabled", "tenant_id", "enabled"),)

    def __repr__(self) -> str:
        scope = f"tenant={self.tenant_id}" if self.tenant_id else "global"
        return f"<DetectionRule {self.rule_id} [{scope}] enabled={self.enabled}>"


class DetectionResult(Base):
    """
    Evidence-backed detection occurrence generated from evaluated security events.
    Strictly tenant-isolated.
    """

    __tablename__ = "detection_results"

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
    rule_id: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    event_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    detection_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    previous_occurrences: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_positive_status: Mapped[str] = mapped_column(String(50), default="UNREVIEWED", index=True, nullable=False)
    analyst_feedback: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    dedup_hash: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_detections_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_detections_tenant_rule", "tenant_id", "rule_id"),
        Index("ix_detections_tenant_dedup", "tenant_id", "dedup_hash"),
    )

    def __repr__(self) -> str:
        return f"<DetectionResult id={self.id} rule={self.rule_id} tenant={self.tenant_id}>"
