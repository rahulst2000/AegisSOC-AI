import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Investigation(Base):
    """
    Forensic investigation record tied to an Incident.
    Contains synthesized attack narrative, hypotheses, findings, and recommendations.
    """

    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        default="COMPLETED",
        nullable=False,
    )  # IN_PROGRESS, COMPLETED, ESCALATED
    executive_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attack_chain: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    known_facts: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    unknowns: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    recommended_next_steps: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    l1_decision: Mapped[str] = mapped_column(String(255), default="ESCALATE_OR_REMEDIATE", nullable=False)
    l2_escalation_recommended: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
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

    # Relationships
    hypotheses: Mapped[list["InvestigationHypothesis"]] = relationship(
        "InvestigationHypothesis",
        back_populates="investigation",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list["InvestigationFinding"]] = relationship(
        "InvestigationFinding",
        back_populates="investigation",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_investigations_tenant_incident", "tenant_id", "incident_id"),
        Index("ix_investigations_tenant_created", "tenant_id", "created_at"),
    )


class InvestigationHypothesis(Base):
    """
    Hypothesis evaluated during investigation (e.g., Credential Attack, Compromised Account).
    Maintains status, confidence, supporting evidence, and unknowns.
    """

    __tablename__ = "investigation_hypotheses"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    hypothesis_id: Mapped[str] = mapped_column(String(50), nullable=False)  # H1, H2, etc.
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # CONFIRMED, LIKELY, UNKNOWN, DISPROVED
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    supporting_evidence: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    contradicting_evidence: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    unknowns: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="hypotheses")

    __table_args__ = (Index("ix_hypotheses_tenant_investigation", "tenant_id", "investigation_id"),)


class InvestigationFinding(Base):
    """
    Specific factual finding generated during investigation, backed by verified evidence.
    """

    __tablename__ = "investigation_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # CONFIRMED, LIKELY, UNKNOWN, DISPROVED
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    reasoning_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship("Investigation", back_populates="findings")

    __table_args__ = (Index("ix_findings_tenant_investigation", "tenant_id", "investigation_id"),)
