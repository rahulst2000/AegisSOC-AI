"""SQLAlchemy models for Phase 5B Advanced Security Intelligence.

Includes:
- Dynamic Security State Model (SecurityState(t))
- Evidence-grounded State Transitions
- Attack Trajectory tracking
- Attack Graph representations
- Organizational Security Memory
- Threat Intelligence indicators
- Continuous Adversary Scheduling
- GRC Framework Control mappings
- Detection Improvement Candidates
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base

JsonType = JSON().with_variant(JSONB, "postgresql")


class SecurityStateSnapshot(Base):
    """Dynamic security-state representation: SecurityState(t).

    Captures state vector across users, assets, processes, network, vulnerabilities,
    controls, incidents, alerts, risk, and security posture.
    """

    __tablename__ = "security_state_snapshots"

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
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        index=True,
        nullable=False,
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    posture_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)
    open_incidents_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    active_alerts_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    monitored_assets_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    monitored_identities_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    state_vector: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    tenant = relationship("Tenant")

    __table_args__ = (Index("ix_state_snapshots_tenant_timestamp", "tenant_id", "timestamp"),)


class SecurityStateTransition(Base):
    """Auditable state transition between SecurityState(t-1) and SecurityState(t).

    Every state transition must have verifiable evidence.
    """

    __tablename__ = "security_state_transitions"

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
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        index=True,
        nullable=False,
    )
    trigger_type: Mapped[str] = mapped_column(String(100), nullable=False)
    trigger_entity_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    from_state_summary: Mapped[str] = mapped_column(Text, nullable=False)
    to_state_summary: Mapped[str] = mapped_column(Text, nullable=False)
    risk_delta: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    posture_delta: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence_references: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    tenant = relationship("Tenant")

    __table_args__ = (Index("ix_state_transitions_tenant_time", "tenant_id", "timestamp"),)


class AttackTrajectoryRecord(Base):
    """Evidence-based attack progression:

    NORMAL -> WEAK SIGNAL -> ANOMALY -> SUSPICIOUS -> ATTACK DEVELOPING -> CONFIRMED -> CONTAINED.
    """

    __tablename__ = "attack_trajectories"

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
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    current_stage: Mapped[str] = mapped_column(String(50), nullable=False)
    observed_stages: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list, nullable=False)
    predicted_next_stages: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    evidence_event_ids: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    tenant = relationship("Tenant")
    incident = relationship("Incident")


class AttackGraphSnapshot(Base):
    """Tenant-isolated attack and evidence graph record."""

    __tablename__ = "attack_graph_snapshots"

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
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    nodes: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list, nullable=False)
    edges: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list, nullable=False)
    graph_metadata: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    tenant = relationship("Tenant")


class OrganizationalSecurityMemory(Base):
    """Tenant-scoped, auditable, timestamped, evidence-linked historical learning repository."""

    __tablename__ = "organizational_security_memory"

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
    category: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)
    tags: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)
    evidence_references: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        index=True,
        nullable=False,
    )

    tenant = relationship("Tenant")

    __table_args__ = (Index("ix_org_memory_tenant_cat", "tenant_id", "category"),)


class ThreatIntelIndicator(Base):
    """Threat intelligence indicator with provider abstraction and hybrid scoring."""

    __tablename__ = "threat_intel_indicators"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)  # IP, DOMAIN, URL, HASH
    value: Mapped[str] = mapped_column(String(500), index=True, nullable=False)
    threat_type: Mapped[str] = mapped_column(String(100), nullable=False)
    reputation_score: Mapped[float] = mapped_column(Float, default=50.0, nullable=False)
    source_provider: Mapped[str] = mapped_column(String(100), default="LOCAL_FEED", nullable=False)
    tags: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)


class ContinuousAdversarySchedule(Base):
    """Scheduler for authorized lab/staging adversary assessments.

    Enforces strict scope, targets, and authorization.
    """

    __tablename__ = "continuous_adversary_schedules"

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
    scenario_id: Mapped[str] = mapped_column(String(100), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(100), default="0 2 * * 1", nullable=False)
    environment: Mapped[str] = mapped_column(String(50), default="LAB", nullable=False)
    authorized_scope: Mapped[dict[str, Any]] = mapped_column(JsonType, nullable=False)
    target_allowlist: Mapped[list[str]] = mapped_column(JsonType, nullable=False)
    technique_allowlist: Mapped[list[str]] = mapped_column(JsonType, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    tenant = relationship("Tenant")


class GrcControlMapping(Base):
    """Auditable mapping to GRC Frameworks: NIST CSF, ISO 27001, CIS Controls, SOC 2, PCI DSS."""

    __tablename__ = "grc_control_mappings"

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
    framework: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    control_id: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    control_name: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="PARTIALLY_COMPLIANT", nullable=False)
    evidence_references: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list, nullable=False)
    gap_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(50), default="LOW", nullable=False)
    remediation_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_method: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    tenant = relationship("Tenant")

    __table_args__ = (Index("ix_grc_tenant_framework_control", "tenant_id", "framework", "control_id"),)


class DetectionImprovementCandidate(Base):
    """Closed-loop detection improvement recommendation requiring human review and approval."""

    __tablename__ = "detection_improvement_candidates"

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
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)
    proposed_rule_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    test_results: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="PENDING_REVIEW", index=True, nullable=False)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    tenant = relationship("Tenant")
