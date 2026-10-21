import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SecurityPolicy(Base):
    """
    Tenant-configurable security policy governing automated recommendations and response actions.
    Determines minimum approval roles, authorization criteria, and safety constraints.
    """

    __tablename__ = "security_policies"

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
    )  # NULL for global platform default policy, UUID for tenant-specific policy
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    min_role_for_approval: Mapped[str] = mapped_column(
        String(50),
        default="SOC_L1_ANALYST",
        nullable=False,
    )  # SOC_L1_ANALYST, SOC_L2_ANALYST, SECURITY_MANAGER, NONE, DISABLED
    require_human_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
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

    __table_args__ = (Index("ix_security_policies_tenant_action", "tenant_id", "action_type"),)
