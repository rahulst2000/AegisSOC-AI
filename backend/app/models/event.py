import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

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
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    normalized_event: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    tenant = relationship("Tenant", back_populates="events")
    alerts = relationship("Alert", back_populates="event")
    evidence_items = relationship("Evidence", back_populates="event")

    __table_args__ = (
        Index("ix_events_tenant_timestamp", "tenant_id", "timestamp"),
        Index("ix_events_tenant_event_type", "tenant_id", "event_type"),
        Index("ix_events_tenant_severity", "tenant_id", "severity"),
        Index("ix_events_tenant_source_ip", "tenant_id", "source_ip"),
        Index("ix_events_tenant_hostname", "tenant_id", "hostname"),
    )

    def __repr__(self) -> str:
        return f"<SecurityEvent id={self.id} type='{self.event_type}' tenant={self.tenant_id}>"
