import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Asset(Base):
    __tablename__ = "assets"

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
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), index=True, nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), default="SERVER", nullable=False)
    criticality: Mapped[str] = mapped_column(String(50), default="MEDIUM", nullable=False)
    environment: Mapped[str] = mapped_column(String(50), default="PRODUCTION", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE", nullable=False)
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
    tenant = relationship("Tenant", back_populates="assets")

    __table_args__ = (
        Index("ix_assets_tenant_hostname", "tenant_id", "hostname"),
        Index("ix_assets_tenant_ip", "tenant_id", "ip_address"),
    )

    def __repr__(self) -> str:
        return f"<Asset id={self.id} hostname='{self.hostname}' ip='{self.ip_address}' tenant_id={self.tenant_id}>"
