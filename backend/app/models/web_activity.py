from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class WebActivityLog(Base):
    __tablename__ = "web_activity_logs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    device_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    mac_address: Mapped[str | None] = mapped_column(String(30), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(50), default="general", index=True)
    protocol: Mapped[str] = mapped_column(String(20), default="DNS")
    is_violation: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    action: Mapped[str] = mapped_column(String(20), default="monitored")
    hit_count: Mapped[int] = mapped_column(Integer, default=1)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )


class WebFilterPolicy(Base):
    __tablename__ = "web_filter_policies"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    block_streaming_work_hours: Mapped[bool] = mapped_column(Boolean, default=True)
    block_gaming_work_hours: Mapped[bool] = mapped_column(Boolean, default=True)
    block_social_media_work_hours: Mapped[bool] = mapped_column(Boolean, default=False)
    block_adult_always: Mapped[bool] = mapped_column(Boolean, default=True)
    enforce_schedule: Mapped[bool] = mapped_column(Boolean, default=True)
    custom_blocked_domains: Mapped[str | None] = mapped_column(Text, nullable=True, default="")
    custom_allowed_domains: Mapped[str | None] = mapped_column(Text, nullable=True, default="")
    sniffer_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
