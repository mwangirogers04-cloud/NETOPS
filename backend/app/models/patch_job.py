from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class UpdatePolicy(Base):
    __tablename__ = "update_policies"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    default_working_start: Mapped[str] = mapped_column(
        String(10),
        default="08:00",
        nullable=False,
    )

    default_working_end: Mapped[str] = mapped_column(
        String(10),
        default="17:00",
        nullable=False,
    )

    default_working_days: Mapped[str] = mapped_column(
        String(100),
        default="weekdays",
        nullable=False,
    )

    auto_off_hours_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    block_working_hours_schedule: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    post_work_delay_minutes: Mapped[int] = mapped_column(
        Integer,
        default=5,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class PatchJob(Base):
    __tablename__ = "patch_jobs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    device_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("devices.id"),
        nullable=True,
        index=True,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )

    mac_address: Mapped[str | None] = mapped_column(
        String(17),
        nullable=True,
        index=True,
    )

    machine_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    action: Mapped[str] = mapped_column(
        String(50),
        default="INSTALL_ALL_UPDATES",
        nullable=False,
    )

    # Statuses: PENDING, IN_PROGRESS, COMPLETED, FAILED, CANCELLED
    status: Mapped[str] = mapped_column(
        String(50),
        default="PENDING",
        nullable=False,
        index=True,
    )

    progress_percent: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    initiated_by: Mapped[str] = mapped_column(
        String(100),
        default="console",
        nullable=False,
    )

    log_output: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    scheduled_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
