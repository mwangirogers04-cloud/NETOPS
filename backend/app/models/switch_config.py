from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class SwitchConfig(Base):
    __tablename__ = "switch_configs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    vendor: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        default="cisco_ios",
    )  # 'cisco_ios', 'aruba', 'mikrotik', 'huawei', 'juniper', 'simulation'

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    management_ip: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    port: Mapped[int] = mapped_column(
        Integer,
        default=22,
        nullable=False,
    )

    username: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    password: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    enable_secret: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
    )

    connection_protocol: Mapped[str] = mapped_column(
        String(20),
        default="ssh",
        nullable=False,
    )

    model: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    total_ports: Mapped[int] = mapped_column(
        Integer,
        default=24,
        nullable=False,
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    last_status: Mapped[str] = mapped_column(
        String(50),
        default="configured",
        nullable=False,
    )  # 'connected', 'failed', 'configured', 'simulation'

    last_tested_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False,
    )
