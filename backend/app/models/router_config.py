from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class RouterConfig(Base):
    __tablename__ = "router_configs"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    vendor: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        default="auto_detect",
    )  # 'tenda', 'tplink', 'mikrotik', 'openwrt', 'asus', 'netgear', 'upnp', 'universal_arp', 'auto_detect'

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="Default Gateway Router",
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
    )

    gateway_ip: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="192.168.0.1",
    )

    management_url: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default="http://192.168.0.1",
    )

    username: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        default="admin",
    )

    password: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    enforcement_mode: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="hybrid",  # 'router_api', 'universal_arp', 'hybrid'
    )

    blocked_macs: Mapped[str | None] = mapped_column(
        Text,
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
