from datetime import datetime, timezone
from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class FirewallConfig(Base):
    __tablename__ = "firewall_configs"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True,
    )

    vendor: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )  # 'sophos', 'fortinet', 'mikrotik', 'pfsense', 'cisco_asa', 'linux_iptables', 'simulation'

    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )

    management_url: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    api_key: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    username: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    password: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    verify_tls: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    quarantine_group: Mapped[str] = mapped_column(
        String(100),
        default="NETOPS_Quarantine",
        nullable=False,
    )

    quarantine_rule: Mapped[str] = mapped_column(
        String(100),
        default="NETOPS_Quarantine_Block",
        nullable=False,
    )

    extra_settings: Mapped[str | None] = mapped_column(
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
