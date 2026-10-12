from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class EndpointUpdate(Base):
    __tablename__ = "endpoint_updates"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    mac_address: Mapped[str | None] = mapped_column(
        String(17),
        nullable=True,
        index=True,
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )
    machine_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    operating_system: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    os_version: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    architecture: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    update_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    pending_updates: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    security_updates: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    last_checked: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )
