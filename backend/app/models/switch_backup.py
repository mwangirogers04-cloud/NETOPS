from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class SwitchBackup(Base):
    __tablename__ = "switch_backups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    switch_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("switch_configs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    backup_name: Mapped[str] = mapped_column(String(150), nullable=False)
    config_text: Mapped[str] = mapped_column(Text, nullable=False)
    config_type: Mapped[str] = mapped_column(String(50), default="running-config", nullable=False)
    backup_type: Mapped[str] = mapped_column(String(50), default="manual", nullable=False)  # manual, scheduled, pre-change, post-change
    created_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    lines_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    change_summary: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False,
        index=True,
    )
