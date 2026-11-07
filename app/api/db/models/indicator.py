from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class ThreatIndicator(Base):
    """A known-bad indicator from a threat source.

    ``indicator_type`` is one of ``domain``, ``host`` or ``url_hash``. URL-level
    indicators store a sha256 hash so sensitive query strings are never persisted.
    """

    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint(
            "source", "indicator_type", "value", name="uq_threat_indicators_source_type_value"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    indicator_type: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(255), index=True)
    threat_type: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
