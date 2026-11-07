from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base

if TYPE_CHECKING:
    from db.models.assessment import Assessment


class Domain(Base):
    """One row per hostname. Domain-level cache, never created per URL path."""

    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    registrable_domain: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    is_ip: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # RDAP registration info (reused across assessments within the cache TTL).
    rdap_registered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rdap_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rdap_registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rdap_status: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    assessments: Mapped[list[Assessment]] = relationship(back_populates="domain")
