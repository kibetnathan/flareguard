from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base


class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    domain_id: Mapped[int | None] = mapped_column(
        ForeignKey("domains.id", ondelete="SET NULL"), nullable=True, index=True
    )
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    registrable_domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    scheme: Mapped[str] = mapped_column(String(8))
    is_ip: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), index=True)
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    provider_results: Mapped[list | None] = mapped_column(JSON, nullable=True)
    recommendations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    analyzed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    cache_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    domain: Mapped[Domain | None] = relationship(back_populates="assessments")  # noqa: F821
    signals: Mapped[list[AssessmentSignal]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class AssessmentSignal(Base):
    __tablename__ = "assessment_signals"

    id: Mapped[int] = mapped_column(primary_key=True)
    assessment_id: Mapped[str] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    code: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    assessment: Mapped[Assessment] = relationship(back_populates="signals")
