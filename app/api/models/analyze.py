from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["low", "medium", "high", "confirmed", "unknown"]
Confidence = Literal["low", "medium", "high"]
Severity = Literal["info", "low", "medium", "high", "critical"]
ProviderStatus = Literal[
    "completed", "not_configured", "error", "timeout", "invalid_response", "skipped"
]
AssessmentStatus = Literal["completed", "cached", "unknown"]


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1)


class TargetInfo(BaseModel):
    hostname: str
    registrable_domain: str | None = None
    is_ip: bool = False
    scheme: str


class AssessmentInfo(BaseModel):
    score: int
    verdict: Verdict
    confidence: Confidence


class SignalOut(BaseModel):
    code: str
    category: str
    severity: Severity
    score: int
    message: str


class ProviderResultOut(BaseModel):
    provider: str
    status: ProviderStatus
    threat_found: bool | None = None
    categories: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    id: str
    status: AssessmentStatus
    target: TargetInfo
    assessment: AssessmentInfo
    signals: list[SignalOut]
    provider_results: list[ProviderResultOut]
    recommendations: list[str]
    analyzed_at: datetime
    expires_at: datetime | None = None
