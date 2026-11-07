from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

from services.normalization import URLTarget

# Canonical threat categories used across providers.
PHISHING = "phishing"
MALWARE = "malware"
UNWANTED_SOFTWARE = "unwanted_software"

TRUSTED_CONFIRMED_CATEGORIES = frozenset({PHISHING, MALWARE})


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    status: str  # completed | not_configured | error | timeout | invalid_response | skipped
    threat_found: bool | None = None
    categories: tuple[str, ...] = ()
    expires_at: datetime | None = None
    details: str | None = None  # internal only; never returned to clients

    @property
    def is_confirmed_threat(self) -> bool:
        return self.threat_found is True and any(
            category in TRUSTED_CONFIRMED_CATEGORIES for category in self.categories
        )

    @property
    def is_failure(self) -> bool:
        """A failure must never be interpreted as a clean result."""
        return self.status not in ("completed",)


class ThreatIntelProvider(ABC):
    """Interface for pluggable threat-intelligence sources.

    Implementations for other sources (e.g. PhishTank, OpenPhish) can be added
    without touching the analysis engine.
    """

    name: str

    def is_configured(self) -> bool:
        return True

    @abstractmethod
    async def lookup(self, target: URLTarget) -> ProviderResult: ...
