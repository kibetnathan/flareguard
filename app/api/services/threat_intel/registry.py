from __future__ import annotations

import httpx

from config import Settings
from services.threat_intel.base import ThreatIntelProvider
from services.threat_intel.google_web_risk import GoogleWebRiskProvider


def build_providers(settings: Settings, client: httpx.AsyncClient) -> list[ThreatIntelProvider]:
    """Instantiate the enabled threat-intelligence providers.

    Additional sources (e.g. PhishTank, OpenPhish) can be appended here as long
    as they implement ``ThreatIntelProvider``; the analysis engine is unchanged.
    """
    providers: list[ThreatIntelProvider] = []
    if settings.web_risk_enabled:
        providers.append(
            GoogleWebRiskProvider(
                settings.google_web_risk_api_key,
                client,
                timeout=settings.provider_timeout_seconds,
            )
        )
    return providers
