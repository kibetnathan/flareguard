from __future__ import annotations

from datetime import datetime

import httpx

from services.normalization import URLTarget
from services.threat_intel.base import (
    MALWARE,
    PHISHING,
    UNWANTED_SOFTWARE,
    ProviderResult,
    ThreatIntelProvider,
)

# Google Web Risk threat type -> canonical category.
_THREAT_TYPE_MAP = {
    "MALWARE": MALWARE,
    "SOCIAL_ENGINEERING": PHISHING,
    "UNWANTED_SOFTWARE": UNWANTED_SOFTWARE,
}


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class GoogleWebRiskProvider(ThreatIntelProvider):
    name = "google_web_risk"
    endpoint = "https://webrisk.googleapis.com/v1/urls:search"

    def __init__(
        self,
        api_key: str | None,
        client: httpx.AsyncClient,
        *,
        timeout: float = 5.0,
    ) -> None:
        self._api_key = api_key
        self._client = client
        self._timeout = timeout

    def is_configured(self) -> bool:
        return bool(self._api_key)

    async def lookup(self, target: URLTarget) -> ProviderResult:
        if not self._api_key:
            return ProviderResult(self.name, status="not_configured")

        params = [
            ("key", self._api_key),
            ("uri", target.normalized_url),
            ("threatTypes", "MALWARE"),
            ("threatTypes", "SOCIAL_ENGINEERING"),
            ("threatTypes", "UNWANTED_SOFTWARE"),
        ]
        try:
            response = await self._client.get(
                self.endpoint, params=params, timeout=self._timeout
            )
        except httpx.TimeoutException:
            return ProviderResult(self.name, status="timeout")
        except httpx.HTTPError:
            return ProviderResult(self.name, status="error")

        if response.status_code >= 400:
            # Includes 400 (invalid key/request) and 5xx. Never "clean".
            return ProviderResult(self.name, status="error")

        try:
            data = response.json()
        except ValueError:
            return ProviderResult(self.name, status="invalid_response")
        if not isinstance(data, dict):
            return ProviderResult(self.name, status="invalid_response")

        threat = data.get("threat")
        if not isinstance(threat, dict):
            # Empty body => no threat known to this source.
            return ProviderResult(self.name, status="completed", threat_found=False)

        categories = tuple(
            _THREAT_TYPE_MAP[t]
            for t in (threat.get("threatTypes") or [])
            if t in _THREAT_TYPE_MAP
        )
        return ProviderResult(
            self.name,
            status="completed",
            threat_found=True,
            categories=categories,
            expires_at=_parse_iso(threat.get("expireTime")),
        )
