from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote

import httpx

# rdap.org is a fixed bootstrap service that redirects to the authoritative
# registry RDAP endpoint. The host is never user-controlled.
_RDAP_BASE = "https://rdap.org/domain/"


@dataclass(frozen=True)
class DomainRegistration:
    status: str  # found | not_found | unsupported | timeout | error | invalid_response
    registered_at: datetime | None = None
    registrar: str | None = None
    age_days: int | None = None

    @property
    def available(self) -> bool:
        return self.status == "found"


class RDAPClient:
    """Best-effort domain registration lookup. Never raises on failure."""

    def __init__(self, client: httpx.AsyncClient, *, timeout: float = 4.0) -> None:
        self._client = client
        self._timeout = timeout

    async def lookup(self, domain: str | None) -> DomainRegistration:
        if not domain:
            return DomainRegistration(status="unsupported")

        url = f"{_RDAP_BASE}{quote(domain)}"
        try:
            response = await self._client.get(
                url, timeout=self._timeout, follow_redirects=True
            )
        except httpx.TimeoutException:
            return DomainRegistration(status="timeout")
        except httpx.HTTPError:
            return DomainRegistration(status="error")

        if response.status_code == 404:
            return DomainRegistration(status="not_found")
        if response.status_code >= 400:
            return DomainRegistration(status="error")

        try:
            data = response.json()
        except ValueError:
            return DomainRegistration(status="invalid_response")
        if not isinstance(data, dict):
            return DomainRegistration(status="invalid_response")

        registered_at = self._parse_registration(data)
        return DomainRegistration(
            status="found",
            registered_at=registered_at,
            registrar=self._parse_registrar(data),
            age_days=age_in_days(registered_at),
        )

    @staticmethod
    def _parse_registration(data: dict) -> datetime | None:
        for event in data.get("events", []) or []:
            if not isinstance(event, dict):
                continue
            if event.get("eventAction") == "registration":
                raw = event.get("eventDate")
                if isinstance(raw, str):
                    return _parse_iso(raw)
        return None

    @staticmethod
    def _parse_registrar(data: dict) -> str | None:
        for entity in data.get("entities", []) or []:
            if not isinstance(entity, dict):
                continue
            roles = entity.get("roles") or []
            if "registrar" not in roles:
                continue
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                        value = field[3]
                        if isinstance(value, str):
                            return value
        return None


def age_in_days(registered_at: datetime | None) -> int | None:
    if registered_at is None:
        return None
    now = datetime.now(UTC)
    if registered_at.tzinfo is None:
        registered_at = registered_at.replace(tzinfo=UTC)
    return max(0, (now - registered_at).days)


def _parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
