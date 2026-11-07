from __future__ import annotations

import httpx
from sqlalchemy import select

from db.models import Assessment, AssessmentSignal
from services.threat_intel.base import ProviderResult, ThreatIntelProvider


class StaticProvider(ThreatIntelProvider):
    def __init__(self, name: str, result: ProviderResult) -> None:
        self.name = name
        self._result = result

    async def lookup(self, target):
        return self._result


class ExplodingProvider(ThreatIntelProvider):
    name = "exploding"

    async def lookup(self, target):
        raise RuntimeError("provider exploded")


async def test_health(client_factory):
    client = client_factory(providers=[])
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_valid_request_returns_full_contract(client_factory):
    client = client_factory()  # default providers -> web risk not configured
    response = await client.post("/api/v1/analyze", json={"url": "https://example.com/login"})
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "completed"
    assert body["id"]
    assert body["target"]["hostname"] == "example.com"
    assert body["target"]["registrable_domain"] == "example.com"
    assert body["target"]["scheme"] == "https"
    assert body["target"]["is_ip"] is False
    assert isinstance(body["assessment"]["score"], int)
    assert body["assessment"]["verdict"] in {"low", "medium", "high", "confirmed", "unknown"}
    assert body["assessment"]["confidence"] in {"low", "medium", "high"}
    assert body["recommendations"]
    assert body["analyzed_at"]
    assert body["expires_at"]

    providers = {item["provider"]: item for item in body["provider_results"]}
    assert providers["google_web_risk"]["status"] == "not_configured"


async def test_invalid_request_returns_422(client_factory):
    client = client_factory(providers=[])
    bad_url = await client.post("/api/v1/analyze", json={"url": "not-a-url"})
    assert bad_url.status_code == 422

    bad_scheme = await client.post("/api/v1/analyze", json={"url": "ftp://example.com"})
    assert bad_scheme.status_code == 422

    missing = await client.post("/api/v1/analyze", json={})
    assert missing.status_code == 422


async def test_assessment_and_signals_are_persisted(client_factory, session):
    client = client_factory(providers=[])
    await client.post("/api/v1/analyze", json={"url": "https://paypal-login.com/account"})

    assessments = (await session.execute(select(Assessment))).scalars().all()
    assert len(assessments) == 1
    stored = assessments[0]
    assert stored.hostname == "paypal-login.com"
    assert stored.path == "/account"
    assert stored.verdict in {"medium", "high"}

    signals = (await session.execute(select(AssessmentSignal))).scalars().all()
    assert {s.code for s in signals}


async def test_brand_impersonation_end_to_end(client_factory):
    client = client_factory(providers=[])
    response = await client.post("/api/v1/analyze", json={"url": "https://paypal-login.com/"})
    body = response.json()
    codes = {signal["code"] for signal in body["signals"]}
    assert "BRAND_IN_DOMAIN" in codes
    assert body["assessment"]["score"] >= 25
    assert body["assessment"]["verdict"] in {"medium", "high"}


async def test_provider_failure_does_not_crash_endpoint(client_factory):
    client = client_factory(providers=[ExplodingProvider()])
    response = await client.post("/api/v1/analyze", json={"url": "https://example.com/"})
    assert response.status_code == 200
    body = response.json()
    assert body["provider_results"][0]["status"] == "error"
    assert body["provider_results"][0]["threat_found"] is None


async def test_confirmed_threat_from_provider_overrides_score(client_factory):
    provider = StaticProvider(
        "fake",
        ProviderResult(
            "fake", status="completed", threat_found=True, categories=("phishing",)
        ),
    )
    client = client_factory(providers=[provider])
    response = await client.post("/api/v1/analyze", json={"url": "https://evil.example/login"})
    body = response.json()
    assert body["assessment"]["verdict"] == "confirmed"
    assert body["assessment"]["score"] == 100


async def test_insufficient_evidence_is_unknown_not_safe(client_factory):
    def rdap_error(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = client_factory(providers=[], rdap=rdap_error)
    response = await client.post("/api/v1/analyze", json={"url": "https://quiet.example/"})
    body = response.json()
    assert body["assessment"]["verdict"] == "unknown"
    assert body["assessment"]["confidence"] == "low"


async def test_response_does_not_leak_internals(client_factory):
    provider = StaticProvider(
        "fake",
        ProviderResult("fake", status="completed", threat_found=False, details="SECRET-INTERNAL"),
    )
    client = client_factory(providers=[provider])
    response = await client.post("/api/v1/analyze", json={"url": "https://example.com/"})
    assert "SECRET-INTERNAL" not in response.text
    assert "details" not in response.text
