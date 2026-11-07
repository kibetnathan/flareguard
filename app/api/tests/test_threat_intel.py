from __future__ import annotations

import httpx

from services.analysis import _run_providers
from services.normalization import normalize_url
from services.threat_intel.base import ProviderResult
from services.threat_intel.google_web_risk import GoogleWebRiskProvider

TARGET = normalize_url("https://example.com/login")


def handler_returning(payload, *, status=200, content=None, media_type="application/json"):
    def handler(request: httpx.Request) -> httpx.Response:
        if content is not None:
            return httpx.Response(status, content=content, headers={"content-type": media_type})
        return httpx.Response(status, json=payload)

    return handler


async def lookup(handler, key="test-key"):
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        provider = GoogleWebRiskProvider(key, client, timeout=1.0)
        return await provider.lookup(TARGET)


async def test_missing_credentials_report_not_configured():
    result = await lookup(handler_returning({}), key=None)
    assert result.status == "not_configured"
    assert result.threat_found is None


async def test_no_threat_found():
    result = await lookup(handler_returning({}))
    assert result.status == "completed"
    assert result.threat_found is False
    assert result.categories == ()


async def test_confirmed_social_engineering_threat():
    payload = {
        "threat": {
            "threatTypes": ["SOCIAL_ENGINEERING"],
            "expireTime": "2030-01-01T00:00:00Z",
        }
    }
    result = await lookup(handler_returning(payload))
    assert result.status == "completed"
    assert result.threat_found is True
    assert "phishing" in result.categories
    assert result.is_confirmed_threat is True
    assert result.expires_at is not None


async def test_malware_threat():
    payload = {"threat": {"threatTypes": ["MALWARE"]}}
    result = await lookup(handler_returning(payload))
    assert result.is_confirmed_threat is True
    assert "malware" in result.categories


async def test_timeout_is_not_a_clean_result():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    result = await lookup(handler)
    assert result.status == "timeout"
    assert result.threat_found is None
    assert result.is_failure is True


async def test_invalid_response_is_not_a_clean_result():
    result = await lookup(
        handler_returning(None, content=b"<html>nope</html>", media_type="text/html")
    )
    assert result.status == "invalid_response"
    assert result.threat_found is None


async def test_server_error_is_not_a_clean_result():
    result = await lookup(handler_returning({"error": "boom"}, status=500))
    assert result.status == "error"
    assert result.threat_found is None


async def test_bad_request_is_error_not_clean():
    result = await lookup(handler_returning({"error": "bad key"}, status=400))
    assert result.status == "error"
    assert result.threat_found is None


async def test_request_includes_expected_threat_types():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["types"] = request.url.params.get_list("threatTypes")
        captured["uri"] = request.url.params.get("uri")
        return httpx.Response(200, json={})

    await lookup(handler)
    assert set(captured["types"]) == {"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"}
    assert captured["uri"] == "https://example.com/login"


class _FakeProvider:
    def __init__(self, name, result=None, error=None):
        self.name = name
        self._result = result
        self._error = error

    async def lookup(self, target):
        if self._error is not None:
            raise self._error
        return self._result


async def test_one_provider_failing_does_not_stop_others():
    working = _FakeProvider(
        "good", result=ProviderResult("good", status="completed", threat_found=False)
    )
    failing = _FakeProvider("bad", error=RuntimeError("kaboom"))

    results = await _run_providers([working, failing], TARGET)
    by_name = {r.provider: r for r in results}

    assert by_name["good"].status == "completed"
    assert by_name["bad"].status == "error"
    assert by_name["bad"].threat_found is None
