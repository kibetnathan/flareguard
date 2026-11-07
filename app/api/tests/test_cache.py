from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from db.models import Assessment, ThreatIndicator
from services.normalization import hash_url, normalize_url


async def test_cached_assessment_is_reused(client_factory, session):
    client = client_factory(providers=[])
    payload = {"url": "https://cache-me.example/login"}

    first = await client.post("/api/v1/analyze", json=payload)
    assert first.json()["status"] == "completed"

    second = await client.post("/api/v1/analyze", json=payload)
    assert second.json()["status"] == "cached"
    assert second.json()["id"] == first.json()["id"]

    rows = (await session.execute(select(Assessment))).scalars().all()
    assert len(rows) == 1


async def test_expired_cache_is_reanalyzed(client_factory, session):
    client = client_factory(providers=[])
    payload = {"url": "https://expire-me.example/login"}

    await client.post("/api/v1/analyze", json=payload)

    rows = (await session.execute(select(Assessment))).scalars().all()
    rows[0].cache_expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
        seconds=1
    )
    await session.commit()

    second = await client.post("/api/v1/analyze", json=payload)
    assert second.json()["status"] == "completed"

    rows = (await session.execute(select(Assessment))).scalars().all()
    assert len(rows) == 2


async def test_newer_confirmed_indicator_overrides_cache(client_factory, session):
    client = client_factory(providers=[])
    payload = {"url": "https://overridden.example/login"}

    first = await client.post("/api/v1/analyze", json=payload)
    assert first.json()["status"] == "completed"
    assert first.json()["assessment"]["verdict"] != "confirmed"

    url_hash = hash_url(normalize_url(payload["url"]).normalized_url)
    now = datetime.now(UTC).replace(tzinfo=None)
    session.add(
        ThreatIndicator(
            source="test-source",
            indicator_type="url_hash",
            value=url_hash,
            threat_type="phishing",
            severity="high",
            first_seen_at=now,
            last_seen_at=now + timedelta(seconds=30),
        )
    )
    await session.commit()

    second = await client.post("/api/v1/analyze", json=payload)
    assert second.json()["status"] == "completed"
    assert second.json()["assessment"]["verdict"] == "confirmed"
