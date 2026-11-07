from __future__ import annotations

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401  (ensure all models are registered)
from application.app import app
from config import Settings, get_settings
from db.base import Base
from db.models import Brand, BrandDomain
from db.session import get_session
from routes.analyze import get_http_client, get_providers
from services.brands import SEED_BRANDS, slugify
from services.threat_intel.base import ProviderResult, ThreatIntelProvider


class FakeProvider(ThreatIntelProvider):
    def __init__(self, name: str, result: ProviderResult) -> None:
        self.name = name
        self._result = result

    async def lookup(self, target):  # noqa: ANN001, ANN201
        return self._result


class ExplodingProvider(ThreatIntelProvider):
    name = "exploding"

    async def lookup(self, target):  # noqa: ANN001, ANN201
        raise RuntimeError("provider exploded")


def default_settings(**overrides) -> Settings:
    values = {
        "google_web_risk_api_key": None,
        "database_url": "sqlite+aiosqlite://",
        "assessment_cache_ttl_seconds": 1800,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
async def session(engine):
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        for entry in SEED_BRANDS:
            brand = Brand(name=entry["name"], slug=slugify(entry["name"]), is_verified=True)
            brand.domains = [BrandDomain(domain=d, is_verified=True) for d in entry["domains"]]
            s.add(brand)
        await s.commit()
        yield s


@pytest.fixture
async def client_factory(session):
    open_clients: list[httpx.AsyncClient] = []

    def _build(*, providers=None, rdap=None, settings=None):
        settings = settings or default_settings()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "rdap.org" and rdap is not None:
                return rdap(request)
            return httpx.Response(404, json={})

        mock_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        open_clients.append(mock_http)
        app.state.http_client = mock_http

        async def override_session():
            yield session

        app.dependency_overrides[get_session] = override_session
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_http_client] = lambda: mock_http
        if providers is not None:
            app.dependency_overrides[get_providers] = lambda: providers
        else:
            app.dependency_overrides.pop(get_providers, None)

        asgi = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        )
        open_clients.append(asgi)
        return asgi

    yield _build
    app.dependency_overrides.clear()
    for client in open_clients:
        await client.aclose()
