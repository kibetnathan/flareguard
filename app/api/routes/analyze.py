from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings, get_settings
from db.session import get_session
from models.analyze import AnalyzeRequest, AnalyzeResponse
from services.analysis import analyze_url
from services.threat_intel import ThreatIntelProvider, build_providers

router = APIRouter(tags=["analyze"])


def get_http_client(request: Request) -> httpx.AsyncClient:
    return request.app.state.http_client


def get_providers(
    request: Request, settings: Settings = Depends(get_settings)
) -> list[ThreatIntelProvider]:
    return build_providers(settings, request.app.state.http_client)


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    payload: AnalyzeRequest,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
    client: httpx.AsyncClient = Depends(get_http_client),
    providers: list[ThreatIntelProvider] = Depends(get_providers),
) -> AnalyzeResponse:
    return await analyze_url(
        session,
        settings=settings,
        client=client,
        providers=providers,
        url=payload.url,
    )
