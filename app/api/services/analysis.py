from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import Settings
from db.models import Assessment, AssessmentSignal, Domain, ThreatIndicator
from models.analyze import (
    AnalyzeResponse,
    AssessmentInfo,
    ProviderResultOut,
    SignalOut,
    TargetInfo,
)
from services.brands import load_verified_brands
from services.domain_intel import DomainRegistration, RDAPClient, age_in_days
from services.heuristics import AnalysisContext, default_analyzers
from services.normalization import URLTarget, hash_url, normalize_url
from services.recommendations import build_recommendations
from services.scoring import ScoringEngine
from services.threat_intel.base import (
    MALWARE,
    PHISHING,
    TRUSTED_CONFIRMED_CATEGORIES,
    ProviderResult,
    ThreatIntelProvider,
)

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Naive UTC timestamp for storage (portable across SQLite/Postgres)."""
    return datetime.now(UTC).replace(tzinfo=None)


def _naive(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def analyze_url(
    session: AsyncSession,
    *,
    settings: Settings,
    client: httpx.AsyncClient,
    providers: list[ThreatIntelProvider],
    url: str,
) -> AnalyzeResponse:
    target = normalize_url(url, max_length=settings.max_url_length)
    now = _utcnow()
    url_hash = hash_url(target.normalized_url)

    cached = await _find_cached_assessment(session, url_hash, now)
    if cached is not None and not await _has_newer_confirmed_indicator(
        session, target, _naive(cached.analyzed_at), now
    ):
        return _response_from_assessment(cached, status="cached")

    domain = await _get_or_create_domain(session, target)
    registration = await _ensure_registration(session, domain, target, settings, client, now)

    db_confirmed = await _lookup_db_threats(session, target, now)
    provider_results = await _run_providers(providers, target)
    provider_confirmed = any(result.is_confirmed_threat for result in provider_results)
    confirmed = db_confirmed or provider_confirmed

    brands = await load_verified_brands(session)
    context = AnalysisContext(
        target=target,
        brands=brands,
        registration=registration,
        provider_results=provider_results,
    )
    signals = []
    for analyzer in default_analyzers():
        signals.extend(analyzer.analyze(context))

    completed_providers = sum(1 for r in provider_results if r.status == "completed")
    rdap_informative = registration is not None and registration.status in ("found", "not_found")

    scored = ScoringEngine().evaluate(
        signals,
        confirmed_threat=confirmed,
        completed_providers=completed_providers,
        rdap_available=rdap_informative,
    )
    score, verdict, confidence = scored.score, scored.verdict, scored.confidence

    # Insufficient evidence: nothing confirmed, no signals, no successful provider
    # and no registration data. Never report this as "safe".
    if not confirmed and not signals and completed_providers == 0 and not rdap_informative:
        score, verdict, confidence = 0, "unknown", "low"

    recommendations = build_recommendations(verdict)

    await _persist_provider_threats(session, target, provider_results, now)

    cache_expires_at = now + timedelta(seconds=settings.assessment_cache_ttl_seconds)
    assessment = Assessment(
        id=uuid4().hex,
        domain_id=domain.id,
        hostname=target.hostname,
        registrable_domain=target.registrable_domain,
        scheme=target.scheme,
        is_ip=target.is_ip,
        url_hash=url_hash,
        path=target.path[:512],
        status="completed",
        score=score,
        verdict=verdict,
        confidence=confidence,
        provider_results=[_provider_result_dict(r) for r in provider_results],
        recommendations=recommendations,
        analyzed_at=now,
        cache_expires_at=cache_expires_at,
    )
    assessment.signals = [
        AssessmentSignal(
            code=s.code,
            category=s.category,
            severity=s.severity,
            score=s.score,
            message=s.message,
        )
        for s in scored.signals
    ]
    session.add(assessment)
    await session.commit()

    logger.info(
        "analyzed %s verdict=%s score=%s confidence=%s",
        target.redacted(),
        verdict,
        score,
        confidence,
    )

    return AnalyzeResponse(
        id=assessment.id,
        status="completed",
        target=TargetInfo(
            hostname=target.hostname,
            registrable_domain=target.registrable_domain,
            is_ip=target.is_ip,
            scheme=target.scheme,
        ),
        assessment=AssessmentInfo(score=score, verdict=verdict, confidence=confidence),
        signals=[
            SignalOut(
                code=s.code,
                category=s.category,
                severity=s.severity,
                score=s.score,
                message=s.message,
            )
            for s in scored.signals
        ],
        provider_results=[ProviderResultOut(**_provider_result_dict(r)) for r in provider_results],
        recommendations=recommendations,
        analyzed_at=_aware(now),
        expires_at=_aware(cache_expires_at),
    )


# --------------------------------------------------------------------------- #
# Persistence helpers
# --------------------------------------------------------------------------- #


async def _get_or_create_domain(session: AsyncSession, target: URLTarget) -> Domain:
    stmt = select(Domain).where(Domain.hostname == target.hostname)
    domain = (await session.execute(stmt)).scalars().first()
    if domain is None:
        domain = Domain(
            hostname=target.hostname,
            registrable_domain=target.registrable_domain,
            is_ip=target.is_ip,
        )
        session.add(domain)
        await session.flush()
    else:
        domain.registrable_domain = target.registrable_domain
        domain.is_ip = target.is_ip
    return domain


async def _ensure_registration(
    session: AsyncSession,
    domain: Domain,
    target: URLTarget,
    settings: Settings,
    client: httpx.AsyncClient,
    now: datetime,
) -> DomainRegistration:
    if target.is_ip:
        return DomainRegistration(status="unsupported")

    checked = _naive(domain.rdap_checked_at)
    is_stale = checked is None or (now - checked).total_seconds() > settings.rdap_cache_ttl_seconds

    if is_stale:
        registration = await RDAPClient(client, timeout=settings.rdap_timeout_seconds).lookup(
            domain.registrable_domain or target.hostname
        )
        domain.rdap_status = registration.status
        domain.rdap_registered_at = _naive(registration.registered_at)
        domain.rdap_registrar = registration.registrar
        domain.rdap_checked_at = now

    return DomainRegistration(
        status=domain.rdap_status or "unsupported",
        registered_at=_naive(domain.rdap_registered_at),
        registrar=domain.rdap_registrar,
        age_days=age_in_days(_naive(domain.rdap_registered_at)),
    )


async def _lookup_db_threats(session: AsyncSession, target: URLTarget, now: datetime) -> bool:
    indicators = await _query_indicators(session, target)
    return any(
        _indicator_is_active(ind, now) and ind.threat_type in TRUSTED_CONFIRMED_CATEGORIES
        for ind in indicators
    )


async def _has_newer_confirmed_indicator(
    session: AsyncSession, target: URLTarget, since: datetime | None, now: datetime
) -> bool:
    indicators = await _query_indicators(session, target)
    for ind in indicators:
        if not _indicator_is_active(ind, now):
            continue
        if ind.threat_type not in TRUSTED_CONFIRMED_CATEGORIES:
            continue
        if since is None:
            return True
        last_seen = _naive(ind.last_seen_at)
        if last_seen is not None and last_seen > since:
            return True
    return False


async def _query_indicators(session: AsyncSession, target: URLTarget) -> list[ThreatIndicator]:
    conditions = [
        and_(ThreatIndicator.indicator_type == "host", ThreatIndicator.value == target.hostname),
        and_(
            ThreatIndicator.indicator_type == "url_hash",
            ThreatIndicator.value == hash_url(target.normalized_url),
        ),
    ]
    if target.registrable_domain:
        conditions.append(
            and_(
                ThreatIndicator.indicator_type == "domain",
                ThreatIndicator.value == target.registrable_domain,
            )
        )
    stmt = select(ThreatIndicator).where(or_(*conditions))
    return list((await session.execute(stmt)).scalars().all())


def _indicator_is_active(indicator: ThreatIndicator, now: datetime) -> bool:
    expires = _naive(indicator.expires_at)
    return expires is None or expires > now


async def _persist_provider_threats(
    session: AsyncSession,
    target: URLTarget,
    results: list[ProviderResult],
    now: datetime,
) -> None:
    for result in results:
        if not result.is_confirmed_threat:
            continue
        threat_type = PHISHING if PHISHING in result.categories else MALWARE
        expires_at = _naive(result.expires_at)
        if target.registrable_domain:
            await _upsert_indicator(
                session,
                source=result.provider,
                indicator_type="domain",
                value=target.registrable_domain,
                threat_type=threat_type,
                expires_at=expires_at,
                now=now,
            )
        await _upsert_indicator(
            session,
            source=result.provider,
            indicator_type="url_hash",
            value=hash_url(target.normalized_url),
            threat_type=threat_type,
            expires_at=expires_at,
            now=now,
        )


async def _upsert_indicator(
    session: AsyncSession,
    *,
    source: str,
    indicator_type: str,
    value: str,
    threat_type: str,
    expires_at: datetime | None,
    now: datetime,
) -> None:
    stmt = select(ThreatIndicator).where(
        ThreatIndicator.source == source,
        ThreatIndicator.indicator_type == indicator_type,
        ThreatIndicator.value == value,
    )
    existing = (await session.execute(stmt)).scalars().first()
    if existing is not None:
        existing.threat_type = threat_type
        existing.last_seen_at = now
        existing.expires_at = expires_at
        return
    session.add(
        ThreatIndicator(
            source=source,
            indicator_type=indicator_type,
            value=value,
            threat_type=threat_type,
            severity="high",
            first_seen_at=now,
            last_seen_at=now,
            expires_at=expires_at,
        )
    )


async def _find_cached_assessment(
    session: AsyncSession, url_hash: str, now: datetime
) -> Assessment | None:
    stmt = (
        select(Assessment)
        .options(selectinload(Assessment.signals))
        .where(
            Assessment.url_hash == url_hash,
            Assessment.cache_expires_at.is_not(None),
            Assessment.cache_expires_at > now,
        )
        .order_by(Assessment.analyzed_at.desc())
        .limit(1)
    )
    return (await session.execute(stmt)).scalars().first()


# --------------------------------------------------------------------------- #
# Provider helpers
# --------------------------------------------------------------------------- #


async def _run_providers(
    providers: list[ThreatIntelProvider], target: URLTarget
) -> list[ProviderResult]:
    if not providers:
        return []

    outcomes = await asyncio.gather(
        *(provider.lookup(target) for provider in providers), return_exceptions=True
    )
    results: list[ProviderResult] = []
    for provider, outcome in zip(providers, outcomes, strict=True):
        if isinstance(outcome, BaseException):
            logger.warning("provider %s failed: %s", provider.name, type(outcome).__name__)
            results.append(ProviderResult(provider.name, status="error"))
        else:
            results.append(outcome)
    return results


def _provider_result_dict(result: ProviderResult) -> dict:
    return {
        "provider": result.provider,
        "status": result.status,
        "threat_found": result.threat_found,
        "categories": list(result.categories),
    }


def _response_from_assessment(assessment: Assessment, *, status: str) -> AnalyzeResponse:
    return AnalyzeResponse(
        id=assessment.id,
        status=status,
        target=TargetInfo(
            hostname=assessment.hostname,
            registrable_domain=assessment.registrable_domain,
            is_ip=assessment.is_ip,
            scheme=assessment.scheme,
        ),
        assessment=AssessmentInfo(
            score=assessment.score,
            verdict=assessment.verdict,
            confidence=assessment.confidence,
        ),
        signals=[
            SignalOut(
                code=s.code,
                category=s.category,
                severity=s.severity,
                score=s.score,
                message=s.message,
            )
            for s in assessment.signals
        ],
        provider_results=[
            ProviderResultOut(**item) for item in (assessment.provider_results or [])
        ],
        recommendations=list(assessment.recommendations or []),
        analyzed_at=_aware(assessment.analyzed_at),
        expires_at=_aware(assessment.cache_expires_at),
    )
