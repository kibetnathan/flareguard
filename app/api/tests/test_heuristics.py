from __future__ import annotations

from datetime import UTC, datetime, timedelta

from services.brands import VerifiedBrand
from services.domain_intel import DomainRegistration
from services.heuristics.base import AnalysisContext
from services.heuristics.brand_impersonation import BrandImpersonationAnalyzer
from services.heuristics.domain_age import DomainAgeAnalyzer
from services.heuristics.domain_structure import DomainStructureAnalyzer
from services.heuristics.url_structure import UrlStructureAnalyzer
from services.normalization import normalize_url

BRANDS = [
    VerifiedBrand(name="PayPal", slug="paypal", domains=("paypal.com",)),
    VerifiedBrand(name="Google", slug="google", domains=("google.com",)),
    VerifiedBrand(
        name="OnlineBankingSafe",
        slug="onlinebankingsafe",
        domains=("onlinebankingsafe.com",),
    ),
]


def context(url, *, registration=None, brands=BRANDS):
    return AnalysisContext(
        target=normalize_url(url),
        brands=list(brands),
        registration=registration,
        provider_results=[],
    )


def codes(signals):
    return {signal.code for signal in signals}


# --- Domain structure ------------------------------------------------------ #


def test_domain_structure_flags_ip():
    signals = DomainStructureAnalyzer().analyze(context("http://203.0.113.7/"))
    assert "IP_ADDRESS" in codes(signals)


def test_domain_structure_flags_long_hostname_and_subdomains():
    signals = DomainStructureAnalyzer().analyze(
        context("https://" + "a" * 45 + ".example.com/")
    )
    assert "LONG_HOSTNAME" in codes(signals)

    signals = DomainStructureAnalyzer().analyze(context("https://a.b.c.d.example.com/"))
    assert "MANY_SUBDOMAINS" in codes(signals)


def test_domain_structure_flags_hyphens_and_punycode():
    hyphenated = DomainStructureAnalyzer().analyze(
        context("https://this-is-a-very-hyphenated.example.com/")
    )
    assert "HYPHEN_ABUSE" in codes(hyphenated)

    punycode = DomainStructureAnalyzer().analyze(context("https://xn--pypal-4ve.com/"))
    assert "PUNYCODE_DOMAIN" in codes(punycode)


# --- Brand impersonation --------------------------------------------------- #


def test_official_domain_is_not_flagged():
    assert BrandImpersonationAnalyzer().analyze(context("https://paypal.com/")) == []


def test_brand_in_unrelated_domain():
    signals = BrandImpersonationAnalyzer().analyze(context("https://paypal-login.com/"))
    assert "BRAND_IN_DOMAIN" in codes(signals)


def test_typosquat_detected():
    signals = BrandImpersonationAnalyzer().analyze(context("https://gooogle.com/"))
    assert "BRAND_TYPOSQUAT" in codes(signals)


def test_homoglyph_lookalike_detected():
    # Cyrillic "ра" lookalike of Latin "pa"
    signals = BrandImpersonationAnalyzer().analyze(context("https://раypal.com/"))
    assert "BRAND_HOMOGLYPH" in codes(signals)


def test_similar_domain_detected():
    signals = BrandImpersonationAnalyzer().analyze(context("https://onlinebankings.com/"))
    assert "BRAND_SIMILAR_DOMAIN" in codes(signals)


def test_brand_in_subdomain_and_keyword_combo():
    sub = BrandImpersonationAnalyzer().analyze(context("https://paypal.evil.com/"))
    assert "BRAND_IN_HOSTNAME" in codes(sub)

    combo = BrandImpersonationAnalyzer().analyze(context("https://paypal-secure.com/"))
    assert "BRAND_KEYWORD_COMBO" in codes(combo)


# --- Domain age ------------------------------------------------------------ #


def test_recent_domain():
    now = datetime.now(UTC)
    registration = DomainRegistration(
        status="found", registered_at=now - timedelta(days=5), age_days=5
    )
    signals = DomainAgeAnalyzer().analyze(context("https://fresh.com/", registration=registration))
    assert "RECENT_DOMAIN" in codes(signals)


def test_old_domain_is_not_flagged_for_age():
    now = datetime.now(UTC)
    registration = DomainRegistration(
        status="found", registered_at=now - timedelta(days=900), age_days=900
    )
    assert DomainAgeAnalyzer().analyze(context("https://old.com/", registration=registration)) == []


def test_missing_registration_produces_no_age_signal():
    assert DomainAgeAnalyzer().analyze(context("https://unknown.com/", registration=None)) == []
    assert (
        DomainAgeAnalyzer().analyze(
            context("https://unknown.com/", registration=DomainRegistration(status="not_found"))
        )
        == []
    )


# --- URL structure --------------------------------------------------------- #


def test_url_structure_flags_at_symbol_long_url_and_encoding():
    at = UrlStructureAnalyzer().analyze(context("https://example.com/path@evil/"))
    assert "AT_SYMBOL" in codes(at)

    long_url = UrlStructureAnalyzer().analyze(context("https://example.com/" + "a" * 130))
    assert "LONG_URL" in codes(long_url)

    encoded = UrlStructureAnalyzer().analyze(
        context("https://example.com/%25%25%25%25%25%25")
    )
    assert "EXCESSIVE_ENCODING" in codes(encoded)


def test_suspicious_path_requires_combination():
    flagged = UrlStructureAnalyzer().analyze(
        context("https://evil.com/login?redirect=http://phish.example")
    )
    assert "SUSPICIOUS_PATH" in codes(flagged)


def test_plain_login_path_is_not_flagged():
    assert UrlStructureAnalyzer().analyze(context("https://example.com/login")) == []
    assert UrlStructureAnalyzer().analyze(context("https://example.com/account")) == []


def test_legitimate_url_is_not_flagged_by_weak_signals():
    ctx = context("https://example.com/login")
    all_codes = set()
    for analyzer in (
        DomainStructureAnalyzer(),
        BrandImpersonationAnalyzer(),
        UrlStructureAnalyzer(),
        DomainAgeAnalyzer(),
    ):
        all_codes |= codes(analyzer.analyze(ctx))
    assert all_codes == set()
