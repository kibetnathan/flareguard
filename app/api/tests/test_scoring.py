from __future__ import annotations

from services.heuristics.base import Signal
from services.scoring import (
    ScoringEngine,
    compute_confidence,
    verdict_for,
)


def make(code: str, category: str = "test") -> Signal:
    return Signal(code=code, category=category, severity="low", message=f"{code} fired")


def score_sum(signals, *, confirmed=False):
    engine = ScoringEngine()
    return engine.evaluate(
        signals,
        confirmed_threat=confirmed,
        completed_providers=0,
        rdap_available=False,
    )


def test_brand_group_takes_the_maximum():
    result = score_sum([make("BRAND_IN_DOMAIN"), make("BRAND_TYPOSQUAT")])
    assert result.score == 30  # not 60


def test_url_structure_group_is_capped():
    signals = [
        make("AT_SYMBOL"),
        make("SUSPICIOUS_PATH"),
        make("EXCESSIVE_ENCODING"),
        make("LONG_URL"),
    ]
    result = score_sum(signals)
    assert result.score == 15  # 30 raw, capped at 15


def test_domain_structure_group_is_capped():
    signals = [make("MANY_SUBDOMAINS"), make("LONG_HOSTNAME"), make("HYPHEN_ABUSE")]
    result = score_sum(signals)
    assert result.score == 20  # 20 raw, cap is 20


def test_independent_signals_add_up():
    result = score_sum([make("RECENT_DOMAIN"), make("IP_ADDRESS")])
    assert result.score == 30
    assert result.verdict == "medium"


def test_confirmed_threat_overrides_scoring():
    result = score_sum([make("LONG_URL")], confirmed=False)
    result_confirmed = score_sum([make("LONG_URL")], confirmed=True)
    assert result.score == 5
    assert result_confirmed.score == 100
    assert result_confirmed.verdict == "confirmed"
    assert result_confirmed.confirmed is True


def test_non_confirmed_score_is_capped_below_100():
    signals = [
        make("BRAND_IN_DOMAIN"),
        make("PUNYCODE_DOMAIN"),
        make("RECENT_DOMAIN"),
        make("IP_ADDRESS"),
    ]
    # 30 + 20 + 15 + 15 = 80
    assert score_sum(signals).score == 80

    heavy = [
        make("BRAND_IN_DOMAIN"),
        make("PUNYCODE_DOMAIN"),
        make("RECENT_DOMAIN"),
        make("IP_ADDRESS"),
        make("SUSPICIOUS_REDIRECT"),
        make("MANY_SUBDOMAINS"),
        make("AT_SYMBOL"),
    ]
    result = score_sum(heavy)
    assert result.score == 99
    assert result.verdict == "high"


def test_verdict_boundaries():
    assert verdict_for(0) == "low"
    assert verdict_for(24) == "low"
    assert verdict_for(25) == "medium"
    assert verdict_for(59) == "medium"
    assert verdict_for(60) == "high"
    assert verdict_for(99) == "high"


def test_unknown_signal_codes_contribute_nothing():
    result = score_sum([make("SOMETHING_NEW")])
    assert result.score == 0
    assert result.signals[0].score == 0


def test_confidence_reflects_evidence():
    def confidence(providers: int, rdap: bool, categories: int) -> str:
        return compute_confidence(
            completed_providers=providers, rdap_available=rdap, signal_categories=categories
        )

    assert confidence(0, False, 0) == "low"
    assert confidence(1, False, 0) == "low"
    assert confidence(1, True, 0) == "medium"
    assert confidence(1, True, 1) == "high"


def test_confirmed_threat_confidence_is_high_with_evidence():
    engine = ScoringEngine()
    result = engine.evaluate(
        [],
        confirmed_threat=True,
        completed_providers=1,
        rdap_available=True,
    )
    assert result.verdict == "confirmed"
    assert result.confidence == "high"
