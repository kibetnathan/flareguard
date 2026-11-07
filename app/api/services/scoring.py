from __future__ import annotations

from dataclasses import dataclass

from services.heuristics.base import Signal

CONFIRMED_THREAT_SCORE = 100
# A non-confirmed assessment never reaches the "confirmed" boundary.
MAX_NON_CONFIRMED_SCORE = 99


@dataclass(frozen=True)
class ScoringRule:
    points: int
    group: str | None = None


# Points by signal code. Grouped signals are de-duplicated so overlapping
# evidence for the same underlying fact is not double-counted.
SCORING_RULES: dict[str, ScoringRule] = {
    # Brand impersonation (group "brand", best-of). Tiered: strong -> lower.
    "BRAND_IN_DOMAIN": ScoringRule(30, "brand"),
    "BRAND_TYPOSQUAT": ScoringRule(30, "brand"),
    "BRAND_IN_HOSTNAME": ScoringRule(20, "brand"),
    "BRAND_KEYWORD_COMBO": ScoringRule(20, "brand"),
    "BRAND_SIMILAR_DOMAIN": ScoringRule(15, "brand"),
    # Unicode obfuscation (group "unicode", best-of).
    "PUNYCODE_DOMAIN": ScoringRule(20, "unicode"),
    "BRAND_HOMOGLYPH": ScoringRule(20, "unicode"),
    # Independent signals.
    "RECENT_DOMAIN": ScoringRule(15),
    "SUSPICIOUS_REDIRECT": ScoringRule(15),
    "IP_ADDRESS": ScoringRule(15),
    # Domain structure (sum, capped).
    "MANY_SUBDOMAINS": ScoringRule(10, "domain_structure"),
    "LONG_HOSTNAME": ScoringRule(5, "domain_structure"),
    "HYPHEN_ABUSE": ScoringRule(5, "domain_structure"),
    # URL structure (sum, capped).
    "AT_SYMBOL": ScoringRule(10, "url_structure"),
    "SUSPICIOUS_PATH": ScoringRule(10, "url_structure"),
    "SUSPICIOUS_HOST_PATH_COMBO": ScoringRule(10, "url_structure"),
    "EXCESSIVE_ENCODING": ScoringRule(5, "url_structure"),
    "LONG_URL": ScoringRule(5, "url_structure"),
}

GROUP_MODE: dict[str, str] = {
    "brand": "max",
    "unicode": "max",
    "url_structure": "sum",
    "domain_structure": "sum",
}
GROUP_CAP: dict[str, int] = {"url_structure": 15, "domain_structure": 20}


@dataclass(frozen=True)
class ScoredSignal:
    code: str
    category: str
    severity: str
    score: int
    message: str


@dataclass(frozen=True)
class ScoredAssessment:
    score: int
    verdict: str
    confidence: str
    signals: list[ScoredSignal]
    confirmed: bool


def verdict_for(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def compute_confidence(
    *, completed_providers: int, rdap_available: bool, signal_categories: int
) -> str:
    """Confidence reflects the strength/completeness of evidence, not probability."""
    evidence = completed_providers + (1 if rdap_available else 0) + signal_categories
    if evidence >= 3:
        return "high"
    if evidence == 2:
        return "medium"
    return "low"


class ScoringEngine:
    def score_signal(self, signal: Signal) -> ScoredSignal:
        rule = SCORING_RULES.get(signal.code)
        points = rule.points if rule else 0
        return ScoredSignal(
            code=signal.code,
            category=signal.category,
            severity=signal.severity,
            score=points,
            message=signal.message,
        )

    def aggregate(self, scored: list[ScoredSignal]) -> int:
        grouped: dict[str, list[int]] = {}
        total = 0
        for signal in scored:
            rule = SCORING_RULES.get(signal.code)
            if rule is None or rule.group is None:
                total += signal.score
                continue
            grouped.setdefault(rule.group, []).append(signal.score)

        for group, points in grouped.items():
            mode = GROUP_MODE.get(group, "sum")
            value = max(points) if mode == "max" else sum(points)
            cap = GROUP_CAP.get(group)
            total += min(value, cap) if cap is not None else value
        return total

    def evaluate(
        self,
        signals: list[Signal],
        *,
        confirmed_threat: bool,
        completed_providers: int,
        rdap_available: bool,
    ) -> ScoredAssessment:
        scored = [self.score_signal(s) for s in signals]
        if confirmed_threat:
            score = CONFIRMED_THREAT_SCORE
            verdict = "confirmed"
            # A trusted confirmed result is conclusive regardless of other evidence.
            confidence = "high"
        else:
            score = min(self.aggregate(scored), MAX_NON_CONFIRMED_SCORE)
            verdict = verdict_for(score)
            categories = len({s.category for s in scored if s.score > 0})
            confidence = compute_confidence(
                completed_providers=completed_providers,
                rdap_available=rdap_available,
                signal_categories=categories,
            )
        return ScoredAssessment(
            score=score,
            verdict=verdict,
            confidence=confidence,
            signals=scored,
            confirmed=confirmed_threat,
        )
