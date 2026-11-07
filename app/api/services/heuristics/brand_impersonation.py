from __future__ import annotations

import unicodedata
from difflib import SequenceMatcher

from services.heuristics.base import AnalysisContext, HeuristicAnalyzer, Signal

# Common confusable characters (Cyrillic / Greek / digits) mapped to Latin.
_HOMOGLYPH_MAP = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "і": "i", "ѕ": "s", "ԁ": "d", "н": "h", "ь": "b", "м": "m", "т": "t",
        "к": "k", "в": "b", "г": "r",
        "α": "a", "ε": "e", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k",
        "υ": "u", "χ": "x", "ο": "o", "μ": "m",
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    }
)

# Credential/account terms frequently paired with a brand in phishing hostnames.
SENSITIVE_HOST_KEYWORDS = (
    "login", "signin", "secure", "verify", "verification", "account", "update",
    "support", "service", "billing", "payment", "wallet", "confirm", "recovery",
)

SIMILARITY_THRESHOLD = 0.8
MIN_SLUG_LENGTH = 4


def _sld(registrable_domain: str) -> str:
    return registrable_domain.split(".")[0]


def _fold(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).lower()
    return normalized.translate(_HOMOGLYPH_MAP)


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _bounded_edit_distance(a: str, b: str, max_distance: int) -> int:
    """Levenshtein distance with early exit once ``max_distance`` is exceeded."""
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


class BrandImpersonationAnalyzer(HeuristicAnalyzer):
    category = "brand_impersonation"

    def analyze(self, ctx: AnalysisContext) -> list[Signal]:
        target = ctx.target
        if target.is_ip or not ctx.brands:
            return []

        registrable = (target.registrable_domain or target.hostname).lower()
        if registrable in {d for brand in ctx.brands for d in brand.domains}:
            return []

        candidate = _sld(registrable)
        unicode_registrable = (target.hostname_unicode or target.hostname).lower()
        unicode_candidate = _sld(unicode_registrable)
        hostname = target.hostname.lower()

        all_official_slds = {
            _sld(d)
            for brand in ctx.brands
            for d in brand.domains
            if len(_sld(d)) >= MIN_SLUG_LENGTH
        }

        found: dict[str, Signal] = {}

        def add(signal: Signal) -> None:
            found.setdefault(signal.code, signal)

        for brand in ctx.brands:
            official = {d.lower() for d in brand.domains}
            if registrable in official:
                continue
            official_slds = {_sld(d) for d in official if len(_sld(d)) >= MIN_SLUG_LENGTH}
            slug = brand.slug

            if slug in candidate and candidate not in all_official_slds:
                add(
                    Signal(
                        "BRAND_IN_DOMAIN",
                        self.category,
                        "high",
                        f"The domain uses the brand name '{brand.name}' but is not an official "
                        "domain.",
                    )
                )

            if slug in hostname and slug not in candidate:
                add(
                    Signal(
                        "BRAND_IN_HOSTNAME",
                        self.category,
                        "medium",
                        f"The hostname references the brand '{brand.name}'.",
                    )
                )

            if slug in hostname and any(k in hostname for k in SENSITIVE_HOST_KEYWORDS):
                add(
                    Signal(
                        "BRAND_KEYWORD_COMBO",
                        self.category,
                        "medium",
                        f"The hostname combines the brand '{brand.name}' with account-related "
                        "terms.",
                    )
                )

            if candidate in all_official_slds:
                continue

            for official_sld in official_slds:
                if candidate == official_sld:
                    continue

                # Unicode / homoglyph lookalike.
                folded = _fold(unicode_candidate)
                if folded == official_sld and unicode_candidate != official_sld:
                    add(
                        Signal(
                            "BRAND_HOMOGLYPH",
                            self.category,
                            "high",
                            f"The domain uses characters that visually resemble "
                            f"'{brand.name}'.",
                        )
                    )
                    break

                # Typosquatting (small edit distance).
                distance = _bounded_edit_distance(candidate, official_sld, 2)
                if 1 <= distance <= 2 and len(official_sld) >= MIN_SLUG_LENGTH:
                    add(
                        Signal(
                            "BRAND_TYPOSQUAT",
                            self.category,
                            "high",
                            f"The domain is a likely typosquat of '{brand.name}'.",
                        )
                    )
                    break

                # Broader string similarity.
                if _similarity(candidate, official_sld) >= SIMILARITY_THRESHOLD:
                    add(
                        Signal(
                            "BRAND_SIMILAR_DOMAIN",
                            self.category,
                            "medium",
                            f"The domain closely resembles the official '{brand.name}' domain.",
                        )
                    )
                    break

        return list(found.values())
