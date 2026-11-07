from __future__ import annotations

from services.heuristics.base import AnalysisContext, HeuristicAnalyzer, Signal

# Path keywords that are common on legitimate sites and therefore only
# suspicious in combination with other evidence.
SENSITIVE_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "password",
    "wallet",
    "billing",
    "payment",
)
# Query parameters commonly abused to bounce users to an attacker-controlled host.
REDIRECT_PARAMS = ("redirect", "url", "next", "continue", "return", "goto", "dest")

LONG_URL_LENGTH = 100
ENCODING_THRESHOLD = 6


class UrlStructureAnalyzer(HeuristicAnalyzer):
    category = "url_structure"

    def analyze(self, ctx: AnalysisContext) -> list[Signal]:
        target = ctx.target
        path_lower = target.path.lower()
        query_lower = target.query.lower()
        signals: list[Signal] = []

        if "@" in target.path or "@" in target.query:
            signals.append(
                Signal(
                    "AT_SYMBOL",
                    self.category,
                    "medium",
                    "The URL uses an '@' character in the path or query, which can be misleading.",
                )
            )

        raw = f"{target.path}?{target.query}"
        if raw.count("%") >= ENCODING_THRESHOLD or "%25" in raw.lower():
            signals.append(
                Signal(
                    "EXCESSIVE_ENCODING",
                    self.category,
                    "low",
                    "The URL uses an excessive amount of encoding.",
                )
            )

        if len(target.normalized_url) > LONG_URL_LENGTH:
            signals.append(
                Signal(
                    "LONG_URL",
                    self.category,
                    "low",
                    "The URL is unusually long.",
                )
            )

        sensitive_in_path = any(k in path_lower for k in SENSITIVE_KEYWORDS)
        has_redirect_param = any(p in query_lower for p in REDIRECT_PARAMS)
        has_embedded_url = "http://" in path_lower or "https://" in path_lower
        if sensitive_in_path and (has_redirect_param or has_embedded_url):
            signals.append(
                Signal(
                    "SUSPICIOUS_PATH",
                    self.category,
                    "low",
                    "The URL combines a sensitive path with redirect-style parameters.",
                )
            )

        hostname_label_lower = target.hostname.lower()
        sensitive_in_host = any(k in hostname_label_lower for k in SENSITIVE_KEYWORDS)
        if sensitive_in_host and sensitive_in_path:
            signals.append(
                Signal(
                    "SUSPICIOUS_HOST_PATH_COMBO",
                    self.category,
                    "low",
                    "The hostname and path both contain account/credential-related terms.",
                )
            )

        return signals
