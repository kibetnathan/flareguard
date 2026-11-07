from __future__ import annotations

_HIGH = [
    "Do not enter passwords or payment information on this website.",
    "Close this page and reach the site by typing its address directly.",
]
_MEDIUM = [
    "Be cautious: confirm the website address before entering any information.",
]
_UNKNOWN = [
    "There is not enough information to assess this URL. Proceed with caution.",
]
_LOW = [
    "No strong risk signals were found, but stay alert for unexpected login or payment "
    "prompts.",
]


def build_recommendations(verdict: str) -> list[str]:
    if verdict in ("high", "confirmed"):
        return list(_HIGH)
    if verdict == "medium":
        return list(_MEDIUM)
    if verdict == "unknown":
        return list(_UNKNOWN)
    return list(_LOW)
