from __future__ import annotations

from services.heuristics.base import AnalysisContext, HeuristicAnalyzer, Signal

RECENT_DOMAIN_DAYS = 30


class DomainAgeAnalyzer(HeuristicAnalyzer):
    """Uses domain age as a risk signal, never as proof of maliciousness.

    When registration information is unavailable no signal is produced (which
    lowers the confidence of the overall assessment).
    """

    category = "domain_age"

    def analyze(self, ctx: AnalysisContext) -> list[Signal]:
        registration = ctx.registration
        if registration is None or registration.age_days is None:
            return []
        if registration.age_days < RECENT_DOMAIN_DAYS:
            return [
                Signal(
                    "RECENT_DOMAIN",
                    self.category,
                    "medium",
                    "The domain was registered very recently.",
                )
            ]
        return []
