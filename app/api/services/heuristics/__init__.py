from services.heuristics.base import AnalysisContext, HeuristicAnalyzer, Signal
from services.heuristics.brand_impersonation import BrandImpersonationAnalyzer
from services.heuristics.domain_age import DomainAgeAnalyzer
from services.heuristics.domain_structure import DomainStructureAnalyzer
from services.heuristics.url_structure import UrlStructureAnalyzer


def default_analyzers() -> list[HeuristicAnalyzer]:
    return [
        DomainStructureAnalyzer(),
        BrandImpersonationAnalyzer(),
        UrlStructureAnalyzer(),
        DomainAgeAnalyzer(),
    ]


__all__ = [
    "AnalysisContext",
    "BrandImpersonationAnalyzer",
    "DomainAgeAnalyzer",
    "DomainStructureAnalyzer",
    "HeuristicAnalyzer",
    "Signal",
    "UrlStructureAnalyzer",
    "default_analyzers",
]
