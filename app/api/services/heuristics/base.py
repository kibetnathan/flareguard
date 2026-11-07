from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from services.brands import VerifiedBrand
from services.domain_intel import DomainRegistration
from services.normalization import URLTarget
from services.threat_intel.base import ProviderResult


@dataclass(frozen=True)
class Signal:
    """Structured evidence produced by a heuristic analyzer.

    The numeric weight is assigned later by the scoring engine (keyed on
    ``code``), so analyzers never hardcode points.
    """

    code: str
    category: str
    severity: str  # info | low | medium | high | critical
    message: str


@dataclass
class AnalysisContext:
    target: URLTarget
    brands: list[VerifiedBrand] = field(default_factory=list)
    registration: DomainRegistration | None = None
    provider_results: list[ProviderResult] = field(default_factory=list)


class HeuristicAnalyzer(ABC):
    category: str

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> list[Signal]: ...
