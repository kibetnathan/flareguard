from __future__ import annotations

from services.heuristics.base import AnalysisContext, HeuristicAnalyzer, Signal

# Thresholds are module-level so rules stay configurable and individually testable.
MAX_HOSTNAME_LENGTH = 40
MAX_SUBDOMAIN_COUNT = 3
MAX_HYPHENS = 3


class DomainStructureAnalyzer(HeuristicAnalyzer):
    category = "domain_structure"

    def analyze(self, ctx: AnalysisContext) -> list[Signal]:
        target = ctx.target
        signals: list[Signal] = []

        if target.is_ip:
            signals.append(
                Signal(
                    "IP_ADDRESS",
                    self.category,
                    "medium",
                    "The URL uses a raw IP address instead of a domain name.",
                )
            )

        if len(target.hostname) > MAX_HOSTNAME_LENGTH:
            signals.append(
                Signal(
                    "LONG_HOSTNAME",
                    self.category,
                    "low",
                    "The hostname is unusually long.",
                )
            )

        if target.subdomain_count >= MAX_SUBDOMAIN_COUNT:
            signals.append(
                Signal(
                    "MANY_SUBDOMAINS",
                    self.category,
                    "low",
                    "The hostname uses an unusually high number of subdomains.",
                )
            )

        if target.hostname.count("-") >= MAX_HYPHENS:
            signals.append(
                Signal(
                    "HYPHEN_ABUSE",
                    self.category,
                    "low",
                    "The hostname uses an unusually high number of hyphens.",
                )
            )

        if target.is_punycode:
            signals.append(
                Signal(
                    "PUNYCODE_DOMAIN",
                    self.category,
                    "medium",
                    "The domain uses a Punycode (internationalized) representation.",
                )
            )

        return signals
