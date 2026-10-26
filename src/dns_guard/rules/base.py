"""Common rule protocol."""

from typing import Protocol

from dns_guard.models import RuleResult


class Rule(Protocol):
    def evaluate(self, hostname: str, registrable_domain: str | None) -> RuleResult: ...
