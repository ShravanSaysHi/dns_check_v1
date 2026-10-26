"""Shared JSON-compatible analysis result models."""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class RuleResult:
    rule: str
    status: str
    value: Any = None
    threshold: Any = None
    score: int = 0
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    timestamp: str
    input_value: str
    hostname: str
    registrable_domain: str | None
    fast_path: bool
    blocklist_match: str | None
    allowlist_match: str | None
    rules: list[RuleResult]
    score: int
    decision: str
    explanations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "registrable_domain": self.registrable_domain,
            "fast_path": self.fast_path,
            "blocklist_match": self.blocklist_match,
            "allowlist_match": self.allowlist_match,
            "rules": [result.to_dict() for result in self.rules],
            "score": self.score,
            "decision": self.decision,
            "explanations": list(self.explanations),
        }
