"""Rule-result scoring and final decision policy."""

from dns_guard.config import Config
from dns_guard.models import RuleResult


def score_results(results: list[RuleResult], config: Config) -> tuple[int, str, list[str]]:
    score = sum(result.score for result in results if result.status not in {"SKIPPED", "UNKNOWN", "ERROR"})
    if score >= config.block_threshold:
        decision = "BLOCK"
    elif score >= config.flag_threshold:
        decision = "FLAG"
    else:
        decision = "ALLOW"
    reasons = [result.reason for result in results if result.reason and result.status not in {"SKIPPED"}]
    if not reasons:
        reasons = ["No configured heuristic indicators triggered."]
    return score, decision, reasons
