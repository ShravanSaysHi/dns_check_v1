"""Analysis orchestration and fast-path policy."""

from datetime import datetime, timezone

from dns_guard.config import Config
from dns_guard.domain import normalize_domain
from dns_guard.filters import find_match
from dns_guard.models import AnalysisResult, RuleResult
from dns_guard.rules.domain_intelligence import DomainIntelligenceRule
from dns_guard.rules.entropy import EntropyRule
from dns_guard.scoring import score_results
from dns_guard.services.rdap import RDAPClient


class AnalysisEngine:
    def __init__(self, config: Config, allowlist: tuple[str, ...], blocklist: tuple[str, ...],
                 rdap: RDAPClient | None = None) -> None:
        self.config = config
        self.allowlist = allowlist
        self.blocklist = blocklist
        client = rdap or RDAPClient(config.rdap_timeout_seconds)
        self.age_rule = DomainIntelligenceRule(config, client)
        self.entropy_rule = EntropyRule(config)

    def analyze(self, value: str) -> AnalysisResult:
        domain = normalize_domain(value)
        block = find_match(domain.hostname, self.blocklist)
        timestamp = datetime.now(timezone.utc).isoformat()
        if block:
            result = RuleResult("local_reputation", "MATCH", block, score=0,
                                reason=f"Blocklist entry {block!r} matched; blocklist takes precedence.")
            return AnalysisResult(timestamp, value, domain.hostname, domain.registrable_domain, False,
                                  block, None, [result], 0, "BLOCK", [result.reason])
        allow = find_match(domain.hostname, self.allowlist)
        if domain.is_local_or_reserved:
            skipped = [RuleResult("domain_age", "SKIPPED", threshold=self.config.age_threshold_days,
                                  reason="Registration-age lookup is not applicable."),
                       RuleResult("entropy", "SKIPPED", threshold=self.config.entropy_threshold_bits,
                                  reason="Entropy analysis is not applicable.")]
            return AnalysisResult(timestamp, value, domain.hostname, domain.registrable_domain, False,
                                  None, allow, skipped, 0, "ALLOW", ["IP, localhost or unsupported name; checks skipped."])
        if allow:
            skipped = [RuleResult("domain_age", "SKIPPED", threshold=self.config.age_threshold_days,
                                  reason="Trusted-domain fast path."),
                       RuleResult("entropy", "SKIPPED", threshold=self.config.entropy_threshold_bits,
                                  reason="Trusted-domain fast path.")]
            return AnalysisResult(timestamp, value, domain.hostname, domain.registrable_domain, True,
                                  None, allow, skipped, 0, "ALLOW", [f"Allowlist entry {allow!r} matched; expensive checks skipped."])
        if domain.registrable_domain is None:
            skipped = [RuleResult("domain_age", "SKIPPED", threshold=self.config.age_threshold_days,
                                  reason="No supported registrable domain."),
                       RuleResult("entropy", "SKIPPED", threshold=self.config.entropy_threshold_bits,
                                  reason="No supported registrable domain.")]
            return AnalysisResult(timestamp, value, domain.hostname, None, False,
                                  None, None, skipped, 0, "ALLOW", ["Unsupported or reserved name; analysis checks skipped."])
        rules = [self.age_rule.evaluate(domain.hostname, domain.registrable_domain),
                 self.entropy_rule.evaluate(domain.hostname, domain.registrable_domain)]
        score, decision, reasons = score_results(rules, self.config)
        return AnalysisResult(timestamp, value, domain.hostname, domain.registrable_domain, False,
                              None, None, rules, score, decision, reasons)
