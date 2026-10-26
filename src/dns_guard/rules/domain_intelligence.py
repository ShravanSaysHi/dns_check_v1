"""Registration-age component of the domain-intelligence rule."""

from datetime import datetime, timezone

from dns_guard.config import Config
from dns_guard.models import RuleResult
from dns_guard.services.rdap import RDAPClient, RDAPLookupError


class DomainIntelligenceRule:
    def __init__(self, config: Config, rdap: RDAPClient) -> None:
        self.config = config
        self.rdap = rdap

    def evaluate(self, hostname: str, registrable_domain: str | None) -> RuleResult:
        if registrable_domain is None:
            return RuleResult("domain_intelligence", "SKIPPED", reason="No supported registrable domain.")
        try:
            created = self.rdap.creation_date(registrable_domain)
        except RDAPLookupError as exc:
            return RuleResult("domain_age", "UNKNOWN", threshold=self.config.age_threshold_days,
                              reason=f"Registration data unavailable: {exc}")
        if created is None:
            return RuleResult("domain_age", "UNKNOWN", threshold=self.config.age_threshold_days,
                              reason="RDAP did not provide a valid registration date.")
        now = datetime.now(timezone.utc)
        age_days = (now - created.astimezone(timezone.utc)).days
        if age_days < 0:
            return RuleResult("domain_age", "UNKNOWN", threshold=self.config.age_threshold_days,
                              reason="RDAP registration date is in the future.")
        triggered = age_days < self.config.age_threshold_days
        return RuleResult(
            "domain_age", "TRIGGERED" if triggered else "CLEAR", age_days,
            self.config.age_threshold_days, self.config.age_weight if triggered else 0,
            f"Domain is {age_days} days old; threshold is {self.config.age_threshold_days} days.",
        )
