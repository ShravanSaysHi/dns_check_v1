from datetime import datetime, timedelta, timezone
from dns_guard.config import Config
from dns_guard.rules.domain_intelligence import DomainIntelligenceRule
from dns_guard.services.rdap import RDAPLookupError

class FakeRDAP:
    def __init__(self, date): self.date = date
    def creation_date(self, _domain):
        if isinstance(self.date, Exception): raise self.date
        return self.date

def test_age_threshold_comparison():
    fresh = datetime.now(timezone.utc) - timedelta(days=5)
    old = datetime.now(timezone.utc) - timedelta(days=31)
    assert DomainIntelligenceRule(Config(), FakeRDAP(fresh)).evaluate("new.test", "new.test").status == "TRIGGERED"
    assert DomainIntelligenceRule(Config(), FakeRDAP(old)).evaluate("old.test", "old.test").status == "CLEAR"

def test_unavailable_is_unknown():
    result = DomainIntelligenceRule(Config(), FakeRDAP(RDAPLookupError("offline"))).evaluate("x.org", "x.org")
    assert result.status == "UNKNOWN" and result.score == 0
