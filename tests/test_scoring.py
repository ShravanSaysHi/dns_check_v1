from dns_guard.config import Config
from dns_guard.models import RuleResult
from dns_guard.scoring import score_results

def test_configurable_scoring():
    config = Config(age_weight=10, entropy_weight=20, flag_threshold=10, block_threshold=30)
    results = [RuleResult("age", "TRIGGERED", score=10), RuleResult("entropy", "TRIGGERED", score=20)]
    assert score_results(results, config)[:2] == (30, "BLOCK")
