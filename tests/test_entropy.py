from dns_guard.config import Config
from dns_guard.rules.entropy import EntropyRule, shannon_entropy

def test_entropy_repeated_and_diverse():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("abcdefgh") == 3

def test_entropy_threshold_and_minimum_length():
    rule = EntropyRule(Config())
    result = rule.evaluate("abcdefgh.example.org", "example.org")
    assert result.status == "TRIGGERED"
    assert result.details["label"] == "abcdefgh"
    assert rule.evaluate("abc.example.org", "example.org").status == "SKIPPED"
