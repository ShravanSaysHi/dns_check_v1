import json
from datetime import datetime, timedelta, timezone
from dns_guard.config import Config
from dns_guard.engine import AnalysisEngine
from dns_guard.reporting import append_jsonl

class FakeRDAP:
    def __init__(self, date): self.date = date
    def creation_date(self, _domain): return self.date

def test_allowlist_fast_path_skips_rules():
    engine = AnalysisEngine(Config(), ("example.com",), (), FakeRDAP(None))
    result = engine.analyze("https://sub.example.com/x")
    assert result.decision == "ALLOW" and result.fast_path
    assert [rule.status for rule in result.rules] == ["SKIPPED", "SKIPPED"]

def test_blocklist_precedes_allowlist():
    engine = AnalysisEngine(Config(), ("example.com",), ("example.com",), FakeRDAP(None))
    result = engine.analyze("sub.example.com")
    assert result.decision == "BLOCK" and result.blocklist_match == "example.com"

def test_combined_synthetic_indicators_and_logging(tmp_path):
    created = datetime.now(timezone.utc) - timedelta(days=1)
    engine = AnalysisEngine(Config(), (), (), FakeRDAP(created))
    result = engine.analyze("abcdefgh.example.org")
    assert result.score == 50 and result.decision == "BLOCK"
    path = tmp_path / "logs" / "analysis.jsonl"
    append_jsonl(path, result)
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["hostname"] == "abcdefgh.example.org"
    assert record["score"] == 50
