"""Configuration loading and validation."""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    age_threshold_days: int = 30
    entropy_threshold_bits: float = 3.0
    minimum_label_length: int = 8
    age_weight: int = 25
    entropy_weight: int = 25
    flag_threshold: int = 25
    block_threshold: int = 50
    rdap_timeout_seconds: float = 4.0
    allowlist_path: str = "data/allowlist.txt"
    blocklist_path: str = "data/blocklist.txt"
    jsonl_log_path: str = "logs/analysis.jsonl"


def load_config(path: Path) -> Config:
    if not path.exists():
        return Config()
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read configuration {path}: {exc}") from exc
    if not isinstance(values, dict):
        raise ValueError("Configuration must be a JSON object.")
    allowed = set(Config.__dataclass_fields__)
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"Unknown configuration setting(s): {', '.join(sorted(unknown))}")
    try:
        config = Config(**values)
    except TypeError as exc:
        raise ValueError(f"Invalid configuration: {exc}") from exc
    integer_fields = ("age_threshold_days", "minimum_label_length", "age_weight",
                      "entropy_weight", "flag_threshold", "block_threshold")
    if any(type(getattr(config, name)) is not int for name in integer_fields):
        raise ValueError("Age, label length, weights and score thresholds must be integers.")
    if any(not isinstance(getattr(config, name), (int, float)) or isinstance(getattr(config, name), bool)
           for name in ("entropy_threshold_bits", "rdap_timeout_seconds")):
        raise ValueError("Entropy threshold and RDAP timeout must be numbers.")
    if any(not isinstance(getattr(config, name), str)
           for name in ("allowlist_path", "blocklist_path", "jsonl_log_path")):
        raise ValueError("List and log paths must be strings.")
    if config.age_threshold_days < 0 or config.minimum_label_length < 1:
        raise ValueError("Age threshold must be nonnegative and minimum label length must be positive.")
    if config.entropy_threshold_bits < 0 or config.rdap_timeout_seconds <= 0:
        raise ValueError("Entropy threshold must be nonnegative and RDAP timeout must be positive.")
    if min(config.age_weight, config.entropy_weight, config.flag_threshold, config.block_threshold) < 0:
        raise ValueError("Weights and score thresholds must be nonnegative.")
    if config.block_threshold < config.flag_threshold:
        raise ValueError("Block threshold must be at least the flag threshold.")
    return config
