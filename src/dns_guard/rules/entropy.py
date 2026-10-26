"""Shannon entropy rule over eligible hostname labels."""

import math
from collections import Counter

from dns_guard.config import Config
from dns_guard.models import RuleResult


def shannon_entropy(label: str) -> float:
    if not label:
        return 0.0
    counts = Counter(label)
    length = len(label)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class EntropyRule:
    def __init__(self, config: Config) -> None:
        self.config = config

    def evaluate(self, hostname: str, registrable_domain: str | None) -> RuleResult:
        if registrable_domain is None:
            return RuleResult("entropy", "SKIPPED", reason="No supported registrable domain.")
        domain_labels = set(registrable_domain.split("."))
        labels = [label for label in hostname.split(".") if label not in domain_labels]
        eligible = [label for label in labels if len(label) >= self.config.minimum_label_length]
        if len(registrable_domain.split(".")) >= 2:
            registrable_label = registrable_domain.split(".")[0]
            if len(registrable_label) >= self.config.minimum_label_length:
                eligible.append(registrable_label)
        # Maximum eligible-label entropy is used once, so a rule never adds duplicate score.
        if not eligible:
            return RuleResult("entropy", "SKIPPED", threshold=self.config.entropy_threshold_bits,
                              reason=f"No label meets the {self.config.minimum_label_length}-character minimum.")
        label = max(dict.fromkeys(eligible), key=shannon_entropy)
        entropy = shannon_entropy(label)
        triggered = entropy >= self.config.entropy_threshold_bits
        return RuleResult(
            "entropy", "TRIGGERED" if triggered else "CLEAR", round(entropy, 4),
            self.config.entropy_threshold_bits, self.config.entropy_weight if triggered else 0,
            f"Label {label!r} has entropy {entropy:.4f} bits; threshold is {self.config.entropy_threshold_bits:.2f} bits.",
            {"label": label, "aggregation": "maximum eligible label entropy"},
        )
