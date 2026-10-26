"""Terminal rendering and JSON Lines logging."""

import json
from pathlib import Path

from dns_guard.models import AnalysisResult


def format_result(result: AnalysisResult) -> str:
    lines = ["\n[DOMAIN]", f"Hostname: {result.hostname}",
             f"Registrable domain: {result.registrable_domain or 'UNKNOWN'}",
             "\n[FAST PATH]", f"Blocklist: {'MATCH ' + result.blocklist_match if result.blocklist_match else 'NO MATCH'}",
             f"Allowlist: {'MATCH ' + result.allowlist_match if result.allowlist_match else 'NO MATCH'}",
             f"Fast path: {'USED' if result.fast_path else 'NOT USED'}"]
    for rule in result.rules:
        title = ("RULE 1 — DOMAIN INTELLIGENCE"
                 if rule.rule in {"domain_intelligence", "domain_age", "local_reputation"}
                 else "RULE 2 — SHANNON ENTROPY")
        lines.extend([f"\n[{title}]", f"Status: {rule.status}"])
        if rule.rule == "domain_age":
            lines.extend([f"Registration age: {rule.value if rule.value is not None else 'UNKNOWN'} days",
                          f"Age threshold: {rule.threshold} days"])
        elif rule.rule == "entropy":
            if rule.details.get("label"):
                lines.append(f"Label analysed: {rule.details['label']}")
            lines.extend([f"Entropy: {rule.value if rule.value is not None else 'UNKNOWN'} bits",
                          f"Threshold: {rule.threshold} bits"])
        lines.append(f"Reason: {rule.reason}")
    lines.extend(["\n[FINAL ASSESSMENT]", f"Risk score: {result.score}", f"Decision: {result.decision}", "Reasons:"])
    lines.extend(f"- {reason}" for reason in result.explanations)
    return "\n".join(lines)


def append_jsonl(path: Path, result: AnalysisResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")
