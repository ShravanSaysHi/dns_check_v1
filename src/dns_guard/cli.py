"""Interactive terminal interface."""

import argparse
from pathlib import Path

from dns_guard.config import load_config
from dns_guard.engine import AnalysisEngine
from dns_guard.filters import load_domain_list
from dns_guard.reporting import append_jsonl, format_result


def main() -> int:
    parser = argparse.ArgumentParser(description="Explainable DNS Guard domain-analysis prototype")
    parser.add_argument("value", nargs="?", help="Optional URL or hostname to analyze once")
    args = parser.parse_args()
    root = Path.cwd()
    try:
        config = load_config(root / "config.json")
        allowlist = load_domain_list(root / config.allowlist_path)
        blocklist = load_domain_list(root / config.blocklist_path)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    engine = AnalysisEngine(config, allowlist, blocklist)
    print("========================================\n       DNS GUARD — DOMAIN ANALYSIS\n========================================")
    try:
        pending = args.value
        while True:
            value = pending if pending is not None else input("\nEnter a URL or domain (q to quit):\n> ")
            pending = None
            if value.strip().lower() in {"q", "quit", "exit"}:
                break
            if not value.strip():
                print("Please enter a non-empty URL or hostname.")
                continue
            try:
                result = engine.analyze(value)
                print(format_result(result))
                try:
                    append_jsonl(root / config.jsonl_log_path, result)
                except OSError as exc:
                    print(f"Warning: could not write analysis log: {exc}")
            except ValueError as exc:
                print(f"Invalid input: {exc}")
            if args.value is not None:
                break
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye.")
    return 0
