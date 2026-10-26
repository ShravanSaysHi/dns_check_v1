# DNS Guard repeatable demonstration

Run from the project root after setup (`python -m pip install -e ".[dev]"`). To repeat without waiting for RDAP, use the offline test fixtures:

```bash
python -m pytest -q tests/test_engine.py
```

These tests inject a fake RDAP client; the supplied registration timestamps are synthetic and are not live registration evidence.

## Case A — allowlisted fast path

```bash
python -m dns_guard sub.example.com
```

The default allowlist contains `example.com`. Expect a match, `Fast path: USED`, `ALLOW`, and both rules `SKIPPED`. The blocklist is checked first.

## Case B — synthetic blocklist precedence

Append `malware.test` to `data/allowlist.txt` temporarily, then run:

```bash
python -m dns_guard sub.malware.test
```

Expect immediate `BLOCK` with blocklist entry `malware.test`, even though it also appears on the allowlist. Remove the temporary allowlist entry afterwards. The shipped blocklist entry is synthetic and uses the reserved `.test` namespace.

## Case C — domain requiring analysis

```bash
python -m dns_guard xq7mz91k.example.org
```

This domain is absent from both lists. Expect age and entropy rule output. RDAP may succeed or show `UNKNOWN` if network/registry service is unavailable; this does not add age points. Entropy is calculated locally from eligible hostname labels.

## Case D — combined heuristic score, offline

```bash
python -m pytest -q tests/test_engine.py::test_combined_synthetic_indicators_and_logging
```

The test injects a synthetic one-day-old registration timestamp and label `abcdefgh`, producing two 25-point indicators and a 50-point `BLOCK` score. It makes no network request and does not claim that `example.org` has that actual age.

Each CLI analysis appends a local JSON object to `logs/analysis.jsonl`; that runtime log is ignored by Git.
