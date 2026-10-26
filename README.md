# DNS Guard — Phase 1 prototype

DNS Guard is a small terminal domain-analysis prototype. It normalizes a submitted hostname, checks local policy files, then (unless allowlisted) combines a registration-age indicator and Shannon label entropy into an explainable score. `ALLOW`, `FLAG`, and `BLOCK` are assessments only: this program does not intercept DNS or block connections. It never opens a submitted website; the only network operation is a bounded RDAP lookup through `rdap.org`.

## Setup

Requires Python 3.11 or later. On Arch Linux, install Python, venv support and libpsl with `sudo pacman -S python libpsl`; then use the portable setup below:

```bash
cd "/home/clown/Documents/New Project"
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m dns_guard
```

The package reads the system Public Suffix List through `libpsl`; it does not download suffix data at runtime. On Linux, `libpsl` must be installed. Configuration and policy paths are relative to the current working directory; run the CLI from the project root. Analyze one item with `python -m dns_guard example.org`.

## How it works

1. URL or hostname is parsed, lowercased and IDNA-encoded. IPs and local/reserved names skip domain checks.
2. `data/blocklist.txt` is checked first. Entries match the domain itself and subdomains on label boundaries.
3. `data/allowlist.txt` permits a match through a fast path, with age and entropy checks marked `SKIPPED`.
4. Other public domains receive a registration-age lookup and entropy analysis. RDAP failures are `UNKNOWN` and contribute no points. Entropy examines eligible non-suffix hostname labels and the registrable label; the maximum eligible entropy is counted once.
5. Indicators add configurable points. Default score boundaries are 25 for `FLAG` and 50 for `BLOCK`; a blocklist match is an immediate block.
6. Completed analyses append JSON Lines records to `logs/analysis.jsonl`. URL paths and query strings are not saved.

Edit the two text lists (one domain per line; `#` comments are ignored) and `config.json` to change policy and thresholds. The supplied allowlist is a small demo list and does not guarantee all subdomains are safe. The default blocklist contains only the synthetic `malware.test` entry.

## Tests and lint

```bash
python -m pytest
ruff check .
ruff format --check .
```

RDAP behavior is tested with mocked synthetic responses; test execution does not need network access. These checks are separate from a live lookup, which may return `UNKNOWN` due to network, server, registry or rate-limit conditions.

## Limitations and Phase 2

This is a rule-based educational prototype, not validated phishing detection. Entropy is a heuristic and registration age can be unavailable or misleading. The RDAP bootstrap endpoint behavior may differ across domain registries. The CLI does not resolve DNS, proxy queries, intercept traffic, or enforce its decision. Phase 2 can evaluate additional detection rules and integration choices after review of this prototype. A DNS proxy, dashboard, API, DGA rule, beacon analysis, machine learning and SaaS features are intentionally deferred.
