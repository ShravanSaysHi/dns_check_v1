"""Local allowlist and blocklist loading and matching."""

from pathlib import Path

from dns_guard.domain import normalize_domain, domain_match


def load_domain_list(path: Path) -> tuple[str, ...]:
    if not path.exists():
        return ()
    entries: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        item = line.split("#", 1)[0].strip()
        if not item:
            continue
        try:
            parsed = normalize_domain(item)
        except ValueError as exc:
            raise ValueError(f"Invalid domain in {path}: {item!r} ({exc})") from exc
        # Reserved dotted domains such as malware.test are useful safe fixtures.
        if parsed.is_ip or "." not in parsed.hostname:
            raise ValueError(f"List entry must be a dotted domain: {item!r}")
        entries.append(parsed.hostname)
    return tuple(dict.fromkeys(entries))


def find_match(hostname: str, entries: tuple[str, ...]) -> str | None:
    return next((entry for entry in entries if domain_match(hostname, entry)), None)
