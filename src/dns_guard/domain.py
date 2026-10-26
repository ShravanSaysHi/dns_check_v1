"""Hostname parsing, normalization and public-suffix-aware domain helpers."""

import ipaddress
import ctypes
import ctypes.util
from dataclasses import dataclass
from urllib.parse import urlsplit



def _registrable_domain(hostname: str) -> str | None:
    """Use the system libpsl database without downloading suffix data at runtime."""
    library_name = ctypes.util.find_library("psl")
    if library_name is None:
        raise RuntimeError("libpsl is required for public-suffix-aware domain parsing")
    library = ctypes.CDLL(library_name)
    library.psl_builtin.restype = ctypes.c_void_p
    library.psl_registrable_domain.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    library.psl_registrable_domain.restype = ctypes.c_char_p
    value = library.psl_registrable_domain(library.psl_builtin(), hostname.encode("ascii"))
    return value.decode("ascii").lower() if value else None


class DomainInputError(ValueError):
    """Raised when input cannot represent a valid analysis hostname."""


@dataclass(frozen=True)
class ParsedDomain:
    hostname: str
    registrable_domain: str | None
    is_ip: bool
    is_local_or_reserved: bool


def normalize_domain(value: str) -> ParsedDomain:
    candidate = value.strip()
    if not candidate:
        raise DomainInputError("Please enter a URL or hostname.")
    if any(char.isspace() for char in candidate):
        raise DomainInputError("A hostname cannot contain whitespace.")
    if "://" not in candidate:
        candidate = "//" + candidate
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        # Accessing port detects malformed port syntax.
        _ = parsed.port
    except ValueError as exc:
        raise DomainInputError(f"Invalid URL or port: {exc}") from exc
    if not hostname:
        raise DomainInputError("No hostname was found in the input.")
    hostname = hostname.rstrip(".").lower()
    if not hostname:
        raise DomainInputError("Hostname is empty after removing its trailing dot.")
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None:
        canonical = ip.compressed.lower()
        return ParsedDomain(canonical, None, True, True)
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DomainInputError(f"Hostname is not valid IDNA: {exc}") from exc
    if len(ascii_hostname) > 253:
        raise DomainInputError("Hostname exceeds the 253-character DNS limit.")
    labels = ascii_hostname.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise DomainInputError("Hostname contains an empty or overlong label.")
    if any(not all(ch.isalnum() or ch == "-" for ch in label) for label in labels):
        raise DomainInputError("Hostname labels may contain letters, digits and hyphens only.")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise DomainInputError("Hostname labels cannot start or end with a hyphen.")
    reserved_suffixes = {"test", "example", "invalid", "localhost", "local", "onion"}
    local = (
        ascii_hostname == "localhost"
        or "." not in ascii_hostname
        or ascii_hostname.rsplit(".", 1)[-1] in reserved_suffixes
    )
    sld = None if local else _registrable_domain(ascii_hostname)
    registrable = sld.lower() if sld else None
    return ParsedDomain(ascii_hostname, registrable, False, local or registrable is None)


def domain_match(hostname: str, entry: str) -> bool:
    """Match a domain itself and its subdomains on DNS label boundaries."""
    return hostname == entry or hostname.endswith("." + entry)
