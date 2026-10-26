import pytest
from dns_guard.domain import DomainInputError, normalize_domain

def test_url_case_and_trailing_dot():
    parsed = normalize_domain("HTTPS://Sub.Example.COM.:8080/path?q=x")
    assert parsed.hostname == "sub.example.com"
    assert parsed.registrable_domain == "example.com"

def test_idn_normalizes_to_ascii():
    assert normalize_domain("bücher.de").hostname == "xn--bcher-kva.de"

def test_ip_and_invalid_input():
    assert normalize_domain("127.0.0.1").is_ip
    with pytest.raises(DomainInputError):
        normalize_domain("https:///path")
