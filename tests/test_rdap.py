import json
from datetime import timezone
from unittest.mock import patch
import pytest
from dns_guard.services.rdap import RDAPClient, RDAPLookupError

class Response:
    def __enter__(self): return self
    def __exit__(self, *_args): return None
    def read(self):
        return json.dumps({"events": [{"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"}]}).encode()

def test_rdap_date_parsing_and_cache():
    client = RDAPClient()
    with patch("urllib.request.urlopen", return_value=Response()) as request:
        date = client.creation_date("example.org")
        assert date.tzinfo == timezone.utc
        assert client.creation_date("example.org") == date
        request.assert_called_once()

def test_rdap_timeout_becomes_expected_error():
    with patch("urllib.request.urlopen", side_effect=TimeoutError("slow")):
        with pytest.raises(RDAPLookupError): RDAPClient().creation_date("example.org")

def test_missing_date_returns_unknown():
    class NoDate(Response):
        def read(self): return b'{"events": []}'
    with patch("urllib.request.urlopen", return_value=NoDate()):
        assert RDAPClient().creation_date("example.org") is None

def test_malformed_json_is_a_lookup_error():
    class InvalidResponse(Response):
        def read(self): return b"not-json"
    with patch("urllib.request.urlopen", return_value=InvalidResponse()):
        with pytest.raises(RDAPLookupError):
            RDAPClient().creation_date("example.org")
