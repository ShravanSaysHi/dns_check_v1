"""Small synchronous RDAP client with bounded timeout and simple cache."""

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone


class RDAPLookupError(Exception):
    """Expected error while retrieving registration data."""


class RDAPClient:
    def __init__(self, timeout: float = 4.0) -> None:
        self.timeout = timeout
        self._cache: dict[str, datetime | None] = {}

    def creation_date(self, domain: str) -> datetime | None:
        if domain in self._cache:
            return self._cache[domain]
        request = urllib.request.Request(
            f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RDAPLookupError(str(exc)) from exc
        if not isinstance(data, dict):
            raise RDAPLookupError("RDAP response was not a JSON object")
        events = data.get("events", [])
        if not isinstance(events, list):
            raise RDAPLookupError("RDAP events field was malformed")
        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction", "")).lower()
            if action in {"registration", "registered", "creation"}:
                raw = event.get("eventDate")
                if not isinstance(raw, str):
                    continue
                try:
                    result = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if result.tzinfo is None:
                        result = result.replace(tzinfo=timezone.utc)
                    result = result.astimezone(timezone.utc)
                except ValueError:
                    continue
                self._cache[domain] = result
                return result
        self._cache[domain] = None
        return None
