# Anti-Logging Bear by Priest

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Sequence

from .. import __version__
from .findings import Finding, Severity

API = "https://mb-api.abuse.ch/api/v1/"
SAMPLE_PAGE = "https://bazaar.abuse.ch/sample/{}/"


class MalwareBazaar:
    def __init__(self, api_key: str, max_lookups: int = 25) -> None:
        self.api_key = api_key.strip()
        self.max_lookups = max_lookups

    def lookup_many(self, items: Sequence[tuple[str, str]], cancelled=lambda: False) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        checked = known = 0
        for path, sha256 in list(items)[: self.max_lookups]:
            if cancelled():
                break
            try:
                result = self._lookup(sha256)
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403):
                    return "MalwareBazaar: Auth-Key rejected", findings
                if exc.code == 429:
                    return f"MalwareBazaar: rate limit reached, checked {checked}", findings
                return f"MalwareBazaar: error {exc.code}", findings
            except (urllib.error.URLError, OSError, ValueError) as exc:
                return "MalwareBazaar: offline ({})".format(getattr(exc, "reason", exc)), findings
            checked += 1
            if result is None:
                continue
            known += 1
            signature, tags = result
            name = signature or ", ".join(tags[:3]) or "unnamed malware"
            findings.append(Finding(path, "mb.known", Severity.CRITICAL,
                                    f"Known malware on MalwareBazaar ({name})",
                                    "This exact file has been reported as malware. " + SAMPLE_PAGE.format(sha256)))
        return f"MalwareBazaar: {checked} checked, {known} known malware", findings

    def _lookup(self, sha256: str):
        body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode("ascii")
        request = urllib.request.Request(API, data=body, headers={
            "Auth-Key": self.api_key,
            "User-Agent": "BarryBear/" + __version__,
        })
        with urllib.request.urlopen(request, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        status = payload.get("query_status")
        if status in ("hash_not_found", "no_results"):
            return None
        if status in ("unknown_auth_key", "user_blacklisted"):
            raise urllib.error.HTTPError(API, 401, status, None, None)
        if status != "ok":
            raise ValueError(f"unexpected reply: {status}")
        entry = (payload.get("data") or [{}])[0]
        return str(entry.get("signature") or ""), [str(t) for t in entry.get("tags") or []]
