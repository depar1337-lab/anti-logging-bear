# Anti-Logging Bear by Priest

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Sequence

from .. import __version__
from .findings import Finding, Severity

API = "https://www.virustotal.com/api/v3/files/"
FREE_TIER_INTERVAL = 15.5


class VirusTotal:
    def __init__(self, api_key: str, max_lookups: int = 4) -> None:
        self.api_key = api_key.strip()
        self.max_lookups = max_lookups
        self._last_call = 0.0

    def lookup_many(self, items: Sequence[tuple[str, str]], cancelled=lambda: False) -> tuple[str, list[Finding]]:
        findings: list[Finding] = []
        checked = known = 0
        for path, sha256 in list(items)[: self.max_lookups]:
            if cancelled():
                break
            try:
                result = self._lookup(sha256)
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    return "VirusTotal: API key rejected", findings
                if exc.code == 429:
                    return f"VirusTotal: rate limit reached, checked {checked}", findings
                return f"VirusTotal: error {exc.code}", findings
            except (urllib.error.URLError, OSError, ValueError) as exc:
                return "VirusTotal: offline ({})".format(getattr(exc, "reason", exc)), findings
            checked += 1
            if result is None:
                continue
            known += 1
            malicious, total, label = result
            if malicious >= 3:
                sev = Severity.CRITICAL
            elif malicious >= 1:
                sev = Severity.MEDIUM
            else:
                continue
            title = f"{malicious} of {total} antivirus engines on VirusTotal flag this file"
            if label:
                title += f" ({label})"
            findings.append(Finding(path, "vt.detections", sev, title,
                                    "https://www.virustotal.com/gui/file/" + sha256))
        return f"VirusTotal: {checked} checked, {known} known", findings

    def _lookup(self, sha256: str):
        wait = FREE_TIER_INTERVAL - (time.monotonic() - self._last_call)
        if self._last_call and wait > 0:
            time.sleep(wait)
        request = urllib.request.Request(API + sha256, headers={
            "x-apikey": self.api_key,
            "User-Agent": "BarryBear/" + __version__,
        })
        self._last_call = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, int))
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
        return malicious, total, label
