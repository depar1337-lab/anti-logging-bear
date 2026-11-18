# Anti-Logging Bear by Priest

from __future__ import annotations

import datetime
import json
import os

from .engine.findings import ScanReport
from .system import paths

LIMIT = 200


class History:
    def __init__(self) -> None:
        self.path = paths.config_dir() / "history.json"
        self.entries: list[dict] = self._load()

    def _load(self) -> list[dict]:
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def add(self, report: ScanReport, source: str) -> None:
        self.entries.insert(0, {
            "when": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "path": report.target,
            "verdict": report.verdict.value,
            "findings": len(report.findings),
            "source": source,
        })
        del self.entries[LIMIT:]
        tmp = self.path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.entries, fh, indent=1)
            os.replace(str(tmp), str(self.path))
        except OSError:
            pass
