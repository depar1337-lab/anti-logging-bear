# Anti-Logging Bear by Priest

from __future__ import annotations

import os
import threading
from pathlib import Path

from .findings import Finding, Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_SEVERITIES = {s.name.lower(): s for s in Severity}


class YaraEngine:
    def __init__(self, extra_dir: str = "") -> None:
        self.status = "not loaded"
        self._rules = None
        self._lock = threading.Lock()
        self._extra_dir = extra_dir

    def load(self) -> bool:
        with self._lock:
            if self._rules is not None:
                return True
            try:
                import yara
            except ImportError:
                self.status = "unavailable (yara-python not installed)"
                return False
            sources = {}
            for folder in (RULES_DIR, Path(self._extra_dir) if self._extra_dir else None):
                if folder is None or not folder.is_dir():
                    continue
                for path in sorted(folder.glob("*.yar")) + sorted(folder.glob("*.yara")):
                    sources[f"{folder.name}_{path.stem}"] = str(path)
            if not sources:
                self.status = "no rules found"
                return False
            try:
                self._rules = yara.compile(filepaths=sources)
            except yara.Error as exc:
                self.status = f"rule error: {exc}"
                return False
            self.status = f"ready ({len(sources)} rule files)"
            return True

    def match(self, path: str, data: bytes) -> list[Finding]:
        if self._rules is None:
            return []
        try:
            matches = self._rules.match(data=data, timeout=20)
        except Exception as exc:
            return [Finding(path, "yara.error", Severity.INFO, "YARA could not finish", str(exc)[:200])]
        out: list[Finding] = []
        for m in matches:
            meta = m.meta or {}
            severity = _SEVERITIES.get(str(meta.get("severity", "high")).lower(), Severity.HIGH)
            title = str(meta.get("title") or meta.get("description") or m.rule)
            out.append(Finding(path, "yara." + m.rule, severity, title,
                               f"YARA rule {m.rule} ({m.namespace})"))
        return out


_shared: YaraEngine | None = None


def shared_engine(extra_dir: str = "") -> YaraEngine:
    global _shared
    if _shared is None or _shared._extra_dir != extra_dir:
        _shared = YaraEngine(extra_dir if extra_dir and os.path.isdir(extra_dir) else "")
        _shared.load()
    return _shared
