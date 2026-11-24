# Anti-Logging Bear by Priest

from __future__ import annotations

import os
import threading
from pathlib import Path

from . import forge
from .findings import Finding, Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_SEVERITIES = {s.name.lower(): s for s in Severity}


class YaraEngine:
    def __init__(self, extra_dir: str = "", data_dir: str = "") -> None:
        self.status = "not loaded"
        self.release = ""
        self.community_rules = 0
        self._rules = None
        self._forge = None
        self._core: frozenset = frozenset()
        self._lock = threading.Lock()
        self._extra_dir = extra_dir
        self._data_key = data_dir or ""
        self._data_dir = Path(data_dir) if data_dir else None

    def load(self) -> bool:
        with self._lock:
            if self._rules is not None or self._forge is not None:
                return True
            try:
                import yara
            except ImportError:
                self.status = "unavailable (yara-python not installed)"
                return False
            notes = []
            own = self._own_sources()
            if own:
                try:
                    self._rules = yara.compile(filepaths=own)
                    notes.append(f"{len(own)} Barry rule file(s)")
                except yara.Error as exc:
                    notes.append(f"rule error: {exc}")
            found = forge.newest_bundle(*self._bundle_paths())
            if found is not None:
                _path, bundle = found
                cache = self._data_dir / "cache" if self._data_dir else None
                try:
                    ready = forge.load_precompiled(yara, RULES_DIR / forge.COMPILED_NAME, bundle)
                    if ready is not None:
                        self._forge, self.community_rules = ready
                    else:
                        self._forge, self.community_rules = forge.compile_bundle(yara, bundle, cache)
                    self._core = bundle.core
                    self.release = bundle.release
                    notes.insert(0, f"{self.community_rules:,} community rules from YARA Forge {_pretty(bundle.release)}")
                except Exception as exc:
                    notes.append(f"community rules failed to load ({str(exc)[:80]})")
            if self._rules is None and self._forge is None:
                self.status = "no rules found" if not notes else notes[-1]
                return False
            self.status = "ready: " + ", ".join(notes)
            return True

    def _own_sources(self) -> dict:
        sources = {}
        for folder in (RULES_DIR, Path(self._extra_dir) if self._extra_dir else None):
            if folder is None or not folder.is_dir():
                continue
            for path in sorted(folder.glob("*.yar")) + sorted(folder.glob("*.yara")):
                sources[f"{folder.name}_{path.stem}"] = str(path)
        return sources

    def _bundle_paths(self) -> list:
        paths = [RULES_DIR / forge.BUNDLE_NAME]
        if self._data_dir is not None:
            paths.append(self._data_dir / forge.BUNDLE_NAME)
        return paths

    def match(self, path: str, data: bytes) -> list[Finding]:
        out: list[Finding] = []
        if self._rules is not None:
            for m in self._safe_match(self._rules, path, data, out):
                meta = m.meta or {}
                severity = _SEVERITIES.get(str(meta.get("severity", "high")).lower(), Severity.HIGH)
                title = str(meta.get("title") or meta.get("description") or m.rule)
                out.append(Finding(path, "yara." + m.rule, severity, title, f"YARA rule {m.rule} ({m.namespace})"))
        if self._forge is not None:
            for m in self._safe_match(self._forge, path, data, out):
                meta = m.meta or {}
                severity, title, _kind = forge.grade(m.rule, meta, self._core)
                detail = f"YARA Forge rule {m.rule}"
                if meta.get("author"):
                    detail += f" by {meta['author']}"
                if meta.get("reference"):
                    detail += f". {meta['reference']}"
                out.append(Finding(path, "forge." + m.rule, severity, title, detail))
        return out

    @staticmethod
    def _safe_match(rules, path: str, data: bytes, out: list):
        try:
            return rules.match(data=data, timeout=30)
        except Exception as exc:
            out.append(Finding(path, "yara.error", Severity.INFO, "YARA could not finish", str(exc)[:200]))
            return []


def _pretty(release: str) -> str:
    if len(release) == 8 and release.isdigit():
        return f"{release[:4]}-{release[4:6]}-{release[6:]}"
    return release


_shared: YaraEngine | None = None
_shared_lock = threading.Lock()


def shared_engine(extra_dir: str = "", data_dir: str = "") -> YaraEngine:
    global _shared
    extra = extra_dir if extra_dir and os.path.isdir(extra_dir) else ""
    with _shared_lock:
        if _shared is None or _shared._extra_dir != extra or _shared._data_key != (data_dir or ""):
            _shared = YaraEngine(extra, data_dir)
        engine = _shared
    engine.load()
    return engine


def summary() -> str:
    engine = _shared
    if engine is None or (engine._rules is None and engine._forge is None):
        return "loading" if engine is None else "no rules"
    total = engine.community_rules + (1 if engine._rules is not None else 0)
    return f"{engine.community_rules:,} rules" if engine.community_rules else "on" if total else "no rules"


def reset_shared() -> None:
    global _shared
    with _shared_lock:
        _shared = None
