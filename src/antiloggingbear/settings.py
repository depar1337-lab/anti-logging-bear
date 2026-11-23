# Anti-Logging Bear by Priest

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field, fields

from .engine.archive import MB, Limits
from .engine.scanner import ScanOptions
from .system import paths

SETTINGS_FILE = "settings.json"


@dataclass
class Settings:
    auto_scan: bool = True
    watch_folders: list[str] = field(default_factory=lambda: [str(paths.downloads_dir())])
    exclusions: list[str] = field(default_factory=list)
    notify_clean: bool = False
    auto_quarantine: bool = False
    scan_all_types: bool = False

    strict: bool = False
    max_file_mb: int = 2048
    max_unpacked_mb: int = 1024
    use_yara: bool = True
    custom_rules_dir: str = ""
    update_rules: bool = True
    rules_checked: str = ""
    use_antivirus: bool = True

    vt_api_key: str = ""
    vt_max_lookups: int = 4
    mb_api_key: str = ""
    mb_max_lookups: int = 25

    start_at_login: bool = False
    context_menu: bool = False
    close_to_tray: bool = True

    show_details: bool = False
    high_contrast: bool = False
    large_text: bool = False
    first_run: bool = True

    def scan_options(self) -> ScanOptions:
        return ScanOptions(
            limits=Limits(max_total_bytes=self.max_unpacked_mb * MB),
            max_file_bytes=self.max_file_mb * MB,
            strict=self.strict,
            use_yara=self.use_yara,
            custom_rules_dir=self.custom_rules_dir,
            rules_dir=str(paths.config_dir() / "rules"),
            use_antivirus=self.use_antivirus,
            vt_api_key=self.vt_api_key,
            vt_max_lookups=self.vt_max_lookups,
            mb_api_key=self.mb_api_key,
            mb_max_lookups=self.mb_max_lookups,
        )


_lock = threading.Lock()


def load() -> Settings:
    path = paths.config_dir() / SETTINGS_FILE
    settings = Settings()
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return settings
    known = {f.name: f for f in fields(Settings)}
    for key, value in raw.items():
        if key in known and isinstance(value, type(getattr(settings, key))):
            setattr(settings, key, value)
    return settings


def save(settings: Settings) -> None:
    path = paths.config_dir() / SETTINGS_FILE
    tmp = path.with_suffix(".tmp")
    with _lock:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(asdict(settings), fh, indent=2)
        os.replace(str(tmp), str(path))
