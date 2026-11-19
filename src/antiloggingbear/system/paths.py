# Anti-Logging Bear by Priest

from __future__ import annotations

import os
import sys
from pathlib import Path

from .. import DATA_NAME

ASSETS = Path(__file__).resolve().parent.parent / "assets"


def config_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        path = base / DATA_NAME
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / DATA_NAME
    else:
        path = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "anti-logging-bear"
    path.mkdir(parents=True, exist_ok=True)
    return path


def quarantine_dir() -> Path:
    path = config_dir() / "Quarantine"
    path.mkdir(parents=True, exist_ok=True)
    return path


def downloads_dir() -> Path:
    if sys.platform == "win32":
        found = _windows_known_folder("{374DE290-123F-4565-9164-39C4925E467B}")
        if found:
            return Path(found)
    return Path.home() / "Downloads"


def _windows_known_folder(guid: str):
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                        ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        folder_id = GUID()
        ctypes.oledll.ole32.CLSIDFromString(ctypes.c_wchar_p(guid), ctypes.byref(folder_id))
        out = ctypes.c_wchar_p()
        ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(folder_id), 0, None, ctypes.byref(out))
        value = out.value
        ctypes.windll.ole32.CoTaskMemFree(out)
        return value
    except (OSError, AttributeError):
        return None


def asset(name: str) -> Path:
    return ASSETS / name
