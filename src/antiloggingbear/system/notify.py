# Anti-Logging Bear by Priest

from __future__ import annotations

import shutil
import subprocess
import sys


def _applescript_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def notify(title: str, message: str, tray=None) -> None:
    if tray is not None:
        try:
            tray.notify(message, title)
            return
        except Exception:
            pass
    try:
        if sys.platform == "darwin":
            script = f"display notification {_applescript_string(message)} with title {_applescript_string(title)}"
            subprocess.Popen(["osascript", "-e", script])
        elif sys.platform.startswith("linux") and shutil.which("notify-send"):
            subprocess.Popen(["notify-send", title, message])
    except OSError:
        pass
