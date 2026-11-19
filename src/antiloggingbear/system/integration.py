# Anti-Logging Bear by Priest

from __future__ import annotations

import contextlib
import os
import plistlib
import subprocess
import sys
from pathlib import Path

from .. import APP_NAME, DATA_NAME
from . import paths

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
MENU_KEY = r"Software\Classes\*\shell\AntiLoggingBear"
LAUNCH_AGENT = Path.home() / "Library" / "LaunchAgents" / "com.priest.antiloggingbear.plist"
AUTOSTART = Path.home() / ".config" / "autostart" / "anti-logging-bear.desktop"


def launch_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable]
    exe = sys.executable
    if sys.platform == "win32" and exe.lower().endswith("python.exe"):
        windowed = exe[:-10] + "pythonw.exe"
        if os.path.isfile(windowed):
            exe = windowed
    return [exe, "-m", "antiloggingbear"]


def _quote(parts: list[str]) -> str:
    return subprocess.list2cmdline(parts)


def supports_context_menu() -> bool:
    return sys.platform == "win32"


def set_start_at_login(enabled: bool) -> None:
    command = launch_command() + ["--background"]
    if sys.platform == "win32":
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            with contextlib.suppress(FileNotFoundError):
                winreg.DeleteValue(key, DATA_NAME)
            if enabled:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _quote(command))
            else:
                with contextlib.suppress(FileNotFoundError):
                    winreg.DeleteValue(key, APP_NAME)
    elif sys.platform == "darwin":
        if enabled:
            LAUNCH_AGENT.parent.mkdir(parents=True, exist_ok=True)
            with open(LAUNCH_AGENT, "wb") as fh:
                plistlib.dump({"Label": "com.priest.antiloggingbear", "ProgramArguments": command,
                               "RunAtLoad": True, "ProcessType": "Interactive"}, fh)
        elif LAUNCH_AGENT.exists():
            LAUNCH_AGENT.unlink()
    else:
        if enabled:
            AUTOSTART.parent.mkdir(parents=True, exist_ok=True)
            AUTOSTART.write_text(
                f"[Desktop Entry]\nType=Application\nName={APP_NAME}\nExec={_quote(command)}\n"
                "X-GNOME-Autostart-enabled=true\n", encoding="utf-8")
        elif AUTOSTART.exists():
            AUTOSTART.unlink()


def set_context_menu(enabled: bool) -> None:
    if sys.platform != "win32":
        return
    import winreg
    if enabled:
        icon = sys.executable if getattr(sys, "frozen", False) else str(paths.asset("app.ico"))
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, MENU_KEY) as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, f"Check with {APP_NAME}")
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, MENU_KEY + r"\command") as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, _quote(launch_command() + ["--gui"]) + ' "%1"')
    else:
        for sub in (MENU_KEY + r"\command", MENU_KEY):
            with contextlib.suppress(FileNotFoundError):
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)


def open_folder(path: str) -> None:
    if sys.platform == "win32":
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def enable_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        with contextlib.suppress(AttributeError, OSError):
            ctypes.windll.user32.SetProcessDPIAware()
