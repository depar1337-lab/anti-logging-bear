# Anti-Logging Bear by Priest

from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import __version__

REPO = "depar1337-lab/anti-logging-bear"
LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
DOWNLOADS = f"https://github.com/{REPO}/releases/download/"
CHECK_EVERY = dt.timedelta(days=1)
MAX_DOWNLOAD = 400 * 1024 * 1024


@dataclass
class Update:
    version: str
    page: str
    notes: str
    asset: str = ""
    url: str = ""
    sha256: str = ""
    size: int = 0

    @property
    def installable(self) -> bool:
        return bool(self.url and self.sha256 and sys.platform == "win32")


def parse_version(text: str) -> tuple:
    numbers = re.findall(r"\d+", text.split("-", 1)[0])
    return tuple(int(n) for n in numbers[:3]) + (0,) * (3 - len(numbers[:3]))


def due(last_checked: str, now: dt.datetime | None = None) -> bool:
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        last = dt.datetime.fromisoformat(last_checked)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=dt.timezone.utc)
    return now - last >= CHECK_EVERY


def installed_copy(executable: str | None = None) -> bool:
    exe = Path(executable or sys.executable)
    return bool(getattr(sys, "frozen", False) or executable) and any(exe.parent.glob("unins*.exe"))


def wanted_asset(system: str | None = None, machine: str | None = None, installed: bool | None = None) -> str:
    system = system or sys.platform
    machine = (machine or platform.machine() or "").lower()
    if system == "win32":
        bits = "x64" if sys.maxsize > 2 ** 32 else "x86"
        if installed if installed is not None else installed_copy():
            return f"BarryBear-{bits}-setup.exe"
        return f"BarryBear-{bits}-portable.zip"
    if system == "darwin":
        return "BarryBear-macOS-AppleSilicon.dmg" if machine in ("arm64", "aarch64") else "BarryBear-macOS-Intel.dmg"
    return ""


def check(current: str = __version__, asset_name: str | None = None) -> Update | None:
    release = _get_json(LATEST)
    tag = str(release.get("tag_name") or "")
    if release.get("draft") or release.get("prerelease") or parse_version(tag) <= parse_version(current):
        return None
    update = Update(version=tag.lstrip("v"), page=str(release.get("html_url") or ""),
                    notes=str(release.get("body") or "")[:4000])
    name = asset_name if asset_name is not None else wanted_asset()
    for asset in release.get("assets") or []:
        url = str(asset.get("browser_download_url") or "")
        if asset.get("name") == name and url.startswith(DOWNLOADS):
            digest = str(asset.get("digest") or "")
            update.asset = name
            update.url = url
            update.sha256 = digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else ""
            update.size = int(asset.get("size") or 0)
    return update


def download(update: Update, progress: Callable[[int, int], None] = lambda done, total: None,
             folder: Path | None = None) -> Path:
    if not update.url.startswith(DOWNLOADS) or not re.fullmatch(r"[0-9a-f]{64}", update.sha256):
        raise ValueError("the update has no trusted download or fingerprint")
    folder = folder or Path(tempfile.mkdtemp(prefix="barry-update-"))
    target = folder / update.asset
    digest = hashlib.sha256()
    done = 0
    with urllib.request.urlopen(_request(update.url), timeout=60) as resp, open(target, "wb") as fh:
        while True:
            chunk = resp.read(256 * 1024)
            if not chunk:
                break
            done += len(chunk)
            if done > MAX_DOWNLOAD:
                raise ValueError("the update is unexpectedly large")
            digest.update(chunk)
            fh.write(chunk)
            progress(done, update.size)
    if digest.hexdigest() != update.sha256:
        target.unlink()
        raise ValueError("the downloaded update doesn't match its published fingerprint")
    return target


def run_installer(installer: Path) -> None:
    flags = 0
    if sys.platform == "win32":
        flags = 0x00000008 | 0x00000200
    subprocess.Popen([str(installer), "/SILENT", "/SP-", "/SUPPRESSMSGBOXES", "/NORESTART"],
                     close_fds=True, creationflags=flags, cwd=str(installer.parent))


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": "BarryBear/" + __version__,
                                                "Accept": "application/vnd.github+json"})


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(_request(url), timeout=30) as resp:
        return json.loads(resp.read(2 * 1024 * 1024).decode("utf-8"))


def open_in_browser(url: str) -> None:
    import webbrowser
    if url.startswith("https://github.com/" + REPO + "/"):
        webbrowser.open(url)
