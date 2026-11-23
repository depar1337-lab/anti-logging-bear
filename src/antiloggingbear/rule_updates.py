# Anti-Logging Bear by Priest

from __future__ import annotations

import datetime as dt
import json
import os
import urllib.request
from pathlib import Path

from . import __version__
from .engine import forge

LATEST = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
CHECK_EVERY = dt.timedelta(days=7)
MAX_DOWNLOAD = 64 * 1024 * 1024


def due(last_checked: str, now: dt.datetime | None = None) -> bool:
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        last = dt.datetime.fromisoformat(last_checked)
    except ValueError:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=dt.timezone.utc)
    return now - last >= CHECK_EVERY


def update(data_dir: Path, current_release: str) -> str | None:
    release = _get_json(LATEST)
    tag = str(release.get("tag_name") or "")
    if not tag or tag <= current_release:
        return None
    assets = {a.get("name"): a.get("browser_download_url") for a in release.get("assets") or []}
    full = assets.get("yara-forge-rules-full.zip")
    core = assets.get("yara-forge-rules-core.zip")
    if not full or not core or not _github(full) or not _github(core):
        return None
    blob = forge.build_bundle(_download(full), _download(core), tag)

    import yara
    forge.compile_bundle(yara, forge.read_bundle(blob), None)

    data_dir.mkdir(parents=True, exist_ok=True)
    target = data_dir / forge.BUNDLE_NAME
    temporary = target.with_suffix(".tmp")
    temporary.write_bytes(blob)
    os.replace(str(temporary), str(target))
    return tag


def _github(url: str) -> bool:
    return url.startswith("https://github.com/YARAHQ/yara-forge/releases/download/")


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": "BarryBear/" + __version__,
                                                "Accept": "application/vnd.github+json"})


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(_request(url), timeout=30) as resp:
        return json.loads(resp.read(1024 * 1024).decode("utf-8"))


def _download(url: str) -> bytes:
    with urllib.request.urlopen(_request(url), timeout=300) as resp:
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("rule package is unexpectedly large")
    return data
