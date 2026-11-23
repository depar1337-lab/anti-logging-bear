# Anti-Logging Bear by Priest

from __future__ import annotations

import hashlib
import io

import pytest

from antiloggingbear import app_updates

PAYLOAD = b"pretend installer"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
BASE = app_updates.DOWNLOADS + "v9.9.9/"


def release(tag="v9.9.9", digest=DIGEST, url=None):
    return {
        "tag_name": tag,
        "html_url": "https://github.com/depar1337-lab/anti-logging-bear/releases/tag/" + tag,
        "body": "## What's new\n- Faster scans",
        "assets": [
            {"name": "BarryBear-x64-setup.exe", "browser_download_url": url or BASE + "BarryBear-x64-setup.exe",
             "digest": "sha256:" + digest, "size": len(PAYLOAD)},
            {"name": "BarryBear-macOS-Intel.dmg", "browser_download_url": BASE + "BarryBear-macOS-Intel.dmg",
             "digest": "sha256:" + "0" * 64, "size": 10},
        ],
    }


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_versions_compare_numerically():
    assert app_updates.parse_version("v1.10.0") > app_updates.parse_version("1.9.3")
    assert app_updates.parse_version("1.2") == (1, 2, 0)


def test_newer_release_is_found(monkeypatch):
    monkeypatch.setattr(app_updates, "_get_json", lambda url: release())
    update = app_updates.check("1.2.0", "BarryBear-x64-setup.exe")
    assert update.version == "9.9.9"
    assert update.sha256 == DIGEST
    assert "Faster scans" in update.notes


def test_same_or_older_release_is_ignored(monkeypatch):
    monkeypatch.setattr(app_updates, "_get_json", lambda url: release("v1.2.0"))
    assert app_updates.check("1.2.0", "BarryBear-x64-setup.exe") is None
    monkeypatch.setattr(app_updates, "_get_json", lambda url: release("v1.1.0"))
    assert app_updates.check("1.2.0", "BarryBear-x64-setup.exe") is None


def test_downloads_outside_github_are_not_used(monkeypatch):
    monkeypatch.setattr(app_updates, "_get_json", lambda url: release(url="https://evil.example/setup.exe"))
    update = app_updates.check("1.2.0", "BarryBear-x64-setup.exe")
    assert update.url == ""
    with pytest.raises(ValueError):
        app_updates.download(update)


def test_download_checks_the_fingerprint(monkeypatch, tmp_path):
    monkeypatch.setattr(app_updates.urllib.request, "urlopen", lambda req, timeout: FakeResponse(PAYLOAD))
    monkeypatch.setattr(app_updates, "_get_json", lambda url: release())
    good = app_updates.check("1.2.0", "BarryBear-x64-setup.exe")
    path = app_updates.download(good, folder=tmp_path)
    assert path.read_bytes() == PAYLOAD

    monkeypatch.setattr(app_updates, "_get_json", lambda url: release(digest="1" * 64))
    bad = app_updates.check("1.2.0", "BarryBear-x64-setup.exe")
    rejected = tmp_path / "rejected"
    rejected.mkdir()
    with pytest.raises(ValueError):
        app_updates.download(bad, folder=rejected)
    assert not (rejected / "BarryBear-x64-setup.exe").exists()


def test_asset_choice_per_platform():
    assert app_updates.wanted_asset("darwin", "arm64") == "BarryBear-macOS-AppleSilicon.dmg"
    assert app_updates.wanted_asset("darwin", "x86_64") == "BarryBear-macOS-Intel.dmg"
    assert app_updates.wanted_asset("win32", "AMD64", installed=True).endswith("-setup.exe")
    assert app_updates.wanted_asset("win32", "AMD64", installed=False).endswith("-portable.zip")
    assert app_updates.wanted_asset("linux", "x86_64") == ""


def test_installed_copy_is_recognised(tmp_path):
    exe = tmp_path / "BarryBear.exe"
    exe.write_bytes(b"MZ")
    assert not app_updates.installed_copy(str(exe))
    (tmp_path / "unins000.exe").write_bytes(b"MZ")
    assert app_updates.installed_copy(str(exe))


def test_daily_check_timing():
    import datetime as dt
    now = dt.datetime(2026, 11, 23, 12, tzinfo=dt.timezone.utc)
    assert app_updates.due("", now)
    assert not app_updates.due("2026-11-23T01:00:00+00:00", now)
    assert app_updates.due("2026-11-22T11:00:00+00:00", now)
