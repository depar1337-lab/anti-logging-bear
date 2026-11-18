# Anti-Logging Bear by Priest

from __future__ import annotations

import json
import sys
from pathlib import Path

from samples import make_pe, make_zip

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))

import barry_web  # noqa: E402

WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/AbCdEf-GhIjKlMnOpQrStUv"


def test_web_report_for_keylogger(tmp_path):
    pe = make_pe(
        {"user32.dll": ["SetWindowsHookExW"], "wininet.dll": ["InternetOpenUrlA"]},
        extra=b"[BACKSPACE]\x00[ENTER]\x00" + WEBHOOK.encode() + b"\x00",
    )
    target = tmp_path / "gta-fps-boost.zip"
    target.write_bytes(make_zip([("fpsboost.asi", pe), ("readme.txt", b"Copy to your game folder.")]))

    seen: list[str] = []
    report = json.loads(barry_web.scan(str(target), progress=seen.append))

    assert report["verdict"] == "dangerous"
    assert report["target"] == "gta-fps-boost.zip"
    assert report["reasons"][0]["severity"] == "critical"
    assert any(WEBHOOK in ioc for ioc in report["indicators"])
    assert "fpsboost.asi" in seen
    assert report["html"].startswith("<!doctype html>")
    assert str(tmp_path) not in report["html"]
    assert report["engines"]["YARA rules"] == barry_web.UNAVAILABLE


def test_web_strict_mode(tmp_path):
    target = tmp_path / "run.zip"
    target.write_bytes(make_zip([("run.ps1", b"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File x.ps1\n")]))
    assert json.loads(barry_web.scan(str(target)))["verdict"] == "clean"
    assert json.loads(barry_web.scan(str(target), strict=True))["verdict"] == "suspicious"
