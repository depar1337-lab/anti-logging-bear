# Anti-Logging Bear by Priest

from __future__ import annotations

import base64
import binascii
import re
import zlib
from typing import Pattern

from . import capabilities as cap
from . import indicators as ioc
from .findings import Finding, Severity

MAX_SCRIPT_BYTES = 8 * 1024 * 1024
FLAGS = re.I | re.M


_LOWERED: dict = {}


def _rx(pattern: str) -> Pattern[str]:
    compiled = re.compile(pattern, FLAGS)
    _LOWERED[compiled] = re.compile(_lower_pattern(pattern), re.M)
    return compiled


def _lower_pattern(pattern: str) -> str:
    out, index = [], 0
    while index < len(pattern):
        if pattern[index] == "\\" and index + 1 < len(pattern):
            out.append(pattern[index:index + 2])
            index += 2
            continue
        out.append(pattern[index].lower())
        index += 1
    return "".join(out)


class _Hit:
    def __init__(self, text: str) -> None:
        self._text = text

    def group(self) -> str:
        return self._text


def _search(pattern: Pattern[str], text: str, lowered: str | None):
    fast = _LOWERED.get(pattern)
    if fast is None or lowered is None:
        return pattern.search(text)
    match = fast.search(lowered)
    return _Hit(text[match.start():match.end()]) if match else None


CAPABILITY_RULES: list[tuple[str, Pattern[str], str]] = [
    (cap.KEYS, _rx(r"GetAsyncKeyState|SetWindowsHookEx|WH_KEYBOARD_LL|RegisterRawInputDevices|GetRawInputData"),
     "keyboard API"),
    (cap.KEYS, _rx(r"\bfrom\s+pynput(?:\.keyboard)?\s+import|\bpynput\.keyboard|\bimport\s+keyboard\b"
                   r"|\bkeyboard\.(?:on_press|on_release|hook|read_key|record)\b|\bpyx?hook\b"),
     "Python keyboard listener"),
    (cap.KEYS, _rx(r"\b(?:u?iohook|node-global-key-listener)\b"), "Node keyboard hook"),
    (cap.KEYS, _rx(r"onWindowMessage[\s\S]{0,400}?(?:0x0?10[02]\b|WM_KEYDOWN|WM_CHAR|VK_)"),
     "captures every key typed into the game window"),

    (cap.NETWORK, _rx(r"Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Net\.WebClient|System\.Net\.Http"
                      r"|Net\.Sockets|\bHttpClient\b|\bWebClient\b|\bSmtpClient\b|\bTcpClient\b|UnityWebRequest"),
     "network (PowerShell/.NET)"),
    (cap.NETWORK, _rx(r"\brequests\.(?:get|post|put|request)\b|urllib\.request|http\.client|socket\.socket"
                      r"|\bsmtplib\b|\baiohttp\b|\bhttpx\b|discord_webhook"),
     "network (Python)"),
    (cap.NETWORK, _rx(r"socket\.http|require\s*\(?\s*['\"](?:socket|requests|ssl\.https|copas|lua-requests)"
                      r"|downloadUrlToFile|asyncHttpRequest|\beffil\b"),
     "network (Lua)"),
    (cap.NETWORK, _rx(r"MSXML2\.(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest|XMLHttpRequest|\bfetch\s*\("),
     "network (script host)"),
    (cap.NETWORK, _rx(r"\bcurl(?:\.exe)?\s+-|\bwget\s+|bitsadmin|certutil(?:\.exe)?\s.*-urlcache"),
     "network (command line)"),

    (cap.LOG_FILE, _rx(r"\bopen\([^)\n]*,\s*['\"]a|io\.open\([^)\n]*,\s*['\"]a|Add-Content|Out-File[^\n]*-Append"
                       r"|OpenTextFile\([^)\n]*,\s*8|AppendAllText"),
     "appends to a file"),

    (cap.CREDENTIALS, _rx(r"CryptUnprotectData|win32crypt|ProtectedData\]::Unprotect|\bbrowser_cookie3\b"),
     "decrypts saved browser data"),
    (cap.CREDENTIALS, _rx(r"discord_desktop_core[\s\S]{0,400}?\b(?:writeFileSync|writeFile|appendFileSync|createWriteStream)\b"
                          r"|\b(?:writeFileSync|writeFile|appendFileSync)\b[\s\S]{0,400}?discord_desktop_core"
                          r"|\b(?:win-dpapi|@primno/dpapi|node-dpapi)\b"),
     "tampers with the Discord app or decrypts saved passwords"),
    (cap.DIALOG_INPUT, _rx(r"sampGetCurrentDialogEditboxText|onSendDialogResponse"),
     "reads SA-MP dialog input (where passwords are typed)"),

    (cap.CLIPBOARD, _rx(r"Get-Clipboard|Clipboard\]::GetText|pyperclip\.paste|GetClipboardData"
                        r"|clipboard\.(?:get|read)|getClipboardText"),
     "reads the clipboard"),
    (cap.SCREENSHOT, _rx(r"ImageGrab\.grab|pyautogui\.screenshot|\bmss\s*\(|CopyFromScreen|takeScreenshot"),
     "takes screenshots"),
    (cap.INJECTION, _rx(r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC"),
     "process memory API"),
    (cap.HOLLOWING, _rx(r"[NZ][tw]UnmapViewOfSection"), "unmaps another program's code"),

    (cap.PERSISTENCE, _rx(r"schtasks(?:\.exe)?\s+/create|Register-ScheduledTask|New-ScheduledTaskTrigger"
                          r"|\bcrontab\s|LaunchAgents|New-Service\b|\bsc(?:\.exe)?\s+create\b"),
     "scheduled task / service"),
    (cap.DEFENDER_TAMPER, _rx(r"netsh\s+(?:adv)?firewall\s+set\s[^\n]*state\s+off"
                              r"|taskkill[^\n]*/im\s+(?:MsMpEng|avp|avgui|bdagent|ekrn|mbam)"),
     "disables firewall or kills antivirus"),

    (cap.DOWNLOAD_EXEC, _rx(r"(?:DownloadString|DownloadData|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b)"
                            r"[^\n]{0,200}\|\s*(?:iex|Invoke-Expression)\b"),
     "downloads and runs PowerShell"),
    (cap.DOWNLOAD_EXEC, _rx(r"(?:\biex\b|Invoke-Expression)\s*\(*\s*(?:\(\s*)?(?:New-Object\s+(?:System\.)?Net\.WebClient"
                            r"|\biwr\b|\birm\b|Invoke-WebRequest|Invoke-RestMethod)"),
     "runs code straight from the internet"),
    (cap.DOWNLOAD_EXEC, _rx(r"DownloadFile\([^)\n]*\)[\s\S]{0,300}?(?:Start-Process|\bsaps\b|Invoke-Item|\bstart\b)"),
     "downloads a file and starts it"),
    (cap.DOWNLOAD_EXEC, _rx(r"certutil(?:\.exe)?\s[^\n]*-urlcache[^\n]*-f|bitsadmin(?:\.exe)?\s+/transfer"
                            r"|mshta(?:\.exe)?\s+[\"']?(?:https?|vbscript|javascript):"
                            r"|regsvr32(?:\.exe)?\s[^\n]*/i:https?|rundll32(?:\.exe)?\s[^\n]*javascript:"),
     "abuses a Windows tool to download code"),
    (cap.DOWNLOAD_EXEC, _rx(r"\b(?:curl|wget)(?:\.exe)?\s[^\n]{0,200}?\s(?:-o|-O|--output)\s+\S+[^\n]{0,200}?"
                            r"(?:&&|;|\n)\s*(?:start\b|call\b|\.\\|\./|chmod\s+\+x|open\s)"),
     "downloads a file and starts it"),
    (cap.DOWNLOAD_EXEC, _rx(r"urlretrieve\([^)]*\)[\s\S]{0,300}?(?:os\.startfile|subprocess|os\.system|os\.popen)"),
     "downloads a file and starts it (Python)"),
    (cap.DOWNLOAD_EXEC, _rx(r"(?:XMLHTTP|WinHttpRequest)[\s\S]{0,1500}?ADODB\.Stream[\s\S]{0,1500}?(?:\.Run\b|ShellExecute|\.Exec\b)"),
     "downloads a file and starts it (script host)"),
    (cap.DOWNLOAD_EXEC, _rx(r"downloadUrlToFile[\s\S]{0,400}?(?:os\.execute|io\.popen|ShellExecute|WinExec)"),
     "downloads a file and starts it (Lua)"),
]

WSH_LANGS = {"jscript", "vbscript", "wsh", "hta"}
WSH_MARKERS = _rx(r"ActiveXObject|CreateObject\s*\(|WScript\.|GetObject\s*\(")
WEB_JS_MARKERS = _rx(r"\brequire\s*\(|module\.exports|\bexports\.|\bwindow\.|\bdocument\.|__webpack|\bself\.")
WSH_RULES: list[tuple[str, Severity, Pattern[str], str]] = [
    ("dropper.wsh-powershell", Severity.HIGH,
     _rx(r"(?:WScript\.Shell|Shell\.Application|ShellExecute)[\s\S]{0,3000}?powershell"
         r"|powershell[\s\S]{0,3000}?(?:WScript\.Shell|Shell\.Application|ShellExecute)"),
     "Windows script that quietly starts PowerShell - a common first step for malware"),
    ("dropper.write-and-run", Severity.HIGH,
     _rx(r"ADODB\.Stream[\s\S]{0,4000}?SaveToFile[\s\S]{0,4000}?(?:\.Run\b|\.Exec\b|ShellExecute)"),
     "Writes a file to disk and runs it"),
]
DIRECT_RULES: list[tuple[str, Severity, Pattern[str], str]] = [
    ("dropper.memory-loader", Severity.CRITICAL,
     _rx(r"(?:DownloadData|DownloadString|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b|Net\.WebClient|HttpClient)"
         r"[\s\S]{0,3000}?(?:Reflection\.Assembly\]?::Load|Assembly\]::Load|\.Load\s*\(\s*\[?Convert)"
         r"|(?:Reflection\.Assembly\]?::Load|Assembly\]::Load)[\s\S]{0,3000}?"
         r"(?:DownloadData|DownloadString|Invoke-WebRequest|\biwr\b|Net\.WebClient)"),
     "Downloads a program and runs it straight from memory (a fileless loader)"),
    ("obfuscation.ps-encoded", Severity.HIGH,
     _rx(r"-e(?:nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{40,}"),
     "Runs a hidden, encoded PowerShell command"),
    ("obfuscation.base64", Severity.MEDIUM,
     _rx(r"FromBase64String|b64decode|atob\s*\(|base64\.decode|DecodeBase64"),
     "Decodes hidden Base64 data at run time"),
    ("obfuscation.charcodes", Severity.MEDIUM,
     _rx(r"(?:\[char\]\s*\d+\s*[+,)]\s*){15,}|String\.fromCharCode\((?:\s*\d+\s*,){20,}|(?:Chr[WB]?\(\s*\d+\s*\)\s*[&+]\s*){15,}"),
     "Builds its code out of character numbers to hide what it does"),
    ("obfuscation.exec", Severity.HIGH,
     _rx(r"\bexec\s*\(\s*(?:base64|zlib|marshal|codecs|bytes\.fromhex|__import__|bz2|lzma)"
         r"|\beval\s*\(\s*(?:atob|unescape|String\.fromCharCode|base64)"
         r"|Execute(?:Global)?\s*\(?\s*(?:Chr|StrReverse|Replace)\b"
         r"|\bload(?:string)?\s*\(\s*(?:['\"](?:\\\d{1,3}){20,}|base64|dec\s*\()"),
     "Decodes hidden code and runs it"),
    ("obfuscation.batch", Severity.HIGH,
     _rx(r"(?:%[^%\s]{1,20}:~-?\d+,-?\d+%){20,}"),
     "Batch file is scrambled to hide its commands"),
    ("obfuscation.lua-escapes", Severity.MEDIUM,
     _rx(r"(?:\\\d{2,3}){60,}"),
     "Contains a long block of escaped bytes (often hidden code)"),
    ("behaviour.hidden-window", Severity.MEDIUM,
     _rx(r"-w(?:indowstyle)?\s+h(?:idden)?\b|CreateNoWindow\s*=\s*\$?true|\.Run\s*\([^)\n]*,\s*0\s*[,)]"),
     "Runs commands in a hidden window"),
    ("behaviour.bypass", Severity.LOW,
     _rx(r"-ExecutionPolicy\s+Bypass|-ep\s+bypass|Set-ExecutionPolicy\s+Unrestricted"),
     "Turns off PowerShell's script safety check"),
    ("behaviour.self-delete", Severity.MEDIUM,
     _rx(r"del\s+(?:/[fq]\s+)*\"?%~f0|Remove-Item[^\n]*\$MyInvocation|os\.remove\(\s*(?:__file__|sys\.argv\[0\])"),
     "Deletes itself after running"),
    ("behaviour.hide-files", Severity.MEDIUM,
     _rx(r"attrib(?:\.exe)?\s+[^\n]*\+h[^\n]*\+s|attrib(?:\.exe)?\s+[^\n]*\+s[^\n]*\+h"),
     "Hides files as protected system files"),
    ("payload.embedded-exe", Severity.HIGH,
     _rx(r"TVqQAAMAAAAEAAAA|TVpQAAIAAAAEAA|4D5A90000300000004000000"),
     "Carries a hidden Windows program inside the script"),
]

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")
_ENCODED_COMMAND = re.compile(r"-e(?:nc|ncodedcommand|c)?\s+([A-Za-z0-9+/=]{40,})", re.I)


def decode_text(data: bytes) -> str:
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    if len(data) > 8 and data[1:8:2] == b"\x00\x00\x00\x00":
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def analyze_script(path: str, kind: str, data: bytes) -> list[Finding]:
    lang = kind.split(":", 1)[1] if ":" in kind else kind
    if lang == "lua-bytecode" or kind == "cleo":
        text = ioc.extract_strings(data)
        findings = [Finding(path, "script.compiled", Severity.MEDIUM,
                            "Compiled script - Barry can only read its text, not its logic",
                            "Compiled mods are common, but they also hide what the code does.")]
        findings.extend(_scan_text(path, text, lang, decoded_depth=1))
        return findings

    text = decode_text(data[:MAX_SCRIPT_BYTES])
    if lang == "text":
        return _scan_passive_text(path, text)
    return _scan_text(path, text, lang, decoded_depth=0)


def analyze_text(path: str, text: str, lang: str, extra: cap.Capabilities | None = None,
                 prefix: str = "script") -> list[Finding]:
    return _scan_text(path, text, lang, decoded_depth=1, extra=extra, prefix=prefix)


def _scan_text(path: str, text: str, lang: str, decoded_depth: int, extra: cap.Capabilities | None = None,
               prefix: str = "script") -> list[Finding]:
    caps = extra if extra is not None else cap.Capabilities()
    lowered = text.lower()
    if len(lowered) != len(text):
        lowered = None
    for name, pattern, label in CAPABILITY_RULES:
        m = _search(pattern, text, lowered)
        if m:
            caps.add(name, f"{label} ({_snippet(m.group())})")

    for endpoint in ioc.exfil_endpoints(text):
        caps.add(cap.EXFIL, endpoint)
    marker = ioc.keylog_marker(text)
    if marker:
        caps.add(cap.KEYLOG_MARKER, marker)
    m = ioc.BROWSER_SECRETS.search(text)
    if m:
        caps.add(cap.CREDENTIALS, f"browser data path ({_snippet(m.group())})")
    token = ioc.discord_token(text)
    if token:
        caps.add(cap.CREDENTIALS, f"Discord token pattern ({_snippet(token)})")
    for pattern in (ioc.RUN_KEY, ioc.STARTUP_FOLDER):
        m = pattern.search(text)
        if m:
            caps.add(cap.PERSISTENCE, m.group())
    m = ioc.DEFENDER_TAMPER.search(text)
    if m:
        caps.add(cap.DEFENDER_TAMPER, _snippet(m.group()))

    findings = cap.assess(path, caps, prefix)
    for check, severity, pattern, title in DIRECT_RULES:
        m = _search(pattern, text, lowered)
        if m:
            findings.append(Finding(path, "script." + check, severity, title,
                                    "Matched: " + _snippet(m.group())))

    if lang in WSH_LANGS or (lang == "jscript" and WSH_MARKERS.search(text[:2_000_000])):
        for check, severity, pattern, title in WSH_RULES:
            m = _search(pattern, text, lowered)
            if m:
                findings.append(Finding(path, "script." + check, severity, title,
                                        "Matched: " + _snippet(m.group())))
    findings.extend(_layout(path, text, lang))

    if decoded_depth == 0:
        findings.extend(_scan_decoded(path, text, lang))

    urls = ioc.find_urls(text)
    if urls and findings:
        findings[0].indicators.extend(u for u in urls if u not in findings[0].indicators)
    return findings


def _layout(path: str, text: str, lang: str) -> list[Finding]:
    if lang not in WSH_LANGS | {"batch", "powershell"}:
        return []
    longest = max((len(line) for line in text.splitlines()), default=0)
    if longest < 50_000:
        return []
    windows_script = lang in WSH_LANGS and (lang != "jscript" or bool(WSH_MARKERS.search(text[:2_000_000])))
    if lang == "jscript" and not windows_script:
        if longest < 500_000 or WEB_JS_MARKERS.search(text[:2_000_000]):
            return []
        return [Finding(path, "script.obfuscation.giant-line", Severity.MEDIUM,
                        "Script is one huge line of code (generated or scrambled)",
                        f"Its longest line is {longest:,} characters. Scripts written by people never look like this.")]
    if windows_script:
        severity = Severity.CRITICAL if longest >= 200_000 else Severity.HIGH
        return [Finding(path, "script.obfuscation.giant-line", severity,
                        "Huge scrambled Windows script - the way malware droppers hide their code",
                        f"Its longest line is {longest:,} characters, and it can control Windows through ActiveX.")]
    return [Finding(path, "script.obfuscation.giant-line", Severity.HIGH,
                    "Hides a huge encoded block on a single line",
                    f"Its longest line is {longest:,} characters - usually a program hidden inside the script.")]


def _scan_decoded(path: str, text: str, lang: str) -> list[Finding]:
    out: list[Finding] = []
    blobs = [m.group(1) for m in _ENCODED_COMMAND.finditer(text)]
    blobs.extend(m.group() for m in _BASE64_BLOB.finditer(text))
    for blob in blobs[:6]:
        raw = _b64(blob)
        if not raw:
            continue
        raw = _inflate(raw)
        if raw.startswith(b"MZ"):
            out.append(Finding(path, "script.payload.embedded-exe", Severity.HIGH,
                               "Carries a hidden Windows program inside the script"))
            continue
        decoded = _printable(raw)
        if decoded is None:
            continue
        inner = _scan_text(path + " [decoded]", decoded, lang, decoded_depth=1)
        if inner:
            out.append(Finding(path, "script.obfuscation.hidden-code", Severity.HIGH,
                               "Hides suspicious code inside an encoded block"))
            out.extend(inner)
    return out


def _scan_passive_text(path: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    hooks = [e for e in ioc.exfil_endpoints(text) if "webhooks" in e.lower() or "telegram" in e.lower()]
    if hooks:
        out.append(Finding(path, "text.webhook", Severity.MEDIUM,
                           "Settings file contains a webhook or bot address",
                           "Programs in this download may send data here.", hooks))
    if re.search(r"TVqQAAMAAAAEAAAA", text):
        out.append(Finding(path, "text.embedded-exe", Severity.HIGH,
                           "Text file carries an encoded Windows program"))
    return out


def _inflate(raw: bytes) -> bytes:
    if raw[:2] == b"\x1f\x8b":
        try:
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw, MAX_SCRIPT_BYTES)
        except zlib.error:
            return raw
    if raw[:1] in (b"\x78",) and raw[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda"):
        try:
            return zlib.decompressobj().decompress(raw, MAX_SCRIPT_BYTES)
        except zlib.error:
            return raw
    return raw


def _b64(blob: str) -> bytes:
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (binascii.Error, ValueError):
        return b""


def _printable(raw: bytes):
    for codec in ("utf-16-le", "utf-8"):
        if codec == "utf-16-le" and (len(raw) < 4 or raw[1:4:2] != b"\x00\x00"):
            continue
        try:
            text = raw.decode(codec)
        except UnicodeDecodeError:
            continue
        sample = text[:2000]
        if sample and sum(ch.isprintable() or ch in "\r\n\t" for ch in sample) / len(sample) > 0.9:
            return text
    return None


def _snippet(value: str, limit: int = 80) -> str:
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."
