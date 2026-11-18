# Anti-Logging Bear by Priest

from __future__ import annotations

import re

MAX_STRING_SCAN = 32 * 1024 * 1024

_ASCII = re.compile(rb"[\x20-\x7e]{5,}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

URL = re.compile(r"https?://[\w.-]+(?::\d+)?(?:/[\w./%?=&+#~:@!$,;-]*)?", re.I)
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

DISCORD_WEBHOOK = re.compile(r"discord(?:app)?\.com/api/(?:v\d+/)?webhooks/\d+/[\w-]+", re.I)
TELEGRAM_BOT = re.compile(r"api\.telegram\.org/bot\d*:?[\w-]*", re.I)
PASTE_SITES = re.compile(
    r"\b(?:pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|rentry\.co|ngrok(?:-free)?\.(?:io|app)"
    r"|transfer\.sh|webhook\.site|requestbin|pipedream\.net|anonfiles|file\.io|gofile\.io"
    r"|discord\.com/api/v\d+/channels)",
    re.I,
)
SMTP = re.compile(r"\bsmtp\.(?:gmail|mail|yandex|office365|outlook|zoho)\.\w+|\bMAIL FROM:", re.I)
DISCORD_TOKEN = re.compile(r"dQw4w9WgXcQ:|[\w-]{24}\.[\w-]{6}\.[\w-]{27}")

BROWSER_SECRETS = re.compile(
    r"\\(?:Login Data|Web Data|Local State|Cookies)\b|logins\.json|key4\.db|cookies\.sqlite"
    r"|\\Local Storage\\leveldb|wallet\.dat|\\Exodus\\|\\Electrum\\|\\Telegram Desktop\\tdata",
    re.I,
)
KEYLOG_MARKERS = re.compile(
    r"\[(?:BACKSPACE|BACK|ENTER|RETURN|SHIFT|CAPSLOCK|CAPS LOCK|TAB|CTRL|ALT|DEL|ESC)\]"
    r"|\bkey ?logg(?:er|ing)\b|\bkeylog(?:s|\.txt|\.log)\b",
    re.I,
)
RUN_KEY = re.compile(r"\\CurrentVersion\\(?:Run|RunOnce|Policies\\Explorer\\Run)\b", re.I)
STARTUP_FOLDER = re.compile(r"\\Start Menu\\Programs\\Startup|shell:startup", re.I)
DEFENDER_TAMPER = re.compile(
    r"Add-MpPreference\s+-Exclusion|Set-MpPreference\s+-Disable|DisableAntiSpyware"
    r"|DisableRealtimeMonitoring|vssadmin(?:\.exe)?\s+delete\s+shadows|bcdedit.+recoveryenabled\s+no"
    r"|wevtutil(?:\.exe)?\s+cl\b",
    re.I,
)


def extract_strings(data: bytes, limit: int = MAX_STRING_SCAN) -> str:
    chunk = data[:limit]
    parts: list[str] = [m.group().decode("ascii") for m in _ASCII.finditer(chunk)]
    parts.extend(m.group().decode("utf-16-le", "ignore") for m in _WIDE.finditer(chunk))
    return "\n".join(parts)


def find_urls(text: str, limit: int = 25) -> list[str]:
    found: list[str] = []
    for m in URL.finditer(text):
        url = m.group().rstrip(".,;)'\"")
        if url not in found and not _is_boring_url(url):
            found.append(url)
            if len(found) >= limit:
                break
    return found


_BORING_HOSTS = (
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "www.w3.org",
    "ns.adobe.com",
    "purl.org",
    "crl.",
    "ocsp.",
    "www.digicert.com",
    "www.verisign.com",
    "www.symauth.com",
    "sectigo.com",
    "globalsign",
    "microsoft.com/pki",
)


def _is_boring_url(url: str) -> bool:
    lowered = url.lower()
    return any(host in lowered for host in _BORING_HOSTS)


def exfil_endpoints(text: str) -> list[str]:
    hits: list[str] = []
    for pattern in (DISCORD_WEBHOOK, TELEGRAM_BOT, PASTE_SITES, SMTP):
        for m in pattern.finditer(text):
            value = m.group()
            if value not in hits:
                hits.append(value)
    return hits[:10]
