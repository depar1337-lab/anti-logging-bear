# Anti-Logging Bear by Priest

from __future__ import annotations

import contextlib
import io
import re
from typing import Iterator

from .findings import Finding, Severity
from .scripts import analyze_script

_LOLBINS = re.compile(
    r"\b(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec"
    r"|conhost|forfiles|schtasks|curl|wmic|hh|msbuild|installutil)(?:\.exe)?\b",
    re.I,
)
_REMOTE = re.compile(r"https?://|\\\\[\w.-]+\\", re.I)


def analyze_lnk(path: str, data: bytes) -> list[Finding]:
    try:
        import LnkParse3
    except ImportError:
        return []
    try:
        with _quiet():
            info = LnkParse3.lnk_file(indata=data).get_json()
    except Exception as exc:
        return [Finding(path, "lnk.malformed", Severity.HIGH,
                        "Damaged shortcut file - Barry can't read where it points", str(exc)[:200])]

    strings = list(_walk_strings(info))
    blob = " ".join(strings)
    out: list[Finding] = []
    arguments = str((info.get("data") or {}).get("command_line_arguments") or "")

    tool = _LOLBINS.search(blob)
    if tool:
        severity = Severity.CRITICAL if _REMOTE.search(arguments) or len(arguments) > 200 else Severity.HIGH
        out.append(Finding(path, "lnk.lolbin", severity,
                           f"Shortcut secretly runs {tool.group(1).lower()} instead of opening a file",
                           "Arguments: " + _clip(arguments) if arguments else ""))
    elif arguments and _REMOTE.search(arguments):
        out.append(Finding(path, "lnk.remote-args", Severity.HIGH,
                           "Shortcut passes an internet address to a program", _clip(arguments)))

    if len(data) > 64 * 1024:
        out.append(Finding(path, "lnk.oversized", Severity.HIGH,
                           "Shortcut is far bigger than normal - it may carry a hidden payload",
                           f"{len(data) // 1024} KB"))

    if arguments:
        out.extend(analyze_script(path + " [arguments]", "script:powershell", arguments.encode("utf-8")))
    return out


def analyze_url_shortcut(path: str, data: bytes) -> list[Finding]:
    text = data.decode("utf-8", "replace")
    out: list[Finding] = []
    m = re.search(r"^\s*URL\s*=\s*(\S+)", text, re.I | re.M)
    target = m.group(1) if m else ""
    if target.lower().startswith(("file:", "\\\\", "smb:", "search-ms:", "ms-msdt:")):
        out.append(Finding(path, "url.local-target", Severity.HIGH,
                           "Internet shortcut opens a file or network share instead of a website", target))
    elif re.search(r"\.(?:exe|scr|hta|bat|cmd|ps1|vbs|js|msi)(?:\?|$)", target, re.I):
        out.append(Finding(path, "url.exe-target", Severity.HIGH,
                           "Internet shortcut downloads a program", target))
    icon = re.search(r"^\s*IconFile\s*=\s*(\\\\\S+)", text, re.I | re.M)
    if icon:
        out.append(Finding(path, "url.unc-icon", Severity.MEDIUM,
                           "Shortcut loads its icon from a network share (can leak your Windows login)",
                           icon.group(1)))
    return out


def _walk_strings(node) -> Iterator[str]:
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_strings(value)
    elif isinstance(node, str):
        yield node


@contextlib.contextmanager
def _quiet():
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        yield


def _clip(value: str, limit: int = 300) -> str:
    return value if len(value) <= limit else value[:limit] + "..."
