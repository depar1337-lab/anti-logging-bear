# Anti-Logging Bear by Priest

from __future__ import annotations

import math
import posixpath
import re
from collections import Counter

from .findings import Finding, Severity

EXECUTABLE_EXTS = {
    "exe", "scr", "com", "pif", "dll", "asi", "sys", "cpl", "ocx", "msi", "msp", "jar",
    "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "lnk",
    "url", "scf", "reg", "inf", "app", "command", "sh", "py", "pyw", "lua", "cs", "dmg", "pkg",
}
DOCUMENT_EXTS = {
    "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif",
    "bmp", "mp3", "mp4", "avi", "mkv", "wav", "rtf", "csv", "zip", "rar", "html", "htm",
}
SCRIPT_EXTS = {
    "bat": "batch", "cmd": "batch", "ps1": "powershell", "psm1": "powershell",
    "vbs": "vbscript", "vbe": "vbscript", "js": "jscript", "jse": "jscript",
    "wsf": "wsh", "wsh": "wsh", "hta": "hta", "py": "python", "pyw": "python",
    "lua": "lua", "luac": "lua", "sh": "shell", "command": "shell", "reg": "registry",
    "txt": "text", "ini": "text", "cfg": "text", "json": "text", "xml": "text",
}
OFFICE_EXTS = {
    "doc", "dot", "docm", "docx", "dotm", "xls", "xlsm", "xlsb", "xlsx", "xlt", "xltm",
    "ppt", "pptm", "pptx", "potm", "ppsm", "rtf",
}
WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩‎‏]")
_DOS_STUB = b"This program cannot be run in DOS mode"
_LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"


def extension(name: str) -> str:
    base = posixpath.basename(name.replace("\\", "/"))
    return base.rsplit(".", 1)[1].lower() if "." in base else ""


def sniff(name: str, data: bytes) -> str:
    head = data[:64]
    ext = extension(name)
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        if ext in OFFICE_EXTS or b"[Content_Types].xml" in data[:4096]:
            return "office"
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "msi" if ext in {"msi", "msp"} else "office"
    if head.startswith(b"%PDF") or b"%PDF-" in data[:1024]:
        return "pdf"
    if head.startswith(_LNK_HEADER):
        return "lnk"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"{\\rtf"):
        return "office"
    if head.startswith(b"\xca\xfe\xba\xbe") or head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"\x1bLua"):
        return "script:lua-bytecode"
    if ext in ("url", "scf"):
        return "shortcut"
    if ext == "lnk":
        return "lnk"
    if ext in SCRIPT_EXTS:
        return "script:" + SCRIPT_EXTS[ext]
    if ext == "cs" and _looks_like_text(data):
        return "script:csharp" if b"using System" in data[:4096] or b"namespace " in data else "cleo"
    if ext in ("cs", "cm", "cleo"):
        return "cleo"
    if head.startswith(b"#!"):
        return "script:shell"
    if _looks_like_text(data):
        return "text"
    return "data"


def _looks_like_text(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return True
    if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
        return True
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) + sum(
        1 for b in sample if b >= 0x80
    ) // 2
    return printable / len(sample) > 0.85 and b"\x00" not in sample[:512]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def check_name(path: str) -> list[Finding]:
    out: list[Finding] = []
    norm = path.replace("\\", "/")
    base = posixpath.basename(norm)

    if BIDI_CONTROLS.search(path):
        out.append(Finding(path, "name.bidi", Severity.CRITICAL,
                           "File name uses hidden characters to fake its file type",
                           "Right-to-left override characters can make 'gpj.exe' display as 'exe.jpg'."))

    parts = base.split(".")
    if len(parts) >= 3:
        inner, outer = parts[-2].lower(), parts[-1].lower()
        if inner in DOCUMENT_EXTS and outer in EXECUTABLE_EXTS:
            out.append(Finding(path, "name.double-ext", Severity.HIGH,
                               f"Program disguised as a .{inner} file",
                               f"The real file type is .{outer}."))

    if re.search(r"\s{6,}\.\w+$", base):
        out.append(Finding(path, "name.padding", Severity.HIGH,
                           "File name is padded with spaces to hide its real extension"))

    stem = base.split(".")[0].lower()
    if stem in WINDOWS_RESERVED:
        out.append(Finding(path, "name.reserved", Severity.MEDIUM,
                           f"Uses a reserved Windows device name ({stem.upper()})"))

    if ":" in norm.split("/")[-1] and not re.match(r"^[A-Za-z]:", norm):
        out.append(Finding(path, "name.ads", Severity.HIGH,
                           "Tries to write into a hidden alternate data stream"))
    return out


def check_content(path: str, kind: str, data: bytes) -> list[Finding]:
    out: list[Finding] = []
    ext = extension(path)

    if kind == "pe" and ext and ext not in EXECUTABLE_EXTS and ext not in {"bin", "dat", "tmp", "mui", "node", "pyd", "drv", "efi", "ax", "acm", "tlb"}:
        out.append(Finding(path, "content.disguised-exe", Severity.HIGH,
                           f"Windows program hidden behind a .{ext} extension",
                           "The file starts with an executable header even though its name says otherwise."))

    if kind not in ("pe", "zip", "office", "msi", "rar", "7z", "gzip"):
        offset = data.find(_DOS_STUB, 64)
        if offset > 0:
            out.append(Finding(path, "content.embedded-exe", Severity.HIGH,
                               "Contains a hidden Windows program inside another file",
                               f"Executable code found at offset {max(offset - 78, 0)}."))

    if kind in ("macho", "elf"):
        out.append(Finding(path, "content.native-binary", Severity.INFO,
                           "Contains a {} program".format("macOS" if kind == "macho" else "Linux")))

    if kind == "msi":
        out.append(Finding(path, "content.installer", Severity.LOW,
                           "Windows installer package (runs setup actions when opened)"))
    return out
