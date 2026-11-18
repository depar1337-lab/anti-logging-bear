# Anti-Logging Bear by Priest

from __future__ import annotations

import io
import logging
import re
import warnings
import zipfile

from .findings import Finding, Severity

logging.getLogger("olevba").setLevel(logging.CRITICAL)

_EXTERNAL_REL = re.compile(
    rb'Type="[^"]*/(attachedTemplate|oleObject|frame|subDocument)"[^>]*Target="((?:https?|file|\\\\)[^"]+)"'
    rb'|Target="((?:https?|file|\\\\)[^"]+)"[^>]*Type="[^"]*/(attachedTemplate|oleObject|frame|subDocument)"',
    re.I,
)
_DDE = re.compile(rb"DDEAUTO|<w:fldSimple[^>]+DDE\b|\bDDE\s+\"?c:\\\\windows", re.I)
_RISKY_KEYWORDS = {
    "shell", "wscript.shell", "run", "createobject", "urldownloadtofile", "xmlhttp", "adodb.stream",
    "powershell", "cmd.exe", "callbyname", "shellexecute", "environ", "kill", "savetofile",
    "winhttprequest", "getobject", "virtualalloc", "rtlmovememory", "createthread", "lib",
}


def analyze_office(path: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    if data.startswith(b"PK"):
        findings.extend(_ooxml_checks(path, data))
    findings.extend(_macro_checks(path, data))
    return findings


def _ooxml_checks(path: str, data: bytes) -> list[Finding]:
    out: list[Finding] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return out
    with zf:
        for info in zf.infolist():
            name = info.filename.lower()
            if info.file_size > 8 * 1024 * 1024:
                continue
            if name.endswith(".rels"):
                content = zf.read(info)
                for m in _EXTERNAL_REL.finditer(content):
                    target = (m.group(2) or m.group(3) or b"").decode("latin-1")
                    out.append(Finding(path, "office.remote-template", Severity.HIGH,
                                       "Document loads content from the internet when opened",
                                       "A known trick for pulling in malicious macros or exploits.",
                                       [target]))
            elif name.endswith(".xml") and name.startswith(("word/", "xl/")):
                if _DDE.search(zf.read(info)):
                    out.append(Finding(path, "office.dde", Severity.HIGH,
                                       "Document can launch programs through DDE fields"))
            elif name.endswith((".bin", ".exe", ".dll", ".js", ".vbs", ".hta", ".lnk")) and "embeddings" in name:
                out.append(Finding(path, "office.embedded-object", Severity.MEDIUM,
                                   "Document has an embedded file ({})".format(info.filename.rsplit("/", 1)[-1])))
    return out


def _macro_checks(path: str, data: bytes) -> list[Finding]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from oletools.olevba import VBA_Parser
    except ImportError:
        return []
    try:
        parser = VBA_Parser(path.rsplit("/", 1)[-1] or "document", data=data)
    except Exception as exc:
        if b"EncryptedPackage" in data[:65536] or b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00" in data[:65536]:
            return [Finding(path, "office.encrypted", Severity.HIGH,
                            "Password-protected document - Barry can't see inside")]
        return [Finding(path, "office.unreadable", Severity.LOW,
                        "Barry couldn't fully read this document", str(exc)[:200])]

    out: list[Finding] = []
    try:
        if not parser.detect_vba_macros():
            if getattr(parser, "detect_xlm_macros", lambda: False)():
                out.append(Finding(path, "office.xlm", Severity.HIGH,
                                   "Spreadsheet contains old-style Excel 4.0 macros (a common malware trick)"))
            return out

        autoexec: list[str] = []
        risky: list[str] = []
        iocs: list[str] = []
        for kind, keyword, _desc in parser.analyze_macros():
            kw = keyword.lower()
            if kind == "AutoExec":
                autoexec.append(keyword)
            elif kind == "Suspicious" and (kw in _RISKY_KEYWORDS or "base64" in kw or "hex" in kw or "obfusc" in kw):
                risky.append(keyword)
            elif kind == "IOC":
                iocs.append(keyword)

        detail = "Auto-run: {}. Risky calls: {}.".format(
            ", ".join(autoexec[:5]) or "none", ", ".join(risky[:8]) or "none")
        if autoexec and risky:
            out.append(Finding(path, "office.malicious-macro", Severity.CRITICAL,
                               "Document runs macros automatically that can launch programs or download files",
                               detail, iocs[:10]))
        elif autoexec:
            out.append(Finding(path, "office.autoexec-macro", Severity.HIGH,
                               "Document runs macros automatically when opened", detail, iocs[:10]))
        elif risky:
            out.append(Finding(path, "office.risky-macro", Severity.HIGH,
                               "Document has macros that can launch programs or download files",
                               detail, iocs[:10]))
        else:
            out.append(Finding(path, "office.macro", Severity.MEDIUM,
                               "Document contains macros", detail, iocs[:10]))
    except Exception as exc:
        out.append(Finding(path, "office.macro-error", Severity.MEDIUM,
                           "Document has macros Barry couldn't fully decode", str(exc)[:200]))
    finally:
        parser.close()
    return out
