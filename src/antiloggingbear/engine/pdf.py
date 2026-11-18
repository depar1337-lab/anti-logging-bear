# Anti-Logging Bear by Priest

from __future__ import annotations

import re
import zlib

from .findings import Finding, Severity

_NAME = re.compile(rb"/[A-Za-z0-9#]+")
_HEX = re.compile(rb"#([0-9A-Fa-f]{2})")
_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
_WATCHED = (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile",
            b"/XFA", b"/SubmitForm", b"/GoToR", b"/RichMedia")
_MAX_STREAMS = 400
_MAX_INFLATED = 64 * 1024 * 1024


def _names(blob: bytes) -> dict[bytes, int]:
    counts: dict[bytes, int] = {}
    for m in _NAME.finditer(blob):
        name = m.group()
        if b"#" in name:
            name = _HEX.sub(lambda h: bytes([int(h.group(1), 16)]), name)
        if name in _WATCHED:
            counts[name] = counts.get(name, 0) + 1
    return counts


def analyze_pdf(path: str, data: bytes) -> list[Finding]:
    counts = _names(data)
    inflated = 0
    for i, m in enumerate(_STREAM.finditer(data)):
        if i >= _MAX_STREAMS or inflated > _MAX_INFLATED:
            break
        try:
            chunk = zlib.decompressobj().decompress(m.group(1), _MAX_INFLATED - inflated)
        except zlib.error:
            continue
        inflated += len(chunk)
        for name, n in _names(chunk).items():
            counts[name] = counts.get(name, 0) + n

    has_js = bool(counts.get(b"/JavaScript") or counts.get(b"/JS"))
    auto = bool(counts.get(b"/OpenAction") or counts.get(b"/AA"))
    out: list[Finding] = []
    if counts.get(b"/Launch"):
        out.append(Finding(path, "pdf.launch", Severity.CRITICAL,
                           "PDF tries to launch a program on your computer"))
    if has_js and auto:
        out.append(Finding(path, "pdf.autorun-js", Severity.HIGH,
                           "PDF runs JavaScript automatically when opened"))
    elif has_js:
        out.append(Finding(path, "pdf.js", Severity.MEDIUM, "PDF contains JavaScript"))
    if counts.get(b"/EmbeddedFile"):
        out.append(Finding(path, "pdf.embedded", Severity.MEDIUM, "PDF has files hidden inside it"))
    if counts.get(b"/XFA") and has_js:
        out.append(Finding(path, "pdf.xfa", Severity.MEDIUM, "PDF uses scripted XFA forms"))
    if counts.get(b"/SubmitForm") and auto:
        out.append(Finding(path, "pdf.submit", Severity.MEDIUM,
                           "PDF can send form data to a website automatically"))
    if counts.get(b"/RichMedia"):
        out.append(Finding(path, "pdf.richmedia", Severity.LOW, "PDF embeds Flash or rich media"))
    return out
