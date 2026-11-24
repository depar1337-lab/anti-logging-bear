# Anti-Logging Bear by Priest

from __future__ import annotations

import io
import json
import os
import zipfile
from typing import Callable

from antiloggingbear import __version__
from antiloggingbear.engine.archive import MB, Limits
from antiloggingbear.engine.findings import FileRecord, Finding, Severity
from antiloggingbear.engine.scanner import ScanOptions, scan_data, scan_path
from antiloggingbear.report import plain_reasons, to_html

UNAVAILABLE = "not available in the web version"


def _options(strict: bool, max_unpacked_mb: int) -> ScanOptions:
    return ScanOptions(limits=Limits(max_total_bytes=max_unpacked_mb * MB), strict=strict, use_yara=False,
                       use_antivirus=False)


def scan(path: str, strict: bool = False, max_unpacked_mb: int = 512,
         progress: Callable[[str], None] | None = None) -> str:
    report = scan_path(path, _options(strict, max_unpacked_mb), progress)
    report.target = os.path.basename(path)
    return _payload(report)


def scan_members(name: str, manifest: str, encrypted: bool = False, sha256: str = "", size: int = 0,
                 strict: bool = False, max_unpacked_mb: int = 512,
                 progress: Callable[[str], None] | None = None) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as bundle:
        for inner, stored in json.loads(manifest):
            with open(stored, "rb") as fh:
                bundle.writestr(inner, fh.read())
    report = scan_data(name, buffer.getvalue(), _options(strict, max_unpacked_mb), progress)
    if report.files:
        report.files[0] = FileRecord(name, size, sha256, os.path.splitext(name)[1].lstrip(".").lower() or "archive")
    if encrypted:
        report.add(Finding(name, "archive.encrypted", Severity.HIGH,
                           "Password-protected archive - Barry can't see inside",
                           "Malware is often shipped in passworded archives to dodge scanners."))
    return _payload(report)


def _payload(report) -> str:
    report.engines = {"Barry's checks": "on", "YARA rules": UNAVAILABLE, "Antivirus": UNAVAILABLE}

    payload = report.to_dict()
    payload["version"] = __version__
    payload["headline"] = report.verdict.headline
    payload["reasons"] = [{"severity": sev.name.lower(), "text": text} for sev, text in plain_reasons(report)]
    payload["indicators"] = report.indicators()
    payload["html"] = to_html(report)
    return json.dumps(payload)
