# Anti-Logging Bear by Priest

from __future__ import annotations

import json
import os
from typing import Callable

from antiloggingbear import __version__
from antiloggingbear.engine.archive import MB, Limits
from antiloggingbear.engine.scanner import ScanOptions, scan_path
from antiloggingbear.report import plain_reasons, to_html

UNAVAILABLE = "not available in the web version"


def scan(path: str, strict: bool = False, max_unpacked_mb: int = 512,
         progress: Callable[[str], None] | None = None) -> str:
    options = ScanOptions(
        limits=Limits(max_total_bytes=max_unpacked_mb * MB),
        strict=strict,
        use_yara=False,
        use_antivirus=False,
    )
    report = scan_path(path, options, progress)
    report.target = os.path.basename(path)
    report.engines = {"Barry's checks": "on", "YARA rules": UNAVAILABLE, "Antivirus": UNAVAILABLE}

    payload = report.to_dict()
    payload["version"] = __version__
    payload["headline"] = report.verdict.headline
    payload["reasons"] = [{"severity": sev.name.lower(), "text": text} for sev, text in plain_reasons(report)]
    payload["indicators"] = report.indicators()
    payload["html"] = to_html(report)
    return json.dumps(payload)
