# Anti-Logging Bear by Priest

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Callable

from . import antivirus, generic
from .archive import MB, ArchiveWalker, Entry, Limits, StopScan
from .findings import FileRecord, Finding, ScanReport, Severity
from .office import analyze_office
from .pdf import analyze_pdf
from .pe import analyze_pe
from .reputation import VirusTotal
from .scripts import analyze_script
from .shortcuts import analyze_lnk, analyze_url_shortcut
from .yara_rules import shared_engine

Progress = Callable[[str], None]


@dataclass
class ScanOptions:
    limits: Limits = field(default_factory=Limits)
    max_file_bytes: int = 2048 * MB
    strict: bool = False
    use_yara: bool = True
    custom_rules_dir: str = ""
    use_antivirus: bool = True
    vt_api_key: str = ""
    vt_max_lookups: int = 4


class ScanCancelled(Exception):
    pass


def scan_path(path: str, options: ScanOptions | None = None,
              progress: Progress | None = None,
              cancelled: Callable[[], bool] = lambda: False) -> ScanReport:
    return Scanner(options or ScanOptions(), progress, cancelled).run(path)


class Scanner:
    def __init__(self, options: ScanOptions, progress: Progress | None,
                 cancelled: Callable[[], bool]) -> None:
        self.options = options
        self._progress = progress or (lambda _msg: None)
        self._cancelled = cancelled
        self._yara = None
        self._risk: dict[str, Severity] = {}

    def run(self, path: str) -> ScanReport:
        started = time.monotonic()
        report = ScanReport(target=os.path.abspath(path), strict=self.options.strict)
        name = os.path.basename(path)

        if self.options.use_yara:
            self._yara = shared_engine(self.options.custom_rules_dir)
            report.engines["YARA"] = self._yara.status
        else:
            report.engines["YARA"] = "off"

        size = os.path.getsize(path)
        report.extend(generic.check_name(name))
        if size > self.options.max_file_bytes:
            report.add(Finding(name, "file.too-large", Severity.MEDIUM,
                               f"File is larger than the scan limit ({size / MB:.0f} MB)"))
        else:
            with open(path, "rb") as fh:
                head = fh.read(8)
            if head.startswith(b"PK") and generic.extension(name) not in generic.OFFICE_EXTS:
                self._scan_archive(path, name, report)
            else:
                with open(path, "rb") as fh:
                    data = fh.read()
                self._scan_entry(Entry(path=name, data=data, depth=0), report, inspect_names=False)

        self._check_cancel()
        self._run_antivirus(path, report)
        self._run_reputation(path, report)
        report.duration = time.monotonic() - started
        return report

    def _scan_archive(self, path: str, name: str, report: ScanReport) -> None:
        walker = ArchiveWalker(self.options.limits)
        top = FileRecord(name, os.path.getsize(path), _sha256_file(path), "zip")
        report.files.append(top)
        try:
            self._walk(walker, path, "", 0, report)
        except StopScan:
            pass
        finally:
            report.extend(walker.findings)

    def _walk(self, walker: ArchiveWalker, source, prefix: str, depth: int, report: ScanReport) -> None:
        for entry in walker.walk(source, prefix, depth):
            self._check_cancel()
            kind = self._scan_entry(entry, report)
            if kind == "zip":
                if depth + 1 > self.options.limits.max_depth:
                    report.add(Finding(entry.path, "archive.deep", Severity.HIGH,
                                       "Archives nested too deep - Barry stopped looking",
                                       "Deeply nested zips are used to tire out scanners."))
                    continue
                self._walk(walker, entry.data, entry.path + "/", depth + 1, report)

    def _scan_entry(self, entry: Entry, report: ScanReport, inspect_names: bool = True) -> str:
        data = entry.data
        kind = generic.sniff(entry.path, data)
        sha = hashlib.sha256(data).hexdigest()
        report.files.append(FileRecord(entry.path, len(data), sha, kind))
        self._progress(entry.path)

        findings: list[Finding] = []
        if inspect_names:
            findings.extend(generic.check_name(entry.path))
        findings.extend(generic.check_content(entry.path, kind, data))
        findings.extend(self._analyze(entry.path, kind, data))
        if kind in ("rar", "7z", "gzip"):
            findings.append(Finding(entry.path, "archive.unsupported", Severity.HIGH,
                                    f"Contains a {kind.upper()} archive Barry can't open - check it separately"))
        if self._yara is not None and kind != "zip":
            findings.extend(self._yara.match(entry.path, data))

        report.extend(findings)
        worst = max((f.severity for f in findings), default=Severity.INFO)
        if generic.extension(entry.path) in generic.EXECUTABLE_EXTS or kind in ("pe", "office", "pdf"):
            worst = max(worst, Severity.LOW)
        self._risk[sha] = max(self._risk.get(sha, Severity.INFO), worst)
        return kind

    def _analyze(self, path: str, kind: str, data: bytes) -> list[Finding]:
        if kind == "pe":
            return analyze_pe(path, data)
        if kind.startswith("script:") or kind == "cleo":
            return analyze_script(path, kind, data)
        if kind == "office":
            return analyze_office(path, data)
        if kind == "pdf":
            return analyze_pdf(path, data)
        if kind == "lnk":
            return analyze_lnk(path, data)
        if kind == "shortcut":
            return analyze_url_shortcut(path, data)
        if kind == "text":
            return analyze_script(path, "script:text", data)
        return []

    def _run_antivirus(self, path: str, report: ScanReport) -> None:
        if not self.options.use_antivirus:
            report.engines["Antivirus"] = "off"
            return
        self._progress("Asking your antivirus for a second opinion...")
        status, findings = antivirus.scan_file(path)
        report.engines["Antivirus"] = status
        for f in findings:
            f.path = f.path or os.path.basename(path)
            report.add(f)

    def _run_reputation(self, path: str, report: ScanReport) -> None:
        if not self.options.vt_api_key:
            report.engines["VirusTotal"] = "off (no API key)"
            return
        self._progress("Checking file fingerprints with VirusTotal...")
        ranked = sorted(report.files, key=lambda r: (-self._risk.get(r.sha256, Severity.LOW), r.path))
        seen = set()
        queue = []
        for rec in ranked:
            if rec.sha256 and rec.sha256 not in seen:
                seen.add(rec.sha256)
                queue.append((rec.path, rec.sha256))
        vt = VirusTotal(self.options.vt_api_key, self.options.vt_max_lookups)
        status, findings = vt.lookup_many(queue, self._cancelled)
        report.engines["VirusTotal"] = status
        report.extend(findings)

    def _check_cancel(self) -> None:
        if self._cancelled():
            raise ScanCancelled


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
