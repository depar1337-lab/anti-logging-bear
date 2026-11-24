# Anti-Logging Bear by Priest

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Callable

from . import antivirus, asar, external7z, generic, pyinstaller, rar, sevenzip
from .archive import MB, ArchiveWalker, Entry, Limits, StopScan
from .bazaar import MalwareBazaar
from .findings import FileRecord, Finding, ScanReport, Severity
from .office import analyze_office
from .pdf import analyze_pdf
from .pe import analyze_pe, overlay_start
from .reputation import VirusTotal
from .scripts import analyze_script
from .shortcuts import analyze_lnk, analyze_url_shortcut
from .yara_rules import shared_engine

Progress = Callable[[str], None]
MAX_FOLDER_FILES = 20000
CONTAINERS = {"msi": "Windows installer package (MSI)", "cab": "cabinet archive (CAB)",
              "iso": "disk image (ISO)", "dmg": "Mac disk image (DMG)", "chm": "compiled help file (CHM)",
              "wim": "Windows image (WIM)"}


@dataclass
class ScanOptions:
    limits: Limits = field(default_factory=Limits)
    max_file_bytes: int = 2048 * MB
    strict: bool = False
    use_yara: bool = True
    custom_rules_dir: str = ""
    rules_dir: str = ""
    use_antivirus: bool = True
    vt_api_key: str = ""
    vt_max_lookups: int = 4
    mb_api_key: str = ""
    mb_max_lookups: int = 25


class ScanCancelled(Exception):
    pass


def scan_path(path: str, options: ScanOptions | None = None,
              progress: Progress | None = None,
              cancelled: Callable[[], bool] = lambda: False) -> ScanReport:
    return Scanner(options or ScanOptions(), progress, cancelled).run(path)


def scan_data(name: str, data: bytes, options: ScanOptions | None = None) -> ScanReport:
    scanner = Scanner(options or ScanOptions(use_antivirus=False), None, lambda: False)
    started = time.monotonic()
    report = ScanReport(target=name, strict=scanner.options.strict)
    if scanner.options.use_yara:
        scanner._yara = shared_engine(scanner.options.custom_rules_dir, scanner.options.rules_dir)
        report.engines["YARA"] = scanner._yara.status
    report.extend(generic.check_name(name))
    try:
        scanner._scan_tree(Entry(path=name, data=data, depth=0), report, inspect_names=False)
    except StopScan:
        pass
    finally:
        report.extend(scanner._walker.findings)
    report.duration = time.monotonic() - started
    return report


class Scanner:
    def __init__(self, options: ScanOptions, progress: Progress | None,
                 cancelled: Callable[[], bool]) -> None:
        self.options = options
        self._progress = progress or (lambda _msg: None)
        self._cancelled = cancelled
        self._yara = None
        self._risk: dict[str, Severity] = {}
        self._walker = ArchiveWalker(options.limits)

    def run(self, path: str) -> ScanReport:
        started = time.monotonic()
        report = ScanReport(target=os.path.abspath(path), strict=self.options.strict)
        name = os.path.basename(path)

        if self.options.use_yara:
            self._yara = shared_engine(self.options.custom_rules_dir, self.options.rules_dir)
            report.engines["YARA"] = self._yara.status
        else:
            report.engines["YARA"] = "off"

        if os.path.isdir(path):
            self._scan_folder(path, report)
        else:
            report.extend(generic.check_name(name))
            self._scan_file(path, name, report, inspect_names=False)

        self._check_cancel()
        self._run_antivirus(path, report)
        self._run_reputation(path, report)
        self._run_bazaar(report)
        report.duration = time.monotonic() - started
        return report

    def _scan_file(self, path: str, name: str, report: ScanReport, inspect_names: bool) -> None:
        size = os.path.getsize(path)
        self._walker = ArchiveWalker(self.options.limits)
        try:
            if size > self.options.max_file_bytes:
                report.add(Finding(name, "file.too-large", Severity.MEDIUM,
                                   f"File is larger than the scan limit ({size / MB:.0f} MB)"))
            elif self._is_plain_zip(path, name):
                report.files.append(FileRecord(name, size, _sha256_file(path), "zip"))
                if inspect_names:
                    report.extend(generic.check_name(name))
                for entry in self._walker.walk(path, name + "/" if inspect_names else "", 0):
                    self._scan_tree(entry, report)
            else:
                with open(path, "rb") as fh:
                    data = fh.read()
                self._scan_tree(Entry(path=name, data=data, depth=0, source=path), report,
                                inspect_names=inspect_names)
        except StopScan:
            pass
        finally:
            report.extend(self._walker.findings)

    def _scan_folder(self, folder: str, report: ScanReport) -> None:
        count = 0
        for root, dirs, files in os.walk(folder):
            dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
            for filename in sorted(files):
                full = os.path.join(root, filename)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                count += 1
                if count > MAX_FOLDER_FILES:
                    report.add(Finding(os.path.basename(folder), "folder.too-many", Severity.MEDIUM,
                                       f"Folder has more than {MAX_FOLDER_FILES:,} files - Barry checked the first "
                                       f"{MAX_FOLDER_FILES:,}"))
                    return
                self._check_cancel()
                relative = os.path.relpath(full, folder).replace(os.sep, "/")
                try:
                    self._scan_file(full, relative, report, inspect_names=True)
                except OSError as exc:
                    report.add(Finding(relative, "file.unreadable", Severity.INFO,
                                       "Barry couldn't open this file", str(exc)[:200]))

    @staticmethod
    def _is_plain_zip(path: str, name: str) -> bool:
        with open(path, "rb") as fh:
            head = fh.read(8)
        return head.startswith(b"PK") and generic.extension(name) not in generic.OFFICE_EXTS

    def _scan_tree(self, entry: Entry, report: ScanReport, inspect_names: bool = True) -> None:
        self._check_cancel()
        kind, children = self._scan_entry(entry, report, inspect_names)
        for child in _flatten(children):
            if child.depth > self.options.limits.max_depth:
                report.add(Finding(entry.path, "archive.deep", Severity.HIGH,
                                   "Files nested too deep - Barry stopped looking",
                                   "Deeply nested archives are used to tire out scanners."))
                break
            self._scan_tree(child, report)

    def _scan_entry(self, entry: Entry, report: ScanReport, inspect_names: bool = True):
        data = entry.data
        kind = generic.sniff(entry.path, data)
        sha = hashlib.sha256(data).hexdigest()
        report.files.append(FileRecord(entry.path, len(data), sha, kind))
        self._progress(entry.path)

        findings: list[Finding] = []
        children: list = []
        if inspect_names:
            findings.extend(generic.check_name(entry.path))
        findings.extend(generic.check_content(entry.path, kind, data))
        findings.extend(self._analyze(entry, kind, children))
        if self._yara is not None and kind not in ("zip", "7z", "rar"):
            findings.extend(self._yara.match(entry.path, data))

        report.extend(findings)
        worst = max((f.severity for f in findings), default=Severity.INFO)
        if generic.extension(entry.path) in generic.EXECUTABLE_EXTS or kind in ("pe", "office", "pdf"):
            worst = max(worst, Severity.LOW)
        self._risk[sha] = max(self._risk.get(sha, Severity.INFO), worst)
        return kind, children

    def _analyze(self, entry: Entry, kind: str, children: list) -> list[Finding]:
        path, data, depth = entry.path, entry.data, entry.depth
        if kind == "zip":
            children.append(self._walker.walk(data, path + "/", depth + 1))
            return []
        if kind in ("7z", "rar"):
            result = external7z.walk(self._walker, path, data, depth + 1, f"{kind.upper()} archive")
            if result is None:
                reader = sevenzip if kind == "7z" else rar
                result = reader.walk(self._walker, path, data, depth + 1)
            found, inner = result
            children.append(inner)
            return found
        if kind in CONTAINERS:
            return self._open_with_7zip(entry, CONTAINERS[kind], children)
        if kind == "pe":
            found = analyze_pe(path, data, children, depth + 1, self._walker, entry.source)
            found.extend(pyinstaller.analyze(path, data, children, depth + 1, self._walker))
            installer = self._installer(entry, children)
            if any(f.check == "installer.opened" for f in installer):
                found = [f for f in found if f.check != "pe.overlay"]
            return found + installer
        if kind == "asar":
            found, inner = asar.walk(self._walker, path, data, depth + 1)
            children.append(inner)
            return found
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
        if kind == "gzip":
            return [Finding(path, "archive.unsupported", Severity.MEDIUM,
                            "Contains a GZIP archive Barry can't open - check it separately")]
        return []

    def _open_with_7zip(self, entry: Entry, label: str, children: list) -> list[Finding]:
        result = external7z.walk(self._walker, entry.path, entry.data, entry.depth + 1, label)
        if result is None:
            return [Finding(entry.path, "archive.unsupported", Severity.MEDIUM,
                            f"Contains a {label} Barry can't open - check it separately")]
        found, inner = result
        children.append(inner)
        return found

    def _installer(self, entry: Entry, children: list) -> list[Finding]:
        data = entry.data
        tail = data[overlay_start(data):]
        if not tail:
            return []
        if b"Inno Setup Setup Data" in data and (b"zlb\x1a" in tail or b"idska" in tail or b"rDlPtS" in tail):
            return [Finding(entry.path, "installer.inno", Severity.INFO,
                            "Inno Setup installer - Barry checks the installer itself but can't open its files yet")]
        label = None
        if b"\xef\xbe\xad\xdeNullsoftInst" in tail:
            label = "NSIS installer"
        elif b"7z\xbc\xaf\x27\x1c" in tail:
            label = "self-extracting 7z archive"
        elif b"Rar!\x1a\x07" in tail:
            label = "self-extracting RAR archive"
        if label is None:
            return []
        result = external7z.walk(self._walker, entry.path, data, entry.depth + 1, label)
        if result is None:
            return [Finding(entry.path, "installer.unopened", Severity.INFO,
                            f"{label[0].upper() + label[1:]} - Barry checks it but can't open its files here")]
        found, inner = result
        children.append(inner)
        return [Finding(entry.path, "installer.opened", Severity.INFO,
                        f"{label[0].upper() + label[1:]} - Barry opened it and checked the files inside")] + found

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

    def _run_bazaar(self, report: ScanReport) -> None:
        if not self.options.mb_api_key:
            report.engines["MalwareBazaar"] = "off (no Auth-Key)"
            return
        self._progress("Checking file fingerprints with MalwareBazaar...")
        ranked = sorted(report.files, key=lambda r: (-self._risk.get(r.sha256, Severity.LOW), r.path))
        seen, queue = set(), []
        for rec in ranked:
            if rec.sha256 and rec.sha256 not in seen and rec.kind not in ("text", "data"):
                seen.add(rec.sha256)
                queue.append((rec.path, rec.sha256))
        status, findings = MalwareBazaar(self.options.mb_api_key, self.options.mb_max_lookups).lookup_many(
            queue, self._cancelled)
        report.engines["MalwareBazaar"] = status
        report.extend(findings)

    def _check_cancel(self) -> None:
        if self._cancelled():
            raise ScanCancelled


def _flatten(items: list):
    for item in items:
        if isinstance(item, Entry):
            yield item
        else:
            yield from item


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
