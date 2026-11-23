# Anti-Logging Bear by Priest

from __future__ import annotations

import io
import lzma
import re
import zipfile
import zlib
from dataclasses import dataclass
from typing import IO, Iterator

from .findings import Finding, Severity
from .generic import EXECUTABLE_EXTS, extension

MB = 1024 * 1024


@dataclass
class Limits:
    max_total_bytes: int = 1024 * MB
    max_member_bytes: int = 256 * MB
    max_members: int = 20000
    max_ratio: int = 250
    max_depth: int = 5


@dataclass
class Entry:
    path: str
    data: bytes
    depth: int


class StopScan(Exception):
    pass


class ArchiveWalker:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.findings: list[Finding] = []
        self.skipped: list[str] = []
        self._total = 0
        self._count = 0

    def walk(self, source: str | bytes | IO[bytes], prefix: str = "", depth: int = 0) -> Iterator[Entry]:
        label = prefix.rstrip("/") or "(archive)"
        if isinstance(source, bytes):
            source = io.BytesIO(source)
        try:
            zf = zipfile.ZipFile(source)
        except (zipfile.BadZipFile, OSError, ValueError) as exc:
            self._flag(label, "archive.unreadable", Severity.HIGH,
                       "Barry can't open this archive - it may be damaged or disguised", str(exc))
            return

        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                path = prefix + info.filename
                self._check_path(path, info.filename)
                entry = self._read(zf, info, path, depth)
                if entry is not None:
                    yield entry

    def _check_path(self, path: str, name: str) -> None:
        norm = name.replace("\\", "/")
        if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm) or ".." in norm.split("/"):
            self._flag(path, "archive.traversal", Severity.HIGH,
                       "Would write a file outside the folder you unzip into",
                       f"Archive path: {name}")

    def admit(self, path: str, declared: int, packed: int = 0, encrypted: bool = False) -> bool:
        ext = extension(path)
        self._count += 1
        if self._count > self.limits.max_members:
            self._flag(path.split("/")[0] or path, "archive.too-many", Severity.HIGH,
                       "Archive holds an unusually huge number of files (possible zip bomb)",
                       f"Stopped after {self.limits.max_members} files.")
            raise StopScan
        if encrypted:
            self._flag(path, "archive.encrypted", Severity.HIGH,
                       "Password-protected file - Barry can't see inside",
                       "Malware is often shipped in passworded archives to dodge scanners.")
            self.skipped.append(path)
            return False
        if declared > 10 * MB and packed and declared / packed > self.limits.max_ratio:
            self._flag(path, "archive.bomb", Severity.HIGH,
                       "Compresses impossibly well - looks like a zip bomb",
                       f"{declared / MB:.0f} MB packed into {packed / 1024:.1f} KB.")
            self.skipped.append(path)
            return False
        if declared > self.limits.max_member_bytes:
            sev = Severity.HIGH if ext in EXECUTABLE_EXTS else Severity.MEDIUM
            self._flag(path, "archive.too-large", sev,
                       f"File is too large to inspect ({declared / MB:.0f} MB)",
                       "Oversized programs are a common trick to get past antivirus size limits.")
            self.skipped.append(path)
            return False
        if self._total + declared > self.limits.max_total_bytes:
            self._flag(path, "archive.total", Severity.HIGH,
                       "Archive unpacks to far more data than expected (possible zip bomb)")
            raise StopScan
        return True

    def accept(self, path: str, data: bytes, depth: int) -> Entry:
        if len(data) > self.limits.max_member_bytes:
            self._flag(path, "archive.size-lie", Severity.HIGH,
                       "File lies about its size inside the archive (possible zip bomb)")
            raise StopScan
        self._total += len(data)
        return Entry(path=path, data=data, depth=depth)

    def _read(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo, path: str, depth: int):
        encrypted = bool(info.flag_bits & 0x1 or info.compress_type == 99)
        if not self.admit(path, info.file_size, info.compress_size, encrypted):
            return None
        try:
            with zf.open(info) as fh:
                data = fh.read(self.limits.max_member_bytes + 1)
        except NotImplementedError:
            self._flag(path, "archive.method", Severity.HIGH,
                       "Uses a compression method Barry can't read",
                       f"Compression type {info.compress_type}.")
            self.skipped.append(path)
            return None
        except RuntimeError as exc:
            self._flag(path, "archive.encrypted", Severity.HIGH,
                       "Password-protected file - Barry can't see inside", str(exc))
            self.skipped.append(path)
            return None
        except (zipfile.BadZipFile, zlib.error, lzma.LZMAError, EOFError, OSError) as exc:
            self._flag(path, "archive.corrupt", Severity.MEDIUM,
                       "File inside the archive is damaged", str(exc))
            self.skipped.append(path)
            return None
        return self.accept(path, data, depth)

    def check_path(self, path: str, name: str) -> None:
        self._check_path(path, name)

    def _flag(self, path: str, check: str, severity: Severity, title: str, detail: str = "") -> None:
        self.findings.append(Finding(path, check, severity, title, detail))
