# Anti-Logging Bear by Priest

from __future__ import annotations

import io

from .findings import Finding, Severity

BATCH_BYTES = 64 * 1024 * 1024


def walk(walker, path: str, data: bytes, depth: int):
    try:
        import py7zr
    except ImportError:
        return [Finding(path, "archive.unsupported", Severity.HIGH,
                        "Contains a 7z archive Barry can't open here - check it with the Windows or Mac app")], []
    try:
        archive = py7zr.SevenZipFile(io.BytesIO(data))
    except py7zr.PasswordRequired:
        return [Finding(path, "archive.encrypted", Severity.HIGH,
                        "Password-protected 7z archive - Barry can't see inside, not even the file names",
                        "Malware is often shipped in passworded archives to dodge scanners.")], []
    except Exception as exc:
        return [Finding(path, "archive.unreadable", Severity.HIGH,
                        "Barry can't open this 7z archive - it may be damaged or disguised", str(exc)[:200])], []
    return [], _entries(walker, archive, path, depth, py7zr)


def _entries(walker, archive, path: str, depth: int, py7zr):
    with archive:
        encrypted = archive.needs_password()
        wanted = []
        for info in archive.list():
            if info.is_directory:
                continue
            child = f"{path}/{info.filename}"
            walker.check_path(child, info.filename)
            if walker.admit(child, int(info.uncompressed or 0), int(info.compressed or 0), encrypted):
                wanted.append((info.filename, int(info.uncompressed or 0)))
        for batch in _batches(wanted):
            archive.reset()
            try:
                files = archive.read(targets=batch) or {}
            except (py7zr.UnsupportedCompressionMethodError, py7zr.DecompressionError, py7zr.Bad7zFile,
                    EOFError, OSError, ValueError) as exc:
                walker.findings.append(Finding(path, "archive.method", Severity.HIGH,
                                               "Uses a 7z compression method Barry can't read", str(exc)[:200]))
                return
            for name in batch:
                handle = files.get(name)
                if handle is not None:
                    yield walker.accept(f"{path}/{name}", handle.read(), depth)


def _batches(wanted):
    batch, size = [], 0
    for name, length in wanted:
        if batch and size + length > BATCH_BYTES:
            yield batch
            batch, size = [], 0
        batch.append(name)
        size += length
    if batch:
        yield batch
