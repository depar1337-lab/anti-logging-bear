# Anti-Logging Bear by Priest

from __future__ import annotations

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

from . import generic
from .findings import Finding, Severity

_configured = False


def _configure(rarfile) -> None:
    global _configured
    if _configured:
        return
    _configured = True
    candidates = []
    if sys.platform == "win32":
        for base in filter(None, (os.environ.get("PROGRAMFILES"), os.environ.get("PROGRAMFILES(X86)"),
                                  os.environ.get("PROGRAMW6432"))):
            candidates.append(("UNRAR_TOOL", os.path.join(base, "WinRAR", "UnRAR.exe")))
            candidates.append(("SEVENZIP_TOOL", os.path.join(base, "7-Zip", "7z.exe")))
        system_tar = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "tar.exe")
        candidates.append(("BSDTAR_TOOL", system_tar))
    elif sys.platform == "darwin":
        candidates.append(("BSDTAR_TOOL", "/usr/bin/tar"))
    for setting, tool in candidates:
        if os.path.isfile(tool) and not shutil.which(getattr(rarfile, setting)):
            setattr(rarfile, setting, tool)
    with contextlib.suppress(Exception):
        rarfile.tool_setup(force=True)


def _system_tar() -> str:
    if sys.platform == "win32":
        candidates = [os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "tar.exe")]
    elif sys.platform == "darwin":
        candidates = ["/usr/bin/bsdtar", "/usr/bin/tar"]
    else:
        candidates = [shutil.which("bsdtar") or ""]
    return next((tool for tool in candidates if tool and os.path.isfile(tool)), "")


def walk(walker, path: str, data: bytes, depth: int):
    try:
        import rarfile
    except ImportError:
        return [Finding(path, "archive.unsupported", Severity.HIGH,
                        "Contains a RAR archive Barry can't open here - check it with the Windows or Mac app")], []
    _configure(rarfile)
    locked = Finding(path, "archive.encrypted", Severity.HIGH,
                     "Password-protected RAR archive - Barry can't see inside, not even the file names",
                     "Malware is often shipped in passworded archives to dodge scanners.")
    try:
        archive = rarfile.RarFile(io.BytesIO(data))
    except rarfile.PasswordRequired:
        return [locked], []
    except Exception as exc:
        return [Finding(path, "archive.unreadable", Severity.HIGH,
                        "Barry can't open this RAR archive - it may be damaged or disguised", str(exc)[:200])], []
    if archive.needs_password() and not archive.infolist():
        archive.close()
        return [locked], []
    return [], _entries(walker, archive, path, data, depth, rarfile)


def _entries(walker, archive, path: str, data: bytes, depth: int, rarfile):
    blind: list[str] = []
    with archive:
        members = [info for info in archive.infolist()
                   if not info.is_dir() and not info.is_symlink() and not getattr(info, "file_redir", None)]
        wanted = set()
        for info in members:
            child = f"{path}/{info.filename}"
            walker.check_path(child, info.filename)
            if walker.admit(child, int(info.file_size or 0), int(info.compress_size or 0), info.needs_password()):
                wanted.add(info.filename)

        tar = _system_tar()
        contents = _stream_with_tar(tar, data, members, walker) if tar and members else None
        if contents is not None:
            for info in members:
                if info.filename in wanted and info.filename in contents:
                    yield walker.accept(f"{path}/{info.filename}", contents[info.filename], depth)
        else:
            for info in members:
                if info.filename not in wanted:
                    continue
                child = f"{path}/{info.filename}"
                if blind:
                    blind.append(child)
                    continue
                try:
                    with archive.open(info) as handle:
                        content = handle.read(walker.limits.max_member_bytes + 1)
                except rarfile.RarCannotExec:
                    blind.append(child)
                    continue
                except rarfile.BadRarFile:
                    blind.append(child)
                    continue
                except Exception as exc:
                    walker.findings.append(Finding(child, "archive.corrupt", Severity.MEDIUM,
                                                   "File inside the RAR archive is damaged", str(exc)[:200]))
                    continue
                yield walker.accept(child, content, depth)
    if blind:
        _report_blind(walker, path, blind)


def _stream_with_tar(tool: str, data: bytes, members, walker):
    expected = sum(int(info.file_size or 0) for info in members)
    if expected > walker.limits.max_total_bytes:
        return None
    handle, name = tempfile.mkstemp(suffix=".rar")
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(data)
        flags = 0x08000000 if sys.platform == "win32" else 0
        process = subprocess.Popen([tool, "-x", "--to-stdout", "-f", name], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=flags)
        try:
            stream = process.stdout.read(expected + 1)
        finally:
            process.stdout.close()
            process.kill()
            process.wait()
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            os.unlink(name)
    if len(stream) != expected:
        return None
    contents, offset = {}, 0
    for info in members:
        size = int(info.file_size or 0)
        contents[info.filename] = stream[offset:offset + size]
        offset += size
    return contents


def _report_blind(walker, path: str, blind: list) -> None:
    risky = [name for name in blind
             if generic.extension(name) in generic.EXECUTABLE_EXTS or generic.extension(name) in generic.SCRIPT_EXTS]
    for name in blind:
        walker.findings.extend(generic.check_name(name))
    walker.findings.append(Finding(
        path, "archive.rar-names-only", Severity.HIGH if risky else Severity.MEDIUM,
        "Barry could read the file names in this RAR but not the files themselves",
        "Installing the free 7-Zip or WinRAR lets Barry read every kind of RAR archive. "
        + (f"It holds {len(risky)} program(s) or script(s) Barry couldn't check." if risky else
           "None of the files are programs or scripts."),
        risky[:10]))
