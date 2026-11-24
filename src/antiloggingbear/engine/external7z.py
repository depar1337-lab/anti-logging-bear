# Anti-Logging Bear by Priest

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from . import generic
from .findings import Finding, Severity

BIN_DIR = Path(__file__).resolve().parent.parent / "bin"
NO_PASSWORD = "-pBarryHasNoPassword"
TIMEOUT = 300
MAX_SINGLE_READS = 300


def find_tool() -> str:
    names = ("7z.exe",) if sys.platform == "win32" else ("7zz", "7z")
    for name in names:
        bundled = BIN_DIR / name
        if bundled.is_file():
            return str(bundled)
    if sys.platform == "win32":
        for base in filter(None, (os.environ.get("PROGRAMFILES"), os.environ.get("PROGRAMW6432"),
                                  os.environ.get("PROGRAMFILES(X86)"))):
            candidate = Path(base) / "7-Zip" / "7z.exe"
            if candidate.is_file():
                return str(candidate)
        return ""
    for name in ("7zz", "7z", "7za"):
        found = shutil.which(name)
        if found:
            return found
    return ""


def available() -> bool:
    return bool(find_tool())


def walk(walker, path: str, data: bytes, depth: int, label: str = "archive"):
    tool = find_tool()
    if not tool:
        return None
    handle, archive = tempfile.mkstemp(suffix="." + (generic.extension(path) or "bin"))
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(data)
        listing, error = _run(tool, ["l", "-slt", "-ba", "-sccUTF-8", NO_PASSWORD, "--", archive])
        if "Wrong password" in error or "encrypted archive" in error.lower():
            with contextlib.suppress(OSError):
                os.unlink(archive)
            return [Finding(path, "archive.encrypted", Severity.HIGH,
                            f"Password-protected {label} - Barry can't see inside, not even the file names",
                            "Malware is often shipped in passworded archives to dodge scanners.")], []
        members = _parse_listing(listing.decode("utf-8", "replace"))
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(archive)
        raise
    if not members:
        with contextlib.suppress(OSError):
            os.unlink(archive)
        return None
    return [], _entries(walker, tool, archive, path, members, depth)


def _entries(walker, tool: str, archive: str, path: str, members: list, depth: int):
    try:
        wanted = []
        for member in members:
            child = f"{path}/{member['path']}"
            walker.check_path(child, member["path"])
            if walker.admit(child, max(member["size"], 0), member["packed"], member["encrypted"]):
                wanted.append(member)
        if not wanted:
            return
        known = all(m["size"] >= 0 for m in members)
        expected = sum(m["size"] for m in members) if known else -1
        stream = None
        if known and expected <= walker.limits.max_total_bytes:
            stream = _stream(tool, ["e", "-so", "-ba", "-y", "-sccUTF-8", NO_PASSWORD, "--", archive], expected)
        if stream is not None and len(stream) == expected:
            offset, contents = 0, {}
            for member in members:
                contents[member["index"]] = stream[offset:offset + member["size"]]
                offset += member["size"]
            for member in wanted:
                yield walker.accept(f"{path}/{member['path']}", contents[member["index"]], depth)
            return
        unread = []
        for number, member in enumerate(wanted):
            if number >= MAX_SINGLE_READS:
                unread.append(member["path"])
                continue
            size = member["size"]
            limit = size if size >= 0 else walker.limits.max_member_bytes
            content = _stream(tool, ["e", "-so", "-ba", "-y", "-spd", "-sccUTF-8", NO_PASSWORD, "--", archive,
                                     member["path"]], limit)
            if content is None or (len(content) != size if size >= 0 else not content):
                unread.append(member["path"])
                continue
            yield walker.accept(f"{path}/{member['path']}", content, depth)
        if unread:
            walker.findings.append(Finding(
                path, "archive.partly-unread", Severity.MEDIUM,
                f"Barry couldn't read {len(unread)} of the files listed inside",
                "Installers and uninstallers often list files they don't carry. " + ", ".join(unread[:8])))
    finally:
        with contextlib.suppress(OSError):
            os.unlink(archive)


def _parse_listing(text: str) -> list:
    members, current = [], {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if current.get("Path") is not None and "D" not in current.get("Attributes", "") \
                    and current.get("Folder", "-") != "+" \
                    and not current.get("Symbolic Link") and not current.get("Hard Link"):
                with contextlib.suppress(ValueError):
                    members.append({
                        "index": len(members),
                        "path": current["Path"].replace("\\", "/"),
                        "size": int(current["Size"]) if current.get("Size") else -1,
                        "packed": int(current.get("Packed Size") or 0),
                        "encrypted": current.get("Encrypted") == "+",
                    })
            current = {}
            continue
        key, sep, value = line.partition(" = ")
        if sep:
            current[key.strip()] = value.strip()
    return members


def _popen(tool: str, args: list, errors=subprocess.PIPE):
    flags = 0x08000000 if sys.platform == "win32" else 0
    return subprocess.Popen([tool] + args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=errors, creationflags=flags)


def _run(tool: str, args: list):
    process = _popen(tool, args)
    try:
        out, err = process.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
    return out, err.decode("utf-8", "replace")


def _stream(tool: str, args: list, expected: int):
    process = _popen(tool, args, subprocess.DEVNULL)
    timer = threading.Timer(TIMEOUT, process.kill)
    timer.start()
    try:
        data = process.stdout.read(expected + 1)
    except OSError:
        data = None
    finally:
        timer.cancel()
        with contextlib.suppress(OSError):
            process.stdout.close()
        process.kill()
        process.wait()
    return data
