# Anti-Logging Bear by Priest

from __future__ import annotations

import json
import struct

from .findings import Finding, Severity

MAX_HEADER = 64 * 1024 * 1024
NATIVE_EXTS = {"node", "exe", "dll", "ps1", "bat", "cmd", "vbs"}


def is_asar(name: str, data: bytes) -> bool:
    return len(data) >= 16 and data[:4] == b"\x04\x00\x00\x00" and name.lower().endswith(".asar")


def walk(walker, path: str, data: bytes, depth: int):
    try:
        header_size, = struct.unpack_from("<I", data, 4)
        json_size, = struct.unpack_from("<I", data, 12)
        if json_size > MAX_HEADER or 16 + json_size > len(data):
            raise ValueError("header too large")
        tree = json.loads(data[16:16 + json_size].decode("utf-8"))
    except (struct.error, ValueError, UnicodeDecodeError) as exc:
        return [Finding(path, "asar.damaged", Severity.MEDIUM,
                        "Electron app bundle is damaged - Barry can't read its code", str(exc)[:200])], []
    base = 8 + header_size
    files = list(_files(tree, ""))
    own = [f for f in files if not _skip(f[0])]
    found = [Finding(path, "asar.found", Severity.INFO,
                     f"Electron app bundle - Barry read its {len(own)} file(s) of JavaScript and resources",
                     f"Skipped {len(files) - len(own)} third-party library file(s) in node_modules.")]
    return found, _entries(walker, path, data, base, own, depth)


def _files(node: dict, prefix: str):
    for name, item in (node.get("files") or {}).items():
        if not isinstance(item, dict) or "/" in name or name in ("..", "."):
            continue
        full = prefix + name
        if "files" in item:
            yield from _files(item, full + "/")
        elif not item.get("unpacked") and "link" not in item:
            try:
                yield full, int(item["offset"]), int(item["size"])
            except (KeyError, TypeError, ValueError):
                continue


def _skip(name: str) -> bool:
    if "node_modules/" not in name:
        return False
    return name.rsplit(".", 1)[-1].lower() not in NATIVE_EXTS


def _entries(walker, path: str, data: bytes, base: int, files, depth: int):
    for name, offset, size in files:
        child = f"{path}/{name}"
        start = base + offset
        if size < 0 or start < base or start + size > len(data):
            continue
        if walker.admit(child, size):
            yield walker.accept(child, data[start:start + size], depth)
