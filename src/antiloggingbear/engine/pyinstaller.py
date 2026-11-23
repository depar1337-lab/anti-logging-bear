# Anti-Logging Bear by Priest

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

from . import capabilities as cap
from . import indicators as ioc
from .findings import Finding, Severity
from .pe import PYINSTALLER_MAGIC as MAGIC
from .pynames import LIBRARIES, STDLIB
from .scripts import analyze_text

_COOKIE = struct.Struct("!8sIIii64s")
_COOKIE_OLD = struct.Struct("!8sIIii")
_TOC_ENTRY = struct.Struct("!iIIIBc")
MAX_SCRIPT = 16 * 1024 * 1024
MAX_OWN_MODULES = 400

MODULE_CAPABILITIES = {
    "pynput.keyboard": cap.KEYS, "keyboard": cap.KEYS, "pyHook": cap.KEYS, "pyWinhook": cap.KEYS,
    "browser_cookie3": cap.CREDENTIALS, "win32crypt": cap.CREDENTIALS, "browser_history": cap.CREDENTIALS,
    "pyperclip": cap.CLIPBOARD, "win32clipboard": cap.CLIPBOARD,
    "PIL.ImageGrab": cap.SCREENSHOT, "mss": cap.SCREENSHOT, "pyscreeze": cap.SCREENSHOT,
    "requests": cap.NETWORK, "aiohttp": cap.NETWORK, "httpx": cap.NETWORK, "websocket": cap.NETWORK,
    "websockets": cap.NETWORK, "discord": cap.NETWORK,
    "discord_webhook": cap.EXFIL, "dhooks": cap.EXFIL, "telebot": cap.EXFIL, "telegram": cap.EXFIL,
    "aiogram": cap.EXFIL,
}
OBFUSCATORS = {"pyarmor_runtime": "PyArmor", "pytransform": "PyArmor", "pyarmor": "PyArmor"}


@dataclass
class Bundle:
    python: str = ""
    scripts: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    own: list = field(default_factory=list)
    encrypted: bool = False
    damaged: bool = False


def analyze(path: str, data: bytes, children: list, depth: int, walker) -> list[Finding]:
    if MAGIC not in data:
        return []
    bundle = read_bundle(data)
    if bundle is None:
        return []

    findings = [Finding(path, "pyinstaller.found", Severity.INFO,
                        "Python program packed with PyInstaller - Barry unpacked and read its Python code",
                        f"{len(bundle.scripts)} script(s), {len(bundle.own)} of its own module(s)"
                        + (f", built with {bundle.python}" if bundle.python else ""))]
    if bundle.damaged:
        findings.append(Finding(path, "pyinstaller.damaged", Severity.MEDIUM,
                                "Part of the packed Python code is damaged or hidden"))
    if bundle.encrypted:
        findings.append(Finding(path, "pyinstaller.encrypted", Severity.MEDIUM,
                                "Some of its Python code is encrypted, so Barry can't read it",
                                "PyInstaller can encrypt code; malware authors use it to hide from scanners."))

    names = set(bundle.modules)
    for name in sorted(names):
        top = name.split(".")[0]
        if top in OBFUSCATORS:
            findings.append(Finding(path, "pyinstaller.obfuscated", Severity.MEDIUM,
                                    f"Python code is scrambled with {OBFUSCATORS[top]}",
                                    "Obfuscators hide what code does. Paid tools use them, and so do stealers."))
            break

    caps = cap.Capabilities()
    for name, capability in MODULE_CAPABILITIES.items():
        if name in names or any(n.startswith(name + ".") for n in names):
            caps.add(capability, f"uses {name}")

    texts = []
    for name, code in bundle.scripts + bundle.own:
        texts.append(ioc.extract_strings(code))
        if walker.admit(f"{path}/[python] {name}", len(code)):
            children.append(walker.accept(f"{path}/[python] {name}", code, depth))
    text = "\n".join(texts)
    findings.extend(analyze_text(path, text, "python", caps, prefix="pyinstaller"))
    return findings


def read_bundle(data: bytes) -> Bundle | None:
    pos = data.rfind(MAGIC)
    if pos < 0:
        return None
    bundle = Bundle()
    if pos + _COOKIE.size <= len(data):
        _magic, length, toc_offset, toc_length, pyver, pylib = _COOKIE.unpack_from(data, pos)
        end = pos + _COOKIE.size
        name = pylib.split(b"\x00", 1)[0].decode("ascii", "ignore")
        if pyver >= 100:
            bundle.python = f"Python {pyver // 100}.{pyver % 100}"
        elif name:
            bundle.python = name
    elif pos + _COOKIE_OLD.size <= len(data):
        _magic, length, toc_offset, toc_length, _pyver = _COOKIE_OLD.unpack_from(data, pos)
        end = pos + _COOKIE_OLD.size
    else:
        return None
    start = end - length
    if start < 0 or toc_offset < 0 or toc_length <= 0 or start + toc_offset + toc_length > len(data):
        return None

    cursor = start + toc_offset
    stop = cursor + toc_length
    while cursor + _TOC_ENTRY.size <= stop:
        size, offset, packed, unpacked, compressed, kind = _TOC_ENTRY.unpack_from(data, cursor)
        if size < _TOC_ENTRY.size:
            bundle.damaged = True
            break
        name = data[cursor + _TOC_ENTRY.size:cursor + size].split(b"\x00", 1)[0].decode("utf-8", "replace")
        cursor += size
        blob = data[start + offset:start + offset + packed]
        if kind == b"s":
            if name.startswith("pyi_rth_") or name.startswith("pyiboot") or name == "pyi_rth__tkinter":
                continue
            code = _inflate(blob, compressed, unpacked)
            if code is None:
                bundle.damaged = True
            else:
                bundle.scripts.append((name, code))
        elif kind in (b"z", b"Z"):
            _read_pyz(blob, bundle)
    return bundle


def _inflate(blob: bytes, compressed: int, unpacked: int) -> bytes | None:
    if not compressed:
        return blob[:MAX_SCRIPT]
    try:
        out = zlib.decompressobj().decompress(blob, MAX_SCRIPT)
    except zlib.error:
        return None
    return out


def _read_pyz(blob: bytes, bundle: Bundle) -> None:
    if not blob.startswith(b"PYZ\x00") or len(blob) < 12:
        bundle.damaged = True
        return
    (toc_pos,) = struct.unpack_from("!i", blob, 8)
    toc = _Marshal(blob, toc_pos).read()
    items = toc.items() if isinstance(toc, dict) else toc if isinstance(toc, (list, tuple)) else None
    if items is None:
        bundle.damaged = True
        return
    for item in items:
        try:
            name, (_kind, pos, length) = item
        except (TypeError, ValueError):
            continue
        if not isinstance(name, str) or not isinstance(pos, int) or not isinstance(length, int):
            continue
        bundle.modules.append(name)
        top = name.split(".")[0]
        if top in STDLIB or top in LIBRARIES or top.startswith("_") or len(bundle.own) >= MAX_OWN_MODULES:
            continue
        try:
            code = zlib.decompressobj().decompress(blob[pos:pos + length], MAX_SCRIPT)
        except zlib.error:
            bundle.encrypted = True
            continue
        bundle.own.append((name, code))


class _Marshal:
    def __init__(self, data: bytes, pos: int) -> None:
        self.data = data
        self.pos = pos
        self.refs: list = []
        self.depth = 0

    def _take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def _int(self) -> int:
        return struct.unpack("<i", self._take(4))[0]

    def read(self):
        try:
            return self._value()
        except (ValueError, IndexError, TypeError, struct.error, RecursionError):
            return None

    def _value(self):
        self.depth += 1
        if self.depth > 50:
            raise ValueError("too deep")
        code = self._take(1)[0]
        flag, kind = code & 0x80, chr(code & 0x7F)
        slot = None
        if flag and kind not in "r":
            slot = len(self.refs)
            self.refs.append(None)
        if kind == "N":
            value = None
        elif kind in "TF":
            value = kind == "T"
        elif kind == "i":
            value = self._int()
        elif kind == "l":
            digits = self._int()
            value = 0
            for i in range(abs(digits)):
                value |= struct.unpack("<H", self._take(2))[0] << (15 * i)
            value = -value if digits < 0 else value
        elif kind in "zZ":
            value = self._take(self._take(1)[0]).decode("latin-1")
        elif kind in "aAut":
            raw = self._take(self._int())
            value = raw.decode("utf-8", "replace") if kind in "ut" else raw.decode("latin-1")
        elif kind == "s":
            value = self._take(self._int())
        elif kind in "([":
            value = [self._value() for _ in range(self._bounded(self._int()))]
            value = tuple(value) if kind == "(" else value
        elif kind == ")":
            value = tuple(self._value() for _ in range(self._take(1)[0]))
        elif kind == "{":
            value = {}
            while self.data[self.pos:self.pos + 1] != b"0":
                key = self._value()
                value[key] = self._value()
            self.pos += 1
        elif kind == "r":
            value = self.refs[self._int()]
        else:
            raise ValueError(f"unsupported marshal type {kind!r}")
        if slot is not None:
            self.refs[slot] = value
        self.depth -= 1
        return value

    def _bounded(self, count: int) -> int:
        if count < 0 or count > 1_000_000:
            raise ValueError("bad length")
        return count
