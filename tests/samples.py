# Anti-Logging Bear by Priest

from __future__ import annotations

import base64
import io
import struct
import zipfile
from typing import List, Tuple

Members = List[Tuple[str, bytes]]


def make_zip(members: Members, encrypted: tuple[str, ...] = ()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
    raw = bytearray(buf.getvalue())
    for name in encrypted:
        encoded = name.encode()
        pos = 0
        while True:
            pos = raw.find(encoded, pos)
            if pos < 0:
                break
            if raw[pos - 30:pos - 26] == b"PK\x03\x04":
                raw[pos - 24] |= 0x1
            elif raw[pos - 46:pos - 42] == b"PK\x01\x02":
                raw[pos - 38] |= 0x1
            pos += len(encoded)
    return bytes(raw)


def _align(value: int, to: int) -> int:
    return (value + to - 1) // to * to


def make_pe(imports: dict[str, list[str]], extra: bytes = b"") -> bytes:
    """Builds a tiny, non-functional PE32 image with a real import table."""
    rva = 0x1000
    dlls = list(imports.items())
    desc_size = (len(dlls) + 1) * 20
    cursor = desc_size
    thunk_offsets = []
    for _dll, funcs in dlls:
        ilt = cursor
        cursor += (len(funcs) + 1) * 4
        iat = cursor
        cursor += (len(funcs) + 1) * 4
        thunk_offsets.append((ilt, iat))
    hint_offsets = []
    for _dll, funcs in dlls:
        offs = []
        for fn in funcs:
            offs.append(cursor)
            cursor += _align(2 + len(fn) + 1, 2)
        hint_offsets.append(offs)
    name_offsets = []
    for dll, _funcs in dlls:
        name_offsets.append(cursor)
        cursor += len(dll) + 1
    extra_offset = cursor
    cursor += len(extra)

    section = bytearray(cursor)
    for i, (dll, funcs) in enumerate(dlls):
        ilt, iat = thunk_offsets[i]
        struct.pack_into("<IIIII", section, i * 20, rva + ilt, 0, 0, rva + name_offsets[i], rva + iat)
        for j, fn in enumerate(funcs):
            struct.pack_into("<I", section, ilt + j * 4, rva + hint_offsets[i][j])
            struct.pack_into("<I", section, iat + j * 4, rva + hint_offsets[i][j])
            entry = struct.pack("<H", 0) + fn.encode() + b"\x00"
            section[hint_offsets[i][j]:hint_offsets[i][j] + len(entry)] = entry
        section[name_offsets[i]:name_offsets[i] + len(dll) + 1] = dll.encode() + b"\x00"
    section[extra_offset:extra_offset + len(extra)] = extra

    raw_size = _align(len(section), 0x200)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    dos[0x4E:0x4E + len(stub)] = stub

    coff = struct.pack("<4sHHIIIHH", b"PE\x00\x00", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    dirs = [(0, 0)] * 16
    dirs[1] = (rva, desc_size)
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 0, 0, raw_size, 0, 0, rva, rva, rva, 0x400000, 0x1000, 0x200,
        4, 0, 0, 0, 4, 0, 0, rva + _align(len(section), 0x1000), 0x200, 0, 2, 0,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    ) + b"".join(struct.pack("<II", a, s) for a, s in dirs)
    sect = struct.pack("<8sIIIIIIHHI", b".text", len(section), rva, raw_size, 0x200, 0, 0, 0, 0, 0xE0000020)
    header = bytes(dos) + coff + opt + sect
    header += b"\x00" * (0x200 - len(header))
    return header + bytes(section) + b"\x00" * (raw_size - len(section))


def make_lnk(relative_path: str, arguments: str) -> bytes:
    flags = 0x08 | 0x20 | 0x80
    header = struct.pack(
        "<I16sIIQQQIIIHHII",
        0x4C,
        bytes.fromhex("0114020000000000c000000000000046"),
        flags, 0x20, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
    )

    def counted(value: str) -> bytes:
        return struct.pack("<H", len(value)) + value.encode("utf-16-le")

    return header + counted(relative_path) + counted(arguments) + b"\x00\x00\x00\x00"


def make_pdf(body: bytes) -> bytes:
    return b"%PDF-1.7\n1 0 obj\n" + body + b"\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"


def encoded_command(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def make_pyinstaller(scripts: dict, modules: dict, encrypt: tuple = ()) -> bytes:
    import marshal
    import zlib

    def code(source: str) -> bytes:
        return marshal.dumps(compile(source, "<sample>", "exec"))

    pyz_body = b""
    toc = []
    header = 12
    for name, source in modules.items():
        blob = b"\x00garbled" * 8 if name in encrypt else zlib.compress(code(source))
        toc.append((name, (0, header + len(pyz_body), len(blob))))
        pyz_body += blob
    pyz = b"PYZ\x00" + b"\x55\x0d\x0d\x0a" + struct.pack("!i", header + len(pyz_body)) + pyz_body
    pyz += marshal.dumps(toc)

    entries = [(name, zlib.compress(code(source)), b"s") for name, source in scripts.items()]
    entries.append(("PYZ-00.pyz", pyz, b"z"))
    package = b""
    toc_bytes = b""
    for name, blob, kind in entries:
        compressed = 1 if kind == b"s" else 0
        raw_name = name.encode() + b"\x00"
        raw_name += b"\x00" * (-(18 + len(raw_name)) % 16)
        toc_bytes += struct.pack("!iIIIBc", 18 + len(raw_name), len(package), len(blob), len(blob),
                                 compressed, kind) + raw_name
        package += blob
    toc_offset = len(package)
    package += toc_bytes
    cookie = struct.pack("!8sIIii64s", b"MEI\x0c\x0b\x0a\x0b\x0e", len(package) + 88, toc_offset,
                         len(toc_bytes), 312, b"python312.dll")
    return make_pe({"kernel32.dll": ["GetModuleFileNameW", "LoadLibraryW", "GetProcAddress", "CreateProcessW",
                                     "GetCommandLineW", "ExitProcess", "GetLastError", "SetDllDirectoryW"]},
                   extra=b"") + package + cookie


def make_asar(files: dict) -> bytes:
    import json
    tree: dict = {"files": {}}
    body = b""
    for path, content in files.items():
        node = tree
        parts = path.split("/")
        for part in parts[:-1]:
            node = node["files"].setdefault(part, {"files": {}})
        node["files"][parts[-1]] = {"size": len(content), "offset": str(len(body))}
        body += content
    header = json.dumps(tree).encode()
    padded = header + b"\x00" * (-len(header) % 4)
    pickle = struct.pack("<II", len(padded) + 4, len(header)) + padded
    return struct.pack("<II", 4, len(pickle)) + pickle + body
