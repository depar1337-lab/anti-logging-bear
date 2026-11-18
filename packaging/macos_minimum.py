# Anti-Logging Bear by Priest

import struct
import sys
from pathlib import Path

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MACHO_64 = 0xFEEDFACF
MACHO_32 = 0xFEEDFACE
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
PLATFORM_MACOS = 1


def parse_version(text):
    parts = [int(part) for part in text.split(".")] + [0, 0]
    return tuple(parts[:3])


def decode(packed):
    return (packed >> 16, (packed >> 8) & 0xFF, packed & 0xFF)


def slice_minimums(data, offset):
    magic = struct.unpack_from("<I", data, offset)[0]
    if magic not in (MACHO_64, MACHO_32):
        return []
    header_size = 32 if magic == MACHO_64 else 28
    ncmds = struct.unpack_from("<I", data, offset + 16)[0]
    cursor = offset + header_size
    found = []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, cursor)
        if cmd == LC_BUILD_VERSION:
            platform, minos = struct.unpack_from("<II", data, cursor + 8)
            if platform == PLATFORM_MACOS:
                found.append(decode(minos))
        elif cmd == LC_VERSION_MIN_MACOSX:
            found.append(decode(struct.unpack_from("<I", data, cursor + 8)[0]))
        if size == 0:
            break
        cursor += size
    return found


def minimums(path):
    data = path.read_bytes()
    if len(data) < 32:
        return []
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack_from(">I", data, 4)[0]
        entry, offset_format = (32, ">Q") if magic == FAT_MAGIC_64 else (20, ">I")
        found = []
        for index in range(count):
            offset = struct.unpack_from(offset_format, data, 8 + index * entry + 8)[0]
            found.extend(slice_minimums(data, offset))
        return found
    return slice_minimums(data, 0)


def dotted(version):
    return ".".join(map(str, version))


def main():
    bundle, target = Path(sys.argv[1]), parse_version(sys.argv[2])
    optional = sys.argv[3:]
    newest = (0, 0, 0)
    too_new = []
    for path in sorted(p for p in bundle.rglob("*") if p.is_file() and not p.is_symlink()):
        relative = path.relative_to(bundle).as_posix()
        for version in minimums(path):
            if version <= target:
                newest = max(newest, version)
            elif any(marker in relative for marker in optional):
                print("optional, needs " + dotted(version) + ": " + relative)
            else:
                too_new.append((relative, version))
    print("newest macOS needed by the app: " + dotted(newest))
    for relative, version in too_new:
        print("  needs " + dotted(version) + ": " + relative)
    return 1 if too_new else 0


if __name__ == "__main__":
    sys.exit(main())
