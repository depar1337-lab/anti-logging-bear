# Anti-Logging Bear by Priest

from __future__ import annotations

import argparse
import hashlib
import io
import os
import platform
import struct
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache" / "tools"
OUTPUT = ROOT / "src" / "antiloggingbear" / "bin"
BASE = "https://github.com/ip7z/7zip/releases/download/26.06/"
PACKAGES = {
    "win-x64": ("7z2606-x64.exe", "9b697f65ecc2d9b0152f5ee96d72dde522a7827690349d9307935dacf40f42ec"),
    "win-x86": ("7z2606.exe", "5e38f80c3752de43887e7a99ad10668c14bf64dcc929a636510b54616ea7dec7"),
    "mac-arm64": ("7z2606-mac.tar.xz", "b6f17920b4240940461dac8ef4009891881ac44d2a5ead625ede2ec8472185dd"),
    "mac-x64": ("7z2606-mac-x64.tar.xz", "3af68b124052da7fc2a246c96b0bea6a68bfee389baa788f4cead1a133445586"),
}


def current_target() -> str:
    if sys.platform == "win32":
        return "win-x64" if struct.calcsize("P") == 8 else "win-x86"
    if sys.platform == "darwin":
        return "mac-arm64" if platform.machine() == "arm64" else "mac-x64"
    raise SystemExit("Barry only bundles 7-Zip for Windows and macOS builds")


def fetch(name: str, sha256: str) -> bytes:
    target = CACHE / name
    if target.exists():
        data = target.read_bytes()
    else:
        request = urllib.request.Request(BASE + name, headers={"User-Agent": "BarryBear-build"})
        with urllib.request.urlopen(request, timeout=120) as resp:
            data = resp.read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise SystemExit(f"checksum mismatch for {name}")
    CACHE.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return data


def windows_files(installer: Path) -> dict:
    tar = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "tar.exe"
    files = {}
    for name in ("7z.exe", "7z.dll", "License.txt"):
        files[name] = subprocess.run([str(tar), "-xOf", str(installer), name], check=True,
                                     capture_output=True).stdout
        if not files[name]:
            raise SystemExit(f"couldn't read {name} from the 7-Zip installer")
    return files


def mac_files(bundle: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:xz") as archive:
        return {"7zz": archive.extractfile("7zz").read(),
                "License.txt": archive.extractfile("License.txt").read()}


def main() -> None:
    parser = argparse.ArgumentParser(description="Bundle 7-Zip for opening installers and archives")
    parser.add_argument("--target", choices=sorted(PACKAGES), default=None)
    args = parser.parse_args()
    target = args.target or current_target()
    name, sha256 = PACKAGES[target]
    data = fetch(name, sha256)
    files = windows_files(CACHE / name) if target.startswith("win") else mac_files(data)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for old in OUTPUT.iterdir():
        if old.is_file():
            old.unlink()
    for filename, content in files.items():
        out = OUTPUT / ("7-Zip-License.txt" if filename == "License.txt" else filename)
        out.write_bytes(content)
        if filename == "7zz":
            out.chmod(0o755)
    print(f"7-Zip 26.06 for {target} -> {OUTPUT} ({', '.join(sorted(files))})")


if __name__ == "__main__":
    main()
