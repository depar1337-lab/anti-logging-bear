# Anti-Logging Bear by Priest
# -*- mode: python ; coding: utf-8 -*-

import os
import platform
import re
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

ROOT = Path(SPECPATH).parent
PKG = ROOT / "src" / "antiloggingbear"
IS_MAC = sys.platform == "darwin"
VERSION = re.search(r'__version__ = "(.+)"', (PKG / "__init__.py").read_text()).group(1)


def tkdnd_platform():
    system, machine = platform.system(), platform.machine()
    if system == "Windows":
        machine = os.environ.get("PROCESSOR_ARCHITECTURE", machine)
    return {
        ("Darwin", "arm64"): "osx-arm64",
        ("Darwin", "x86_64"): "osx-x64",
        ("Linux", "aarch64"): "linux-arm64",
        ("Linux", "x86_64"): "linux-x64",
        ("Windows", "ARM64"): "win-arm64",
        ("Windows", "AMD64"): "win-x64",
        ("Windows", "x86"): "win-x86",
    }.get((system, machine))


def tkdnd_wanted(target):
    parts = Path(target).parts
    if "tkdnd" not in parts or parts.index("tkdnd") == len(parts) - 1:
        return True
    folder = parts[parts.index("tkdnd") + 1]
    return folder in (TKDND, TKDND + "-tcl9")


TKDND = tkdnd_platform()

datas = [
    (str(PKG / "assets"), "antiloggingbear/assets"),
    (str(PKG / "rules"), "antiloggingbear/rules"),
]
datas += collect_data_files("tkinterdnd2")
datas += collect_data_files("oletools", includes=["**/*.txt", "**/*.json"])

hidden = ["pystray._win32"] if sys.platform == "win32" else []

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT / "src")],
    datas=datas,
    hiddenimports=hidden,
    excludes=["pytest", "numpy", "matplotlib", "IPython", "setuptools", "pip", "cryptography", "msoffcrypto",
              "PIL._avif", "PIL._webp", "PIL.ImageCms", "PIL.ImageQt", "PIL.ImageTk", "yaml", "pygments"],
    noarchive=False,
)
a.binaries = [entry for entry in a.binaries if tkdnd_wanted(entry[0])]
a.datas = [entry for entry in a.datas if tkdnd_wanted(entry[0])]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Barry Bear" if IS_MAC else "BarryBear",
    console=False,
    upx=False,
    icon=str(PKG / "assets" / ("app.icns" if IS_MAC else "app.ico")),
)

coll = COLLECT(exe, a.binaries, a.datas, upx=False, name="BarryBear")

if IS_MAC:
    app = BUNDLE(
        coll,
        name="Barry Bear.app",
        icon=str(PKG / "assets" / "app.icns"),
        bundle_identifier="com.priest.antiloggingbear",
        info_plist={
            "CFBundleShortVersionString": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": os.environ.get("MACOSX_DEPLOYMENT_TARGET", "11.0"),
            "CFBundleDocumentTypes": [{
                "CFBundleTypeName": "Download to check",
                "CFBundleTypeRole": "Viewer",
                "LSHandlerRank": "Alternate",
                "LSItemContentTypes": ["public.data", "public.item"],
            }],
        },
    )
