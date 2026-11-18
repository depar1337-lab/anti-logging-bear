# Anti-Logging Bear by Priest
# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

ROOT = Path(SPECPATH).parent
PKG = ROOT / "src" / "antiloggingbear"
IS_MAC = sys.platform == "darwin"

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
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Anti-Logging Bear" if IS_MAC else "AntiLoggingBear",
    console=False,
    upx=False,
    icon=str(PKG / "assets" / ("app.icns" if IS_MAC else "app.ico")),
)

coll = COLLECT(exe, a.binaries, a.datas, upx=False, name="AntiLoggingBear")

if IS_MAC:
    app = BUNDLE(
        coll,
        name="Anti-Logging Bear.app",
        icon=str(PKG / "assets" / "app.icns"),
        bundle_identifier="com.priest.antiloggingbear",
        info_plist={
            "CFBundleShortVersionString": "1.0.0",
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "10.13",
            "CFBundleDocumentTypes": [{
                "CFBundleTypeName": "Download to check",
                "CFBundleTypeRole": "Viewer",
                "LSHandlerRank": "Alternate",
                "LSItemContentTypes": ["public.data", "public.item"],
            }],
        },
    )
