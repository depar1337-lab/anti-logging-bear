# Anti-Logging Bear by Priest

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
PACKAGE = ROOT / "src" / "antiloggingbear"
CACHE = ROOT / ".cache" / "web"

PYODIDE_VERSION = "314.0.7"
PYODIDE_SHA256 = "66b7949e5a0cba2250b586d7e368bf12fb482800748d182c4618254b685ffaa0"
PYODIDE_URL = f"https://registry.npmjs.org/pyodide/-/pyodide-{PYODIDE_VERSION}.tgz"
PYODIDE_FILES = ("pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json")
PYODIDE_PACKAGES = ("pyyaml",)
PYODIDE_CDN = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/"

STATIC_FILES = ("index.html", "app.css", "app.js", "worker.js", "manifest.webmanifest")
ENGINE_SOURCES = ("__init__.py", "report.py", "engine/*.py")
SKIP_IN_WHEELS = ("/tests/", ".dist-info/RECORD")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the Anti-Logging Bear web app")
    parser.add_argument("--out", default=str(ROOT / "build" / "web"), help="output folder")
    args = parser.parse_args()

    out = Path(args.out).resolve()
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    for name in STATIC_FILES:
        shutil.copy2(WEB / name, out / name)
    shutil.copytree(WEB / "icons", out / "icons")
    images = out / "img"
    shutil.copytree(WEB / "img", images)
    for png in sorted((PACKAGE / "assets").glob("barry-*.png")):
        shutil.copy2(png, images / png.name)
    shutil.copy2(PACKAGE / "assets" / "forest.png", images / "forest.png")

    _write_pyodide(out / "pyodide")
    (out / "py").mkdir()
    (out / "py" / "barry.zip").write_bytes(_python_bundle())
    _write_service_worker(out)
    print(f"web app written to {out}")


def _download(url: str, target: Path, sha256: str) -> bytes:
    if target.exists():
        data = target.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise SystemExit(f"checksum mismatch for {url}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return data


def _write_pyodide(target: Path) -> None:
    data = _download(PYODIDE_URL, CACHE / f"pyodide-{PYODIDE_VERSION}.tgz", PYODIDE_SHA256)
    target.mkdir()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for name in PYODIDE_FILES:
            member = tar.extractfile(f"package/{name}")
            if member is None:
                raise SystemExit(f"{name} missing from the Pyodide package")
            (target / name).write_bytes(member.read())
    lock = json.loads((target / "pyodide-lock.json").read_text(encoding="utf-8"))["packages"]
    for name in PYODIDE_PACKAGES:
        entry = lock[name]
        if entry["depends"]:
            raise SystemExit(f"{name} has dependencies; add them to PYODIDE_PACKAGES")
        wheel = _download(PYODIDE_CDN + entry["file_name"], CACHE / entry["file_name"], entry["sha256"])
        (target / entry["file_name"]).write_bytes(wheel)


def _wheels() -> list[Path]:
    folder = CACHE / "wheels"
    folder.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [sys.executable, "-m", "pip", "download", "--quiet", "--only-binary", ":all:", "--no-deps",
         "--dest", str(folder), "--requirement", str(WEB / "requirements.txt")],
        check=True,
    )
    wanted = {_normalise(line.split("==")[0]) for line in (WEB / "requirements.txt").read_text().split()}
    return sorted(w for w in folder.glob("*.whl") if _normalise(w.name.split("-")[0]) in wanted)


def _normalise(name: str) -> str:
    return name.lower().replace("-", "_")


def _python_bundle() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as bundle:
        for pattern in ENGINE_SOURCES:
            for source in sorted(PACKAGE.glob(pattern)):
                bundle.write(source, "antiloggingbear/" + source.relative_to(PACKAGE).as_posix())
        bundle.write(WEB / "barry_web.py", "barry_web.py")
        for wheel in _wheels():
            with zipfile.ZipFile(wheel) as zf:
                for info in zf.infolist():
                    if not any(skip in "/" + info.filename for skip in SKIP_IN_WHEELS):
                        bundle.writestr(info.filename, zf.read(info))
    return buf.getvalue()


def _write_service_worker(out: Path) -> None:
    files = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    digest = hashlib.sha256()
    for name in files:
        digest.update(name.encode())
        digest.update((out / name).read_bytes())
    template = (WEB / "sw.js").read_text(encoding="utf-8")
    script = (template.replace("__CACHE_NAME__", "barry-" + digest.hexdigest()[:12])
              .replace("__PRECACHE__", json.dumps(["./"] + files)))
    (out / "sw.js").write_text(script, encoding="utf-8")


if __name__ == "__main__":
    main()
