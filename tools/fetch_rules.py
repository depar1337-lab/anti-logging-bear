# Anti-Logging Bear by Priest

from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from antiloggingbear.engine import forge  # noqa: E402

RELEASE = "20261122"
BASE = "https://github.com/YARAHQ/yara-forge/releases/download/{}/yara-forge-rules-{}.zip"
CHECKSUMS = {
    "full": "829b07a15d58cbaabe216b83ba3291810dd863b7a82c2a8972376af471bb88f9",
    "core": "f88eb4ea361a4636021513dd71c3dfde0ca7af8d51e43ac9ccdfec9530dc3737",
}
CACHE = ROOT / ".cache" / "rules"
OUTPUT = ROOT / "src" / "antiloggingbear" / "rules" / forge.BUNDLE_NAME


def fetch(package: str) -> bytes:
    target = CACHE / f"yara-forge-{RELEASE}-{package}.zip"
    if target.exists():
        data = target.read_bytes()
    else:
        request = urllib.request.Request(BASE.format(RELEASE, package), headers={"User-Agent": "BarryBear-build"})
        with urllib.request.urlopen(request, timeout=120) as resp:
            data = resp.read()
    if hashlib.sha256(data).hexdigest() != CHECKSUMS[package]:
        raise SystemExit(f"checksum mismatch for the {package} rule package")
    CACHE.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Bundle the YARA Forge community rules")
    parser.add_argument("--out", default=str(OUTPUT))
    parser.add_argument("--compile", action="store_true",
                        help="also ship the rules precompiled for the installed yara-python")
    args = parser.parse_args()
    blob = forge.build_bundle(fetch("full"), fetch("core"), RELEASE)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    bundle = forge.read_bundle(blob)
    print(f"YARA Forge {RELEASE}: {bundle.rule_count} rules ({len(bundle.core)} core) -> {out}")
    if args.compile:
        import yara
        compiled = out.with_name(forge.COMPILED_NAME)
        compiled.write_bytes(forge.precompile(yara, bundle))
        print(f"precompiled for yara-python {yara.__version__} -> {compiled}")


if __name__ == "__main__":
    main()
