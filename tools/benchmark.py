# Anti-Logging Bear by Priest

from __future__ import annotations

import argparse
import collections
import io
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from antiloggingbear.engine import ScanOptions, Verdict  # noqa: E402
from antiloggingbear.engine.scanner import scan_data, scan_path  # noqa: E402

API = "https://mb-api.abuse.ch/api/v1/"
FAMILIES = ["AgentTesla", "SnakeKeylogger", "RedLineStealer", "LummaStealer", "Vidar", "Stealc", "AsyncRAT",
            "XWorm", "RemcosRAT", "QuasarRAT", "DCRat", "NjRAT", "Formbook", "BlankGrabber", "Phemedrone",
            "RisePro", "MetaStealer", "Amadey"]
MAX_SAMPLE = 60 * 1024 * 1024
PASSWORD = b"infected"


def query(key: str, fields: dict) -> dict:
    request = urllib.request.Request(API, data=urllib.parse.urlencode(fields).encode("ascii"),
                                     headers={"Auth-Key": key, "User-Agent": "BarryBear-benchmark"})
    with urllib.request.urlopen(request, timeout=120) as resp:
        body = resp.read(MAX_SAMPLE + 1)
    if fields.get("query") == "get_file":
        return {"zip": body}
    return json.loads(body.decode("utf-8"))


def sample_bytes(key: str, sha256: str) -> tuple[str, bytes] | None:
    import pyzipper
    blob = query(key, {"query": "get_file", "sha256_hash": sha256})["zip"]
    if not blob.startswith(b"PK") or len(blob) > MAX_SAMPLE:
        return None
    with pyzipper.AESZipFile(io.BytesIO(blob)) as archive:
        archive.setpassword(PASSWORD)
        name = archive.namelist()[0]
        return name, archive.read(name)


def malware(key: str, per_family: int, options: ScanOptions) -> dict:
    results = collections.defaultdict(collections.Counter)
    misses = []
    for family in FAMILIES:
        try:
            listing = query(key, {"query": "get_siginfo", "signature": family, "limit": str(per_family)})
        except Exception as exc:
            print(f"{family}: lookup failed ({exc})")
            continue
        for item in (listing.get("data") or [])[:per_family]:
            sha256 = item.get("sha256_hash", "")
            try:
                sample = sample_bytes(key, sha256)
            except Exception as exc:
                print(f"  {sha256[:16]} download failed ({exc})")
                continue
            if sample is None:
                continue
            name, data = sample
            report = scan_data(name, data, options)
            del data
            results[family][report.verdict.value] += 1
            if report.verdict is Verdict.CLEAN:
                misses.append({"family": family, "sha256": sha256, "name": name, "type": item.get("file_type")})
            print(f"  {family:15} {report.verdict.value:10} {item.get('file_type', ''):6} {sha256[:16]}", flush=True)
            time.sleep(0.5)
    return {"families": {f: dict(c) for f, c in results.items()}, "misses": misses}


def clean(folders: list, limit: int, options: ScanOptions) -> dict:
    counts = collections.Counter()
    flagged = []
    seen = 0
    for folder in folders:
        for root, _dirs, files in os.walk(folder):
            for filename in files:
                if not filename.lower().endswith((".exe", ".dll")) or seen >= limit:
                    continue
                path = os.path.join(root, filename)
                try:
                    if os.path.getsize(path) > 200 * 1024 * 1024:
                        continue
                    report = scan_path(path, options)
                except (OSError, ValueError):
                    continue
                seen += 1
                counts[report.verdict.value] += 1
                if report.verdict is not Verdict.CLEAN:
                    flagged.append({"path": path, "verdict": report.verdict.value,
                                    "why": [f.title for f in report.ranked()[:3]]})
    return {"verdicts": dict(counts), "flagged": flagged}


def summary(result: dict) -> str:
    lines = ["# Barry benchmark", ""]
    if "malware" in result:
        lines += ["## Real malware (MalwareBazaar)", "", "| Family | Dangerous | Suspicious | Missed |", "|---|---|---|---|"]
        total = collections.Counter()
        for family, counts in sorted(result["malware"]["families"].items()):
            total.update(counts)
            lines.append(f"| {family} | {counts.get('dangerous', 0)} | {counts.get('suspicious', 0)} | "
                         f"{counts.get('clean', 0)} |")
        caught = total["dangerous"] + total["suspicious"]
        all_samples = caught + total["clean"]
        if all_samples:
            lines += ["", f"Caught {caught} of {all_samples} ({caught * 100 / all_samples:.0f}%), "
                          f"{total['dangerous']} as Dangerous."]
    if "clean" in result:
        verdicts = result["clean"]["verdicts"]
        checked = sum(verdicts.values())
        wrong = checked - verdicts.get("clean", 0)
        lines += ["", "## Clean software on this PC", "",
                  f"{checked} programs checked, {wrong} false alarm(s) ({wrong * 100 / max(checked, 1):.1f}%)."]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure Barry on real malware and clean software")
    parser.add_argument("--per-family", type=int, default=15)
    parser.add_argument("--clean", nargs="*", default=[], help="folders of trusted programs to check")
    parser.add_argument("--clean-limit", type=int, default=400)
    parser.add_argument("--out", default="benchmark")
    args = parser.parse_args()
    options = ScanOptions(use_antivirus=False)
    result = {}
    key = os.environ.get("MB_API_KEY", "")
    if not key:
        from antiloggingbear import settings as config
        key = config.load().mb_api_key
    if key:
        result["malware"] = malware(key, args.per_family, options)
    else:
        print("No MalwareBazaar key (MB_API_KEY or Barry's settings) - skipping the malware samples")
    if args.clean:
        result["clean"] = clean(args.clean, args.clean_limit, options)
    out = Path(args.out)
    out.with_suffix(".json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    out.with_suffix(".md").write_text(summary(result), encoding="utf-8")
    print(summary(result))


if __name__ == "__main__":
    main()
