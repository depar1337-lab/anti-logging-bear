# Anti-Logging Bear by Priest

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys

from .findings import Finding, Severity

TIMEOUT = 180


def _defender_path() -> str | None:
    candidates: list[str] = []
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    platform_dirs = glob.glob(os.path.join(program_data, "Microsoft", "Windows Defender", "Platform", "*"))
    candidates.extend(os.path.join(d, "MpCmdRun.exe") for d in sorted(platform_dirs, reverse=True))
    for root in (os.environ.get("PROGRAMFILES", r"C:\Program Files"), os.environ.get("PROGRAMW6432", "")):
        if root:
            candidates.append(os.path.join(root, "Windows Defender", "MpCmdRun.exe"))
            candidates.append(os.path.join(root, "Microsoft Security Client", "MpCmdRun.exe"))
            candidates.append(os.path.join(root, "Microsoft Security Client", "Antimalware", "MpCmdRun.exe"))
    return next((c for c in candidates if os.path.isfile(c)), None)


def _clamscan_path() -> str | None:
    found = shutil.which("clamscan")
    if found:
        return found
    for candidate in ("/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan",
                      r"C:\Program Files\ClamAV\clamscan.exe"):
        if os.path.isfile(candidate):
            return candidate
    return None


def available_engine() -> str | None:
    if sys.platform == "win32" and _defender_path():
        return "Microsoft Defender"
    if _clamscan_path():
        return "ClamAV"
    return None


def scan_file(path: str) -> tuple[str, list[Finding]]:
    if sys.platform == "win32":
        exe = _defender_path()
        if exe:
            return _run_defender(exe, path)
    clam = _clamscan_path()
    if clam:
        return _run_clamav(clam, path)
    return "not available", []


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=TIMEOUT, check=False, **kwargs)


def _run_defender(exe: str, path: str) -> tuple[str, list[Finding]]:
    try:
        proc = _run([exe, "-Scan", "-ScanType", "3", "-File", os.path.abspath(path), "-DisableRemediation"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"error: {exc}", []
    output = proc.stdout.decode("utf-8", "replace").replace("\x00", "")
    if proc.returncode == 2:
        names = re.findall(r"Threat\s*:\s*(.+)", output) or ["unnamed threat"]
        return "Microsoft Defender: threat found", [
            Finding("", "av.defender", Severity.CRITICAL,
                    f"Microsoft Defender flags this download as {names[0].strip()}",
                    "; ".join(n.strip() for n in names[:5]))
        ]
    if proc.returncode == 0:
        return "Microsoft Defender: no threats", []
    return f"Microsoft Defender: unavailable (exit {proc.returncode})", []


def _run_clamav(exe: str, path: str) -> tuple[str, list[Finding]]:
    try:
        proc = _run([exe, "--no-summary", "--infected", "--scan-archive=yes", os.path.abspath(path)])
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"error: {exc}", []
    output = proc.stdout.decode("utf-8", "replace")
    if proc.returncode == 1:
        names = re.findall(r":\s*(\S+)\s+FOUND", output) or ["unnamed threat"]
        return "ClamAV: threat found", [
            Finding("", "av.clamav", Severity.CRITICAL,
                    f"ClamAV flags this download as {names[0]}", "; ".join(names[:5]))
        ]
    if proc.returncode == 0:
        return "ClamAV: no threats", []
    return f"ClamAV: error (exit {proc.returncode})", []
