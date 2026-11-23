# Anti-Logging Bear by Priest

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from .findings import Severity

BUNDLE_NAME = "forge.bin"
_RULE_START = re.compile(r"(?m)^(?=(?:private |global )*rule \w+)")
_RULE_NAME = re.compile(r"(?:private |global )*rule (\w+)")
_WORD = re.compile(r"\w+")
_UNSUPPORTED = re.compile(r'(?:invalid field name|undefined identifier|unknown module|invalid argument)\s*"([\w.]+)"')
_FEATURE_PROBES = {
    "pe.number_of_signatures": 'import "pe" rule probe { condition: pe.number_of_signatures > 0 }',
    "pe.signatures": 'import "pe" rule probe { condition: pe.signatures[0].issuer == "" }',
    "pe.is_signed": 'import "pe" rule probe { condition: pe.is_signed }',
    "pe.imphash": 'import "pe" rule probe { condition: pe.imphash() == "" }',
    "hash.": 'import "hash" rule probe { condition: hash.md5(0, 1) == "" }',
    "dotnet.": 'import "dotnet" rule probe { condition: dotnet.number_of_resources > 0 }',
    "math.": 'import "math" rule probe { condition: math.entropy(0, 1) > 0 }',
    "string.": 'import "string" rule probe { condition: string.length("a") == 1 }',
    "console.": 'import "console" rule probe { condition: console.log("") }',
    "elf.": 'import "elf" rule probe { condition: elf.type == 0 }',
}
TOOL_WORDS = {"HKTL", "HACKTOOL", "PUA", "SUSP", "SUSPICIOUS", "GEN", "GENERIC", "EXPL", "EXPLOIT", "TOOL",
              "TOOLS", "OFFENSIVE", "PENTEST", "REDTEAM", "METASPLOIT", "COBALTSTRIKE_BEACON_SUSP"}
MALWARE_WORDS = {"MAL", "MALW", "MALWARE", "APT", "STEALER", "INFOSTEALER", "RAT", "RANSOM", "RANSOMWARE",
                 "BACKDOOR", "LOADER", "TROJAN", "CRYPTER", "WEBSHELL", "KEYLOGGER", "BANKER", "BOTNET",
                 "DROPPER", "WORM", "MINER", "COINMINER", "GRABBER", "MALPEDIA"}
PLATFORMS = {"win": "Windows", "osx": "macOS", "elf": "Linux", "apk": "Android", "js": "JavaScript",
             "ps1": "PowerShell", "py": "Python", "jar": "Java"}
_MALPEDIA = re.compile(r"malpedia[^\s\"']*/details/(\w+)\.(\w+)")


@dataclass
class Bundle:
    release: str
    source: str
    core: frozenset

    @property
    def rule_count(self) -> int:
        return len(_RULE_START.findall(self.source))


def build_bundle(full_zip: bytes, core_zip: bytes, release: str) -> bytes:
    full = _zip_rules(full_zip)
    core = _zip_rules(core_zip)
    core_names = sorted({m.group(1) for m in _RULE_NAME.finditer(core)})
    payload = json.dumps({"release": release, "core": core_names, "source": full}).encode("utf-8")
    return zlib.compress(payload, 9)


def read_bundle(blob: bytes) -> Bundle:
    payload = json.loads(zlib.decompress(blob).decode("utf-8"))
    return Bundle(str(payload["release"]), str(payload["source"]), frozenset(payload.get("core") or []))


def newest_bundle(*paths: Path) -> tuple[Path, Bundle] | None:
    best = None
    for path in paths:
        try:
            bundle = read_bundle(path.read_bytes())
        except (OSError, ValueError, KeyError, zlib.error):
            continue
        if best is None or bundle.release > best[1].release:
            best = (path, bundle)
    return best


def compile_bundle(yara, bundle: Bundle, cache_dir: Path | None):
    digest = hashlib.sha256(bundle.source.encode("utf-8")).hexdigest()[:16]
    version = getattr(yara, "__version__", "x").replace(".", "")
    cache = cache_dir / f"forge-{bundle.release}-{digest}-{version}.yarc" if cache_dir else None
    if cache is not None and cache.exists():
        try:
            return yara.load(str(cache)), _cached_count(cache)
        except yara.Error:
            pass

    missing = [feature for feature, probe in _FEATURE_PROBES.items() if not _compiles(yara, probe)]
    blocks = _RULE_START.split(bundle.source)
    head, blocks = blocks[0], blocks[1:]
    for feature in missing:
        if feature.endswith(".") and not _compiles(yara, f'import "{feature[:-1]}"'):
            head = _drop_import(head, feature[:-1])
    kept = _without_dependents([b for b in blocks if not any(feature in b for feature in missing)], blocks)
    rules = None
    last_error = ""
    for _attempt in range(300):
        try:
            rules = yara.compile(source=head + "".join(kept))
            break
        except yara.SyntaxError as exc:
            last_error = str(exc)
            culprit = _UNSUPPORTED.search(last_error)
            if culprit:
                name = culprit.group(1)
                if "unknown module" in last_error:
                    head = _drop_import(head, name)
                    name += "."
                fewer = _without_dependents([b for b in kept if name not in _condition(b)], blocks)
                if len(fewer) < len(kept) or "unknown module" in last_error:
                    kept = fewer
                    continue
            index = _block_at_line(head, kept, last_error)
            if index is None:
                raise
            kept.pop(index)
    if rules is None:
        raise RuntimeError("too many community rules failed to compile: " + last_error[:120])
    if cache is not None:
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            for old in cache_dir.glob("forge-*.yarc"):
                old.unlink()
            rules.save(str(cache))
            cache.with_suffix(".count").write_text(str(len(kept)), encoding="ascii")
        except (OSError, yara.Error):
            pass
    return rules, len(kept)


def grade(name: str, meta: dict, core: frozenset) -> tuple[Severity, str, str]:
    words = set(name.upper().split("_"))
    trusted = name in core
    description = str(meta.get("description") or "")
    family = _family(meta)
    if not description or "autogenerated" in description.lower() or "yara-signator" in description.lower():
        description = family or name.replace("_", " ")
    if words & TOOL_WORDS:
        return Severity.MEDIUM, "Matches a hacking tool or suspicious pattern: " + description, "tool"
    if words & MALWARE_WORDS or family:
        severity = Severity.CRITICAL if trusted else Severity.HIGH
        label = family or description
        return severity, "Matches known malware: " + label, "malware"
    return (Severity.HIGH if trusted else Severity.MEDIUM), "Matches a community YARA rule: " + description, "other"


def _family(meta: dict) -> str:
    for key in ("reference", "malpedia_reference", "source_url"):
        match = _MALPEDIA.search(str(meta.get(key) or ""))
        if match:
            platform, family = match.groups()
            return f"{family.replace('_', ' ').title()} ({PLATFORMS.get(platform, platform)})"
    return ""


def _zip_rules(blob: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".yar"))
        return archive.read(name).decode("utf-8")


def _without_dependents(kept: list, everything: list) -> list:
    rules = [(_RULE_NAME.match(b).group(1), b) for b in kept]
    dropped = {_RULE_NAME.match(b).group(1) for b in everything} - {name for name, _b in rules}
    if not dropped:
        return kept
    words = {name: set(_WORD.findall(_condition(block))) for name, block in rules}
    while dropped:
        survivors = [(name, block) for name, block in rules if not words[name] & dropped]
        dropped = {name for name, _b in rules} - {name for name, _b in survivors}
        rules = survivors
    return [block for _name, block in rules]


def _drop_import(head: str, module: str) -> str:
    return re.sub(r'(?m)^\s*import\s+"' + re.escape(module) + r'"\s*$', "", head)


def _condition(block: str) -> str:
    index = block.rfind("condition:")
    return block[index:] if index >= 0 else ""


def _compiles(yara, source: str) -> bool:
    try:
        yara.compile(source=source)
        return True
    except yara.Error:
        return False


def _block_at_line(head: str, blocks: list, message: str):
    match = re.search(r"line (\d+)", message)
    if not match:
        return None
    line = int(match.group(1))
    seen = head.count("\n")
    for index, block in enumerate(blocks):
        seen += block.count("\n")
        if seen >= line:
            return index
    return None


def _cached_count(cache: Path) -> int:
    try:
        return int(cache.with_suffix(".count").read_text(encoding="ascii"))
    except (OSError, ValueError):
        return 0
