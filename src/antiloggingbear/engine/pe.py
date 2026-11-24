# Anti-Logging Bear by Priest

from __future__ import annotations

import re

import pefile

from . import capabilities as cap
from . import dotnet
from . import indicators as ioc
from .findings import Finding, Severity
from .generic import entropy, extension

API_CAPABILITIES: dict[str, list[str]] = {
    cap.KEYS: ["setwindowshookexa", "setwindowshookexw", "getasynckeystate",
               "registerrawinputdevices", "getrawinputdata"],
    cap.NETWORK: ["internetopena", "internetopenw", "internetopenurla", "internetopenurlw",
                  "internetconnecta", "internetconnectw", "httpsendrequesta", "httpsendrequestw",
                  "winhttpopen", "winhttpconnect", "winhttpsendrequest", "urldownloadtofilea",
                  "urldownloadtofilew", "wsastartup", "connect", "send", "getaddrinfo",
                  "gethostbyname", "ftpputfilea", "ftpputfilew"],
    cap.CLIPBOARD: ["getclipboarddata"],
    cap.SCREENSHOT: ["bitblt", "printwindow"],
    cap.INJECTION: ["virtualallocex", "writeprocessmemory", "createremotethread",
                    "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread"],
    cap.HOLLOWING: ["ntunmapviewofsection", "zwunmapviewofsection"],
    cap.CREDENTIALS: ["cryptunprotectdata", "credenumeratea", "credenumeratew"],
}
PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
_API_LOOKUP = {api: name for name, apis in API_CAPABILITIES.items() for api in apis}
_DOWNLOAD_API = {"urldownloadtofilea", "urldownloadtofilew"}
_EXEC_API = {"shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw", "winexec",
             "createprocessa", "createprocessw"}
_REMOTE_WRITE = {"writeprocessmemory"}
_REMOTE_THREAD = {"createremotethread", "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread"}
_STRING_APIS = re.compile(
    r"\b(SetWindowsHookEx[AW]?|GetAsyncKeyState|RegisterRawInputDevices|GetClipboardData"
    r"|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|ZwUnmapViewOfSection"
    r"|CryptUnprotectData|URLDownloadToFile[AW]?|InternetOpenUrl[AW]?|WinHttpOpen|HttpClient|WebClient"
    r"|SmtpClient|UploadValues|UploadString|UploadFile)\b"
)
_PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".mpress1": "MPRESS",
    ".mpress2": "MPRESS", ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".enigma1": "Enigma", ".enigma2": "Enigma", ".petite": "Petite",
    "pec2": "PECompact", ".nsp0": "NsPack", ".packed": "generic packer", ".boom": "The Boomerang",
}
_NET_STRING_MAP = {
    "HttpClient": cap.NETWORK, "WebClient": cap.NETWORK, "SmtpClient": cap.NETWORK,
    "UploadValues": cap.NETWORK, "UploadString": cap.NETWORK, "UploadFile": cap.NETWORK,
}


def analyze_pe(path: str, data: bytes, children: list | None = None, depth: int = 0, walker=None) -> list[Finding]:
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
        ])
    except pefile.PEFormatError as exc:
        return [Finding(path, "pe.malformed", Severity.HIGH,
                        "Damaged or deliberately malformed program - Barry can't inspect it", str(exc))]

    findings: list[Finding] = []
    caps = cap.Capabilities()
    imports = _imports(pe)
    strings = ioc.extract_strings(data)

    for api in sorted(imports):
        target = _API_LOOKUP.get(api)
        if target:
            caps.add(target, api)
    if imports & _DOWNLOAD_API and imports & _EXEC_API:
        caps.add(cap.DOWNLOAD_EXEC, "URLDownloadToFile + process start")

    named = set(imports)
    for m in _STRING_APIS.finditer(strings):
        name = m.group(1)
        lowered = name.lower()
        named.add(lowered)
        target = _NET_STRING_MAP.get(name) or _API_LOOKUP.get(lowered) or _API_LOOKUP.get(lowered + "w")
        if target and lowered not in imports:
            caps.add(target, name + " (by name)")

    for endpoint in ioc.exfil_endpoints(strings):
        caps.add(cap.EXFIL, endpoint)
    marker = ioc.keylog_marker(strings)
    if marker:
        caps.add(cap.KEYLOG_MARKER, marker)
    m = ioc.BROWSER_SECRETS.search(strings)
    if m:
        caps.add(cap.CREDENTIALS, m.group())
    if ioc.discord_token(strings):
        caps.add(cap.CREDENTIALS, "Discord token pattern")
    for pattern in (ioc.RUN_KEY, ioc.STARTUP_FOLDER):
        m = pattern.search(strings)
        if m:
            caps.add(cap.PERSISTENCE, m.group())
    m = ioc.DEFENDER_TAMPER.search(strings)
    if m:
        caps.add(cap.DEFENDER_TAMPER, m.group())
    # Loaders and trainers import one or two of these; real injection needs a remote write and a remote thread.
    if not (named & _REMOTE_WRITE and named & _REMOTE_THREAD):
        caps.discard(cap.INJECTION)

    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0:
        findings.extend(dotnet.analyze(path, data, caps, _API_LOOKUP, children, depth, walker))
    if not caps.trusted:
        findings.extend(cap.assess(path, caps, "pe"))
    findings.extend(_structure(path, pe, data, imports))
    if pyinstaller_like(data):
        findings = [f for f in findings if f.check not in ("pe.overlay",)]

    urls = ioc.find_urls(strings)
    if urls:
        target = findings[0] if findings else None
        if target is not None and target.severity >= Severity.MEDIUM:
            target.indicators.extend(u for u in urls if u not in target.indicators)
    if extension(path) == "asi" and any(f.severity >= Severity.HIGH for f in findings):
        findings.append(Finding(path, "pe.asi", Severity.INFO,
                                "This is an ASI mod - your game loads it automatically on start"))
    pe.close()
    return findings


def overlay_start(data: bytes) -> int:
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return len(data)
    end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections), default=len(data))
    pe.close()
    return min(end, len(data))


def pyinstaller_like(data: bytes) -> bool:
    return PYINSTALLER_MAGIC in data


def _imports(pe: pefile.PE) -> set[str]:
    names: set[str] = set()
    for attr in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in getattr(pe, attr, []) or []:
            for imp in entry.imports:
                if imp.name:
                    names.add(imp.name.decode("ascii", "ignore").lower())
    return names


def _structure(path: str, pe: pefile.PE, data: bytes, imports: set[str]) -> list[Finding]:
    out: list[Finding] = []
    packers: list[str] = []
    dense = 0
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("latin-1").lower()
        if name in _PACKER_SECTIONS:
            packers.append(_PACKER_SECTIONS[name])
        raw = section.get_data()
        is_code = section.Characteristics & 0x20000000
        if is_code and len(raw) > 4096 and entropy(raw) > 7.3:
            dense += 1

    dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
    if packers:
        out.append(Finding(path, "pe.packed", Severity.HIGH,
                           "Program is packed with {} - Barry can't see what's inside".format(
                               ", ".join(sorted(set(packers)))),
                           "Packing hides a program's real code. Some honest tools use it, but most "
                           "malware does."))
    elif dense and not dotnet:
        out.append(Finding(path, "pe.encrypted-code", Severity.HIGH,
                           "Program's code is scrambled or encrypted - Barry can't see what's inside",
                           f"{dense} code section(s) look like random data."))
    elif not dotnet and len(imports) < 8 and imports & {"getprocaddress", "loadlibrarya", "loadlibraryw"}:
        out.append(Finding(path, "pe.hidden-imports", Severity.MEDIUM,
                           "Program hides which Windows features it uses",
                           f"Only {len(imports)} imports, loaded by name at run time."))

    overlay = pe.get_overlay_data_start_offset()
    signed = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0
    if overlay and not signed and len(data) - overlay > max(1024 * 1024, len(data) // 2):
        overlay_entropy = entropy(data[overlay:overlay + 1024 * 1024])
        if overlay_entropy > 7.5:
            out.append(Finding(path, "pe.overlay", Severity.MEDIUM,
                               "Carries a large encrypted payload after its code",
                               "Installers do this too; packed malware does it a lot."))

    if signed:
        out.append(Finding(path, "pe.signed", Severity.INFO,
                           "Has a digital signature (not verified - Barry doesn't unpack files to check it)"))
    elif extension(path) in ("exe", "scr", "msi", "sys"):
        out.append(Finding(path, "pe.unsigned", Severity.INFO, "Program is not digitally signed"))

    if dotnet:
        out.append(Finding(path, "pe.dotnet", Severity.INFO, ".NET program (Barry read its code references)"))
    if extension(path) == "scr":
        out.append(Finding(path, "pe.screensaver", Severity.MEDIUM,
                           "Screensaver file - these are programs and a classic way to sneak in malware"))
    return out
