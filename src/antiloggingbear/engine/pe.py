# Anti-Logging Bear by Priest

from __future__ import annotations

import re

import pefile

from . import authenticode, dotnet
from . import capabilities as cap
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
_SET_CONTEXT = {"setthreadcontext", "wow64setthreadcontext"}
_REMOTE_THREAD = {"createremotethread", "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread"}
_STRING_APIS = re.compile(
    r"\b(SetWindowsHookEx[AW]?|GetAsyncKeyState|RegisterRawInputDevices|GetClipboardData"
    r"|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|ZwUnmapViewOfSection"
    r"|SetThreadContext|Wow64SetThreadContext"
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


def analyze_pe(path: str, data: bytes, children: list | None = None, depth: int = 0, walker=None,
               source: str = "") -> list[Finding]:
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
    if not imports & {"ntunmapviewofsection", "zwunmapviewofsection"} and not named & _SET_CONTEXT:
        caps.discard(cap.HOLLOWING)

    if _chromium_runtime(data, strings):
        caps.discard(cap.CREDENTIALS)
        findings.append(Finding(path, "pe.chromium", Severity.INFO,
                                "Built on the Chromium browser engine (like Chrome, Edge and Electron apps)",
                                "Chromium contains its own cookie and password code, so Barry judges the app by "
                                "its own code instead, such as the app.asar file next to it."))
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0:
        findings.extend(dotnet.analyze(path, data, caps, _API_LOOKUP, children, depth, walker))
    signature = None
    if pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0 and source and authenticode.supported():
        signature = authenticode.verify_file(source)
    verified = signature is not None and signature.status == authenticode.VALID
    lowered = []
    if not caps.trusted:
        assessed = cap.assess(path, caps, "pe")
        findings.extend(assessed)
        lowered.extend(assessed)
    structure = _structure(path, pe, data, imports, signature)
    findings.extend(structure)
    lowered.extend(f for f in structure if f.check in _SIGNABLE_STRUCTURE)
    if verified:
        for finding in lowered:
            if finding.severity > Severity.INFO:
                finding.severity = Severity(int(finding.severity) - 1)
                finding.detail = (finding.detail + " " if finding.detail else "") + \
                    f"(Lowered one step: signed by {signature.signer or 'a trusted publisher'}.)"
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


_SIGNABLE_STRUCTURE = {"pe.packed", "pe.encrypted-code", "pe.hidden-imports", "pe.overlay"}


def _chromium_runtime(data: bytes, strings: str) -> bool:
    if len(data) < 30 * 1024 * 1024:
        return False
    markers = ("Chromium", "chrome_elf", "content_shell", "Electron", "CEF_VERSION", "libcef")
    return sum(1 for marker in markers if marker in strings) >= 2


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


def _structure(path: str, pe: pefile.PE, data: bytes, imports: set[str], signature=None) -> list[Finding]:
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

    status = signature.status if signature is not None else authenticode.UNKNOWN
    who = signature.signer if signature is not None and signature.signer else "an unknown publisher"
    if signed and status == authenticode.VALID:
        out.append(Finding(path, "pe.signed", Severity.INFO, f"Signed by {who} (signature checked by Windows)"))
    elif signed and status == authenticode.TAMPERED:
        out.append(Finding(path, "pe.signature-broken", Severity.HIGH,
                           "Its digital signature doesn't match - the program was changed after it was signed",
                           "Tampered installers are a common way to slip malware into real software."))
    elif signed and status == authenticode.DISTRUSTED:
        out.append(Finding(path, "pe.signature-revoked", Severity.HIGH,
                           f"Signed with a certificate Windows has revoked or blocked ({who})",
                           "Certificates are revoked when they're stolen or used to sign malware."))
    elif signed and status == authenticode.UNTRUSTED:
        out.append(Finding(path, "pe.signature-untrusted", Severity.MEDIUM,
                           f"Signed by {who}, but Windows doesn't trust the certificate",
                           "Self-made or expired certificates prove nothing about who made the program."))
    elif signed:
        out.append(Finding(path, "pe.signed", Severity.INFO,
                           "Has a digital signature (Barry can only check signatures on Windows, for files "
                           "that aren't inside an archive)"))
    elif extension(path) in ("exe", "scr", "msi", "sys"):
        out.append(Finding(path, "pe.unsigned", Severity.INFO, "Program is not digitally signed"))

    if dotnet:
        out.append(Finding(path, "pe.dotnet", Severity.INFO, ".NET program (Barry read its code references)"))
    if extension(path) == "scr":
        out.append(Finding(path, "pe.screensaver", Severity.MEDIUM,
                           "Screensaver file - these are programs and a classic way to sneak in malware"))
    return out
