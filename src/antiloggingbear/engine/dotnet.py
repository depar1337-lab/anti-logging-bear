# Anti-Logging Bear by Priest

from __future__ import annotations

import hashlib
import re
import zlib

from . import capabilities as cap
from .findings import Finding, Severity

TYPE_CAPABILITIES = {
    "System.Net.Http.HttpClient": cap.NETWORK,
    "System.Net.WebClient": cap.NETWORK,
    "System.Net.HttpWebRequest": cap.NETWORK,
    "System.Net.WebRequest": cap.NETWORK,
    "System.Net.Sockets.TcpClient": cap.NETWORK,
    "System.Net.Sockets.Socket": cap.NETWORK,
    "System.Net.Mail.SmtpClient": cap.NETWORK,
    "System.Net.FtpWebRequest": cap.NETWORK,
    "System.Windows.Forms.Clipboard": cap.CLIPBOARD,
}
MEMBER_CAPABILITIES = {"CopyFromScreen": cap.SCREENSHOT}
OBFUSCATOR_MARKERS = {
    "ConfusedByAttribute": "ConfuserEx",
    "DotfuscatorAttribute": "Dotfuscator",
    "SmartAssembly.Attributes": "SmartAssembly",
    "PoweredByAttribute": "SmartAssembly",
    "BabelObfuscatorAttribute": "Babel",
    "ObfuscatedByGoliath": "Goliath",
    "Xenocode.Client.Attributes": "Xenocode",
    "YanoAttribute": "Yano",
    "CryptoObfuscator": "Crypto Obfuscator",
    "NETSpider.Attribute": ".NET Spider",
    "EMyPID_8234_": "Agile.NET",
}
FRAMEWORK_TOKENS = {
    "b77a5c561934e089", "b03f5f7f11d50a3a", "31bf3856ad364e35", "cc7b13ffcd2ddd51", "7cec85d7bea7798e",
    "adb9793829ddae60", "0738eb9f132ed756", "84e04ff9cfb79065",
}
FRAMEWORK_NAMES = {"mscorlib", "netstandard", "System", "Accessibility", "WindowsBase", "PresentationCore",
                   "PresentationFramework"}
FRAMEWORK_PREFIXES = ("System.", "Microsoft.", "Mono.", "Windows.")
_READABLE_NAME = re.compile(r"^[A-Za-z_<][\w<>`.$]*$")


def analyze(path: str, data: bytes, caps: cap.Capabilities, api_lookup: dict, children: list | None,
            depth: int, walker) -> list[Finding]:
    try:
        import dnfile
    except ImportError:
        return []
    try:
        dn = dnfile.dnPE(data=data)
    except Exception:
        return [Finding(path, "dotnet.malformed", Severity.MEDIUM,
                        ".NET program with damaged metadata - Barry could only read its text")]
    net = getattr(dn, "net", None)
    if net is None or getattr(net, "mdtables", None) is None:
        return []
    tables = net.mdtables
    findings: list[Finding] = []
    if is_framework(tables):
        caps.mark_trusted()
        dn.close()
        return [Finding(path, "dotnet.framework", Severity.INFO,
                        "Part of the .NET framework (carries Microsoft's or Mono's framework identity)")]

    for row in _rows(tables, "ImplMap"):
        name = str(row.ImportName or "")
        target = api_lookup.get(name.lower()) or api_lookup.get(name.lower() + "w")
        if target:
            caps.add(target, f"{name} (P/Invoke)")

    type_refs = set()
    for row in _rows(tables, "TypeRef"):
        full = f"{row.TypeNamespace}.{row.TypeName}" if str(row.TypeNamespace) else str(row.TypeName)
        type_refs.add(full)
        target = TYPE_CAPABILITIES.get(full)
        if target:
            caps.add(target, str(row.TypeName))
    members = {str(row.Name) for row in _rows(tables, "MemberRef")}
    for name in members:
        target = MEMBER_CAPABILITIES.get(name)
        if target:
            caps.add(target, name)
    if "System.Security.Cryptography.ProtectedData" in type_refs and "Unprotect" in members \
            and "Protect" not in members:
        caps.add(cap.CREDENTIALS, "ProtectedData.Unprotect without Protect")

    obfuscators = {label for marker, label in OBFUSCATOR_MARKERS.items()
                   if any(marker in ref for ref in type_refs)}
    names = [str(r.TypeName) for r in _rows(tables, "TypeDef")] + [str(r.Name) for r in _rows(tables, "MethodDef")]
    names = [n for n in names if n and n not in ("<Module>", ".ctor", ".cctor")]
    if len(names) >= 20:
        unreadable = sum(1 for n in names if not _READABLE_NAME.match(n))
        if unreadable / len(names) > 0.4:
            obfuscators.add("an obfuscator that renames everything")
    if obfuscators:
        findings.append(Finding(path, "dotnet.obfuscated", Severity.MEDIUM,
                                "Code is scrambled with " + " and ".join(sorted(obfuscators)),
                                "Obfuscators hide what a program does. Paid apps use them, and so does "
                                "most .NET malware."))

    for resource in getattr(net, "resources", None) or []:
        blob = getattr(resource, "data", None)
        name = str(getattr(resource, "name", "") or "resource")
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < 64:
            continue
        blob = bytes(blob)
        if name.lower().startswith("costura.") and name.lower().endswith(".compressed"):
            try:
                blob = zlib.decompressobj(-15).decompress(blob, walker.limits.max_member_bytes if walker else 1 << 28)
            except zlib.error:
                continue
            name = name[len("costura."):-len(".compressed")]
        elif blob.startswith(b"MZ"):
            findings.append(Finding(path, "dotnet.embedded-program", Severity.MEDIUM,
                                    f"Carries another program inside its resources ({name})",
                                    "Barry checks the hidden program too. Droppers use this trick."))
        if children is not None and walker is not None and blob.startswith(b"MZ"):
            child = f"{path}/[resource] {name}"
            if walker.admit(child, len(blob)):
                children.append(walker.accept(child, blob, depth))
    dn.close()
    return findings


def is_framework(tables) -> bool:
    rows = _rows(tables, "Assembly")
    if not rows:
        return False
    row = rows[0]
    name = str(getattr(row, "Name", "") or "")
    if not (name in FRAMEWORK_NAMES or name.startswith(FRAMEWORK_PREFIXES)):
        return False
    key = getattr(row, "PublicKey", None)
    key = bytes(getattr(key, "value", key) or b"")
    if not key:
        return False
    token = hashlib.sha1(key).digest()[-8:][::-1].hex()
    return token in FRAMEWORK_TOKENS


def _rows(tables, name: str) -> list:
    table = getattr(tables, name, None)
    if table is None:
        return []
    try:
        return list(table)
    except Exception:
        return []
