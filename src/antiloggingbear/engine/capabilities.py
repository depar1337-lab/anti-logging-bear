# Anti-Logging Bear by Priest

from __future__ import annotations

from typing import Iterable

from .findings import Finding, Severity

KEYS = "keys"
KEYLOG_MARKER = "keylog_marker"
EXFIL = "exfil"
NETWORK = "network"
LOG_FILE = "log_file"
CREDENTIALS = "credentials"
CLIPBOARD = "clipboard"
SCREENSHOT = "screenshot"
INJECTION = "injection"
HOLLOWING = "hollowing"
PERSISTENCE = "persistence"
DEFENDER_TAMPER = "defender_tamper"
DOWNLOAD_EXEC = "download_exec"
DIALOG_INPUT = "dialog_input"


class Capabilities:
    def __init__(self) -> None:
        self._evidence: dict[str, list[str]] = {}
        self.trusted = False

    def add(self, cap: str, evidence: str) -> None:
        bucket = self._evidence.setdefault(cap, [])
        if evidence not in bucket:
            bucket.append(evidence)

    def add_all(self, cap: str, evidence: Iterable[str]) -> None:
        for item in evidence:
            self.add(cap, item)

    def mark_trusted(self) -> None:
        self.trusted = True

    def discard(self, cap: str) -> None:
        self._evidence.pop(cap, None)

    def has(self, *caps: str) -> bool:
        return all(c in self._evidence for c in caps)

    def any(self, *caps: str) -> bool:
        return any(c in self._evidence for c in caps)

    def evidence(self, *caps: str) -> list[str]:
        out: list[str] = []
        for cap in caps:
            for item in self._evidence.get(cap, []):
                if item not in out:
                    out.append(item)
        return out

    def __bool__(self) -> bool:
        return bool(self._evidence)


def assess(path: str, caps: Capabilities, prefix: str) -> list[Finding]:
    out: list[Finding] = []

    def emit(check: str, severity: Severity, title: str, *evidence_caps: str) -> None:
        evidence = caps.evidence(*evidence_caps)
        out.append(
            Finding(
                path=path,
                check=f"{prefix}.{check}",
                severity=severity,
                title=title,
                detail="Evidence: " + ", ".join(evidence[:12]) if evidence else "",
                indicators=[e for e in evidence if "/" in e and "." in e][:10],
            )
        )

    keys = caps.has(KEYS)
    marker = caps.has(KEYLOG_MARKER)
    online = caps.any(NETWORK, EXFIL)

    if keys and caps.has(EXFIL):
        emit("keylogger", Severity.CRITICAL,
             "Can record your keystrokes and send them to an outside server",
             KEYS, KEYLOG_MARKER, EXFIL)
    elif keys and marker and online:
        emit("keylogger", Severity.CRITICAL,
             "Looks like a keylogger: records keystrokes and can send them over the internet",
             KEYS, KEYLOG_MARKER, NETWORK)
    elif marker and online:
        emit("keylog-text", Severity.HIGH,
             "Contains keylogger-style text and can connect to the internet",
             KEYLOG_MARKER, NETWORK)
    elif keys and marker:
        emit("keylogger", Severity.HIGH,
             "Looks like a keylogger: records keystrokes in a log format",
             KEYS, KEYLOG_MARKER, LOG_FILE)
    elif keys and caps.has(LOG_FILE):
        emit("keys-file", Severity.MEDIUM,
             "Reads keyboard input and appends to a file (some mods do this for settings)", KEYS, LOG_FILE)
    elif keys and online:
        emit("keys-online", Severity.MEDIUM,
             "Reads keyboard input and can connect to the internet "
             "(fine for mods with hotkeys and update checks, but worth a look)",
             KEYS, NETWORK)
    elif marker:
        emit("keylog-text", Severity.MEDIUM,
             "Contains text typical of keyloggers", KEYLOG_MARKER)
    elif keys:
        emit("keys", Severity.LOW,
             "Reads keyboard input (normal for games and hotkey mods)", KEYS)

    if caps.has(CREDENTIALS):
        if online:
            emit("stealer", Severity.CRITICAL,
                 "Looks for saved passwords, cookies or tokens and can send them out",
                 CREDENTIALS, EXFIL, NETWORK)
        else:
            emit("credentials", Severity.HIGH,
                 "Looks for saved browser passwords, cookies or Discord tokens", CREDENTIALS)

    if caps.has(DIALOG_INPUT):
        if caps.has(EXFIL):
            emit("dialog-stealer", Severity.CRITICAL,
                 "Reads what you type into server login dialogs and sends it to an outside server",
                 DIALOG_INPUT, EXFIL)
        elif caps.has(NETWORK):
            emit("dialog-online", Severity.MEDIUM,
                 "Reads server login dialogs and can connect to the internet", DIALOG_INPUT, NETWORK)

    if caps.has(EXFIL) and not keys and not caps.any(CREDENTIALS, DIALOG_INPUT):
        tunnels_only = all("ngrok" in item.lower() for item in caps.evidence(EXFIL))
        emit("exfil", Severity.MEDIUM if tunnels_only else Severity.HIGH,
             "Connects to a public tunnel service (used by remote-access tools, and by developers)"
             if tunnels_only else "Sends data to a webhook, chat bot or paste site", EXFIL)

    if caps.has(CLIPBOARD) and caps.has(EXFIL):
        emit("clipboard", Severity.HIGH,
             "Reads your clipboard and can send it to an outside server", CLIPBOARD, EXFIL)
    elif caps.has(CLIPBOARD) and online:
        emit("clipboard", Severity.LOW,
             "Reads the clipboard and can connect to the internet (normal for apps with paste)",
             CLIPBOARD, NETWORK)

    if caps.has(SCREENSHOT) and caps.has(EXFIL):
        emit("screenshots", Severity.HIGH,
             "Takes screenshots and can send them to an outside server", SCREENSHOT, EXFIL)

    if caps.has(HOLLOWING):
        emit("hollowing", Severity.CRITICAL,
             "Can hollow out another program and run hidden code inside it", HOLLOWING)
    elif caps.has(INJECTION):
        risky = caps.any(CREDENTIALS, EXFIL, DOWNLOAD_EXEC) or (keys and marker)
        emit("injection", Severity.HIGH if risky else Severity.MEDIUM,
             "Can inject code into other running programs (used by trainers and by malware)",
             INJECTION)

    if caps.has(PERSISTENCE):
        risky = caps.any(KEYS, CREDENTIALS, EXFIL, DOWNLOAD_EXEC)
        emit("persistence", Severity.HIGH if risky else Severity.MEDIUM,
             "Sets itself up to run every time your computer starts", PERSISTENCE)

    if caps.has(DEFENDER_TAMPER):
        emit("av-tamper", Severity.CRITICAL,
             "Tries to switch off antivirus protection or delete system backups",
             DEFENDER_TAMPER)

    if caps.has(DOWNLOAD_EXEC):
        emit("dropper", Severity.HIGH,
             "Downloads something from the internet and runs it", DOWNLOAD_EXEC)

    return out
