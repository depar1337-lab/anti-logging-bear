# Anti-Logging Bear by Priest

from __future__ import annotations

import contextlib
import fnmatch
import os
import threading
from typing import Callable, Iterable, Tuple

PARTIAL_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp", ".!ut", ".aria2")
INTERESTING = {
    "zip", "jar", "exe", "dll", "asi", "scr", "com", "pif", "msi", "cpl", "sys",
    "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "url", "scf", "reg",
    "py", "pyw", "lua", "luac", "cs", "cleo", "sh", "command",
    "doc", "docm", "docx", "dot", "dotm", "xls", "xlsm", "xlsb", "xlsx", "ppt", "pptm", "pptx", "rtf", "pdf",
    "7z", "rar", "gz",
}

Signature = Tuple[int, int]


class FolderWatcher(threading.Thread):
    def __init__(self, folders: Iterable[str], on_ready: Callable[[str], None],
                 exclusions: Iterable[str] = (), all_types: bool = False, interval: float = 2.0) -> None:
        super().__init__(name="download-watcher", daemon=True)
        self.folders: list[str] = [f for f in folders if f]
        self.on_ready = on_ready
        self.exclusions = [e.lower() for e in exclusions if e]
        self.all_types = all_types
        self.interval = interval
        self._halt = threading.Event()
        self._done: dict[str, Signature] = {}
        self._pending: dict[str, Signature] = {}

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        for path, sig in self._listing():
            self._done[path] = sig
        while not self._halt.wait(self.interval):
            self.poll()

    def poll(self) -> None:
        current = dict(self._listing())
        for path in list(self._pending):
            if path not in current:
                del self._pending[path]
        for path in list(self._done):
            if path not in current:
                del self._done[path]

        for path, sig in current.items():
            if self._done.get(path) == sig:
                continue
            if self._pending.get(path) != sig:
                self._pending[path] = sig
                continue
            if sig[0] == 0 or not _readable(path):
                continue
            del self._pending[path]
            self._done[path] = sig
            with contextlib.suppress(Exception):
                self.on_ready(path)

    def _listing(self):
        for folder in self.folders:
            try:
                entries = list(os.scandir(folder))
            except OSError:
                continue
            for entry in entries:
                name = entry.name
                lowered = name.lower()
                if lowered.endswith(PARTIAL_SUFFIXES) or lowered.startswith((".", "~$")):
                    continue
                if not self.all_types and lowered.rsplit(".", 1)[-1] not in INTERESTING:
                    continue
                if any(fnmatch.fnmatch(lowered, pattern) for pattern in self.exclusions):
                    continue
                try:
                    if not entry.is_file():
                        continue
                    st = entry.stat()
                except OSError:
                    continue
                yield entry.path, (st.st_size, int(st.st_mtime))


def _readable(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False
