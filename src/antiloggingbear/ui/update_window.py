# Anti-Logging Bear by Priest

from __future__ import annotations

import sys
import threading
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

from .. import __version__, app_updates
from .widgets import BlockProgress, Window

if TYPE_CHECKING:
    from ..app import Application


class UpdateWindow(tk.Toplevel):
    def __init__(self, app: Application, update: app_updates.Update) -> None:
        super().__init__(app.root)
        self.app = app
        self.update_info = update
        self.title("Update available")
        self.configure(background=app.theme.palette.bg)
        self.resizable(False, False)
        self.transient(app.root)

        frame = Window(self, app.theme, f"Barry Bear {update.version} is available", padding=14)
        frame.pack(fill="both", expand=True, padx=8, pady=8)
        body = frame.body
        body.columnconfigure(0, weight=1)
        ttk.Label(body, text=f"You have version {__version__}. Here's what's new:", style="Card.TLabel").grid(
            row=0, column=0, sticky="w")

        notes = tk.Text(body, width=64, height=12, wrap="word", relief="sunken", borderwidth=2,
                        font="ALB.Body", background=app.theme.palette.field, foreground=app.theme.palette.ink,
                        highlightthickness=0, padx=6, pady=4)
        notes.insert("1.0", _plain(update.notes) or "See the release page for details.")
        notes.configure(state="disabled")
        notes.grid(row=1, column=0, sticky="nsew", pady=(6, 10))

        self.message = ttk.Label(body, text=self._explain(), style="CardMuted.TLabel", wraplength=480,
                                 justify="left")
        self.message.grid(row=2, column=0, sticky="w")
        self.progress = BlockProgress(body, app.theme)

        buttons = ttk.Frame(body, style="Panel.TFrame")
        buttons.grid(row=4, column=0, sticky="e", pady=(12, 0))
        primary = "Update now" if update.installable else "Download"
        self.primary = ttk.Button(buttons, text=primary, style="Accent.TButton", command=self._go)
        self.later = ttk.Button(buttons, text="Later", command=self.destroy)
        self.skip = ttk.Button(buttons, text="Skip this version", command=self._skip)
        self.skip.pack(side="left")
        self.later.pack(side="left", padx=8)
        self.primary.pack(side="left")
        self.bind("<Escape>", lambda _e: self.destroy())
        self.primary.focus_set()
        self.lift()

    def _explain(self) -> str:
        update = self.update_info
        if update.installable:
            return ("Barry will download the update, check its fingerprint, then close, install it and "
                    "start again. Your settings, history and quarantine are kept.")
        if sys.platform == "darwin":
            return "Barry will download the new Mac app. Open it and drag Barry into Applications to replace this one."
        return "This copy of Barry can't update itself, so Barry will open the download for you."

    def _go(self) -> None:
        update = self.update_info
        if not update.installable:
            app_updates.open_in_browser(update.url or update.page)
            self.destroy()
            return
        for button in (self.primary, self.later, self.skip):
            button.state(["disabled"])
        self.message.configure(text="Downloading the update...")
        self.progress.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        self.progress.start(12)
        threading.Thread(target=self._download, name="update", daemon=True).start()

    def _download(self) -> None:
        def progress(done: int, total: int) -> None:
            if total:
                self.app.post(lambda: self.message.configure(
                    text=f"Downloading the update... {done * 100 // total}%"))

        try:
            installer = app_updates.download(self.update_info, progress)
        except Exception as exc:
            reason = str(exc)
            self.app.post(lambda: self._failed(reason))
            return
        self.app.post(lambda: self._install(installer))

    def _install(self, installer) -> None:
        self.progress.stop()
        self.message.configure(text="Installing. Barry will be back in a moment.")
        self.update_idletasks()
        try:
            app_updates.run_installer(installer)
        except OSError as exc:
            self._failed(str(exc))
            return
        self.app.quit()

    def _failed(self, reason: str) -> None:
        self.progress.stop()
        self.progress.grid_forget()
        self.message.configure(text=f"The update didn't work: {reason}. Nothing was changed.")
        for button in (self.primary, self.later, self.skip):
            button.state(["!disabled"])
        self.primary.configure(text="Try again")

    def _skip(self) -> None:
        self.app.settings.skipped_version = self.update_info.version
        self.app.save_settings()
        self.destroy()


def _plain(markdown: str) -> str:
    markdown = markdown.replace("\r", "")
    start = markdown.lower().find("## what's new")
    if start >= 0:
        markdown = markdown[start:]
    lines = []
    for line in markdown.splitlines():
        line = line.strip()
        if line.startswith("|") or set(line) <= {"-", "|", " "} and line:
            continue
        line = line.lstrip("#").strip().replace("**", "").replace("`", "")
        lines.append(line)
    text = "\n".join(lines)
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text.strip()
