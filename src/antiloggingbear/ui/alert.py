# Anti-Logging Bear by Priest

from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

from ..engine.findings import ScanReport, Verdict
from ..report import plain_reasons
from .main_window import POSE_FOR_VERDICT
from .widgets import Barry, WrapLabel

if TYPE_CHECKING:
    from ..app import Application


class DownloadAlert(tk.Toplevel):
    def __init__(self, app: Application, report: ScanReport, quarantined: bool) -> None:
        super().__init__(app.root)
        self.app = app
        self.report = report
        verdict = report.verdict
        fg, _bg = app.theme.verdict_colours(verdict)
        self.title("Barry found something")
        self.configure(background=app.theme.palette.bg)
        self.resizable(False, False)
        self.attributes("-topmost", True)

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        Barry(frame, POSE_FOR_VERDICT[verdict]).grid(row=0, column=0, rowspan=4, sticky="n", padx=(0, 16))
        name = os.path.basename(report.target)
        tk.Label(frame, text=verdict.headline, font="ALB.Verdict", foreground=fg,
                 background=app.theme.palette.bg, anchor="w").grid(row=0, column=1, sticky="w")
        text = f"Barry checked your new download {name}."
        if quarantined:
            text += " It has been moved to quarantine so it can't be opened."
        WrapLabel(frame, text=text, width=46).grid(row=1, column=1, sticky="ew", pady=(4, 8))
        reasons = "\n".join("• " + line for _sev, line in plain_reasons(report, 3))
        WrapLabel(frame, text=reasons, width=46, style="Muted.TLabel").grid(row=2, column=1, sticky="ew")

        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=1, sticky="w", pady=(16, 0))
        if quarantined:
            first = ttk.Button(buttons, text="OK", style="Accent.TButton", command=self.destroy)
            first.pack(side="left")
        else:
            first = ttk.Button(buttons, text="Quarantine it", style="Danger.TButton", command=self._quarantine)
            first.pack(side="left")
        ttk.Button(buttons, text="View report", command=self._view).pack(side="left", padx=8)
        if not quarantined:
            ttk.Button(buttons, text="Ignore", command=self.destroy).pack(side="left")
        self.bind("<Escape>", lambda _e: self.destroy())
        if verdict is Verdict.DANGEROUS:
            self.bell()
        self.update_idletasks()
        x = self.winfo_screenwidth() - self.winfo_reqwidth() - 40
        y = self.winfo_screenheight() - self.winfo_reqheight() - 90
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.lift()
        first.focus_set()

    def _quarantine(self) -> None:
        if self.app.quarantine_report(self.report):
            self.destroy()

    def _view(self) -> None:
        self.app.show_window()
        self.app.window.show_result(self.report, quarantined=not os.path.exists(self.report.target))
        self.destroy()
