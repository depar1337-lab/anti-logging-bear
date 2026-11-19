# Anti-Logging Bear by Priest

from __future__ import annotations

import contextlib
import sys
import tkinter as tk
from dataclasses import dataclass
from tkinter import font as tkfont
from tkinter import ttk

from ..engine.findings import Severity, Verdict


@dataclass(frozen=True)
class Palette:
    bg: str
    panel: str
    field: str
    ink: str
    muted: str
    border: str
    header: str
    header_ink: str
    accent: str
    accent_active: str
    accent_ink: str
    focus: str
    select: str
    select_ink: str
    title: str
    title_end: str
    title_ink: str
    clean: tuple
    warn: tuple
    danger: tuple


FOREST = Palette(
    bg="#efe5d2", panel="#efe5d2", field="#ffffff", ink="#2a2118", muted="#6b5a48", border="#b3a181",
    header="#24492e", header_ink="#fbf6ea", accent="#2f6b3a", accent_active="#3b7d47",
    accent_ink="#ffffff", focus="#2a2118", select="#2f6b3a", select_ink="#ffffff",
    title="#24492e", title_end="#4f8a5a", title_ink="#ffffff",
    clean=("#2f6b3a", "#e6f2e3"), warn=("#7a4f00", "#fbefd5"), danger=("#a3241c", "#f9e1de"),
)

HIGH_CONTRAST = Palette(
    bg="#000000", panel="#000000", field="#000000", ink="#ffffff", muted="#e0e0e0", border="#ffffff",
    header="#000000", header_ink="#ffff00", accent="#000000", accent_active="#333333",
    accent_ink="#ffff00", focus="#00ffff", select="#ffff00", select_ink="#000000",
    title="#000080", title_end="#000080", title_ink="#ffffff",
    clean=("#7CFC00", "#000000"), warn=("#ffff00", "#000000"), danger=("#ff6b6b", "#000000"),
)

FONT_NAMES = ("ALB.Body", "ALB.Small", "ALB.Bold", "ALB.Title", "ALB.Heading", "ALB.Verdict", "ALB.Mono")
_BASE_SIZES = {"ALB.Body": 9, "ALB.Small": 8, "ALB.Bold": 9, "ALB.Title": 15, "ALB.Heading": 10,
               "ALB.Verdict": 14, "ALB.Mono": 9}
_FAMILIES = ("Tahoma", "Verdana", "Geneva", "DejaVu Sans")
_MONO = ("Lucida Console", "Monaco", "Consolas", "Menlo", "DejaVu Sans Mono")


def _first_available(root: tk.Misc, names: tuple) -> str:
    installed = {name.lower() for name in tkfont.families(root)}
    for name in names:
        if name.lower() in installed:
            return name
    return "TkDefaultFont"


class Theme:
    def __init__(self, root: tk.Misc, high_contrast: bool = False, large_text: bool = False) -> None:
        self.root = root
        self.style = ttk.Style(root)
        self.style.theme_use("alt")
        self.palette = FOREST
        self.scale = 1.0
        self.family = _first_available(root, _FAMILIES)
        self.mono = _first_available(root, _MONO)
        self.fonts = {name: tkfont.Font(root, name=name, exists=name in tkfont.names(root)) for name in FONT_NAMES}
        self.apply(high_contrast, large_text)

    def apply(self, high_contrast: bool, large_text: bool) -> None:
        self.palette = HIGH_CONTRAST if high_contrast else FOREST
        self.scale = 1.25 if large_text else 1.0
        for name, size in _BASE_SIZES.items():
            weight = "bold" if name in ("ALB.Bold", "ALB.Title", "ALB.Heading", "ALB.Verdict") else "normal"
            self.fonts[name].configure(
                family=self.mono if name == "ALB.Mono" else self.family,
                size=round(size * self.scale), weight=weight)
        self._configure_styles()

    def verdict_colours(self, verdict: Verdict) -> tuple:
        p = self.palette
        return {Verdict.CLEAN: p.clean, Verdict.SUSPICIOUS: p.warn, Verdict.DANGEROUS: p.danger}[verdict]

    def severity_colour(self, severity: Severity) -> str:
        p = self.palette
        if severity >= Severity.CRITICAL:
            return p.danger[0]
        if severity >= Severity.HIGH:
            return p.danger[0] if p is HIGH_CONTRAST else "#b4471a"
        if severity >= Severity.MEDIUM:
            return p.warn[0]
        return p.muted

    def _configure_styles(self) -> None:
        p, s = self.palette, self.style
        self.root.configure(background=p.bg)
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
            with contextlib.suppress(tk.TclError):
                tkfont.Font(self.root, name=name, exists=True).configure(
                    family=self.family, size=round(9 * self.scale))
        if sys.platform != "darwin":
            self.root.option_add("*Menu.relief", "raised")

        s.configure(".", background=p.bg, foreground=p.ink, font="ALB.Body", bordercolor=p.border,
                    focuscolor=p.focus, troughcolor=p.border, fieldbackground=p.field,
                    selectbackground=p.select, selectforeground=p.select_ink, insertcolor=p.ink)
        s.configure("TFrame", background=p.bg)
        s.configure("Card.TFrame", background=p.panel)
        s.configure("Panel.TFrame", background=p.panel)
        s.configure("Header.TFrame", background=p.header)
        s.configure("TLabel", background=p.bg, foreground=p.ink)
        s.configure("Card.TLabel", background=p.panel, foreground=p.ink)
        s.configure("Muted.TLabel", background=p.bg, foreground=p.muted, font="ALB.Small")
        s.configure("CardMuted.TLabel", background=p.panel, foreground=p.muted)
        s.configure("Heading.TLabel", background=p.panel, foreground=p.ink, font="ALB.Heading")
        s.configure("HeaderTitle.TLabel", background=p.header, foreground=p.header_ink, font="ALB.Title")
        s.configure("HeaderSub.TLabel", background=p.header, foreground=p.header_ink, font="ALB.Small")
        s.configure("Status.TLabel", background=p.bg, foreground=p.muted, font="ALB.Small")

        s.configure("TButton", background=p.bg, foreground=p.ink, padding=(10, 3), relief="raised",
                    borderwidth=2, focuscolor=p.focus, anchor="center")
        s.map("TButton", background=[("pressed", p.bg), ("active", p.bg), ("disabled", p.bg)],
              foreground=[("disabled", p.muted)], relief=[("pressed", "sunken")])
        s.configure("Accent.TButton", background=p.accent, foreground=p.accent_ink, font="ALB.Bold")
        s.map("Accent.TButton", background=[("pressed", p.accent), ("active", p.accent_active)],
              relief=[("pressed", "sunken")])
        s.configure("Danger.TButton", background=p.danger[0], foreground="#ffffff" if p is FOREST else "#000000",
                    font="ALB.Bold")
        s.map("Danger.TButton", background=[("active", p.danger[0])], relief=[("pressed", "sunken")])
        s.configure("Header.TButton", background=p.header, foreground=p.header_ink, padding=(10, 3),
                    focuscolor=p.header_ink)
        s.map("Header.TButton", background=[("pressed", p.header), ("active", "#2f5c39" if p is FOREST else p.header)],
              relief=[("pressed", "sunken")])

        for name in ("TCheckbutton", "TRadiobutton"):
            s.configure(name, background=p.bg, foreground=p.ink, indicatorbackground=p.field,
                        indicatorforeground=p.ink, focuscolor=p.focus, indicatormargin=(0, 0, 6, 0))
            s.map(name, background=[("active", p.bg)], indicatorbackground=[("pressed", p.bg), ("selected", p.field)],
                  indicatorforeground=[("selected", p.ink)])

        s.configure("TEntry", fieldbackground=p.field, foreground=p.ink, borderwidth=2, relief="sunken")
        s.configure("TSpinbox", fieldbackground=p.field, foreground=p.ink, arrowcolor=p.ink, background=p.bg)
        s.configure("TCombobox", fieldbackground=p.field, foreground=p.ink, background=p.bg, arrowcolor=p.ink)
        s.configure("TNotebook", background=p.bg, borderwidth=2, tabmargins=(2, 2, 2, 0))
        s.configure("TNotebook.Tab", background=p.bg, foreground=p.ink, padding=(10, 3), borderwidth=2)
        s.map("TNotebook.Tab", background=[("selected", p.bg)], expand=[("selected", (2, 2, 2, 0))])
        s.configure("Treeview", background=p.field, fieldbackground=p.field, foreground=p.ink,
                    rowheight=round(20 * self.scale), borderwidth=2, relief="sunken")
        s.map("Treeview", background=[("selected", p.select)], foreground=[("selected", p.select_ink)])
        s.configure("Treeview.Heading", background=p.bg, foreground=p.ink, font="ALB.Body", relief="raised",
                    borderwidth=2, padding=(4, 1))
        s.map("Treeview.Heading", relief=[("pressed", "sunken")])
        s.configure("Horizontal.TProgressbar", background=p.accent, troughcolor=p.field, borderwidth=2)
        s.configure("TScrollbar", background=p.bg, troughcolor=p.border, arrowcolor=p.ink, borderwidth=2)
        s.configure("TLabelframe", background=p.bg, borderwidth=2, relief="groove")
        s.configure("TLabelframe.Label", background=p.bg, foreground=p.ink, font="ALB.Body")
