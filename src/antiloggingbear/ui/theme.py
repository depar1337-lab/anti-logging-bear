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
    clean: tuple
    warn: tuple
    danger: tuple


FOREST = Palette(
    bg="#fbf6ea", panel="#ffffff", ink="#2a2118", muted="#6b5a48", border="#e3d6bd",
    header="#24492e", header_ink="#fbf6ea", accent="#2f6b3a", accent_active="#24532d",
    accent_ink="#ffffff", focus="#c98b00", select="#dcebd6",
    clean=("#2f6b3a", "#e6f2e3"), warn=("#7a4f00", "#fbefd5"), danger=("#a3241c", "#f9e1de"),
)

HIGH_CONTRAST = Palette(
    bg="#000000", panel="#000000", ink="#ffffff", muted="#e0e0e0", border="#ffffff",
    header="#000000", header_ink="#ffff00", accent="#ffff00", accent_active="#ffffff",
    accent_ink="#000000", focus="#00ffff", select="#003366",
    clean=("#7CFC00", "#000000"), warn=("#ffff00", "#000000"), danger=("#ff6b6b", "#000000"),
)

FONT_NAMES = ("ALB.Body", "ALB.Small", "ALB.Bold", "ALB.Title", "ALB.Heading", "ALB.Verdict", "ALB.Mono")
_BASE_SIZES = {"ALB.Body": 10, "ALB.Small": 9, "ALB.Bold": 10, "ALB.Title": 18, "ALB.Heading": 13,
               "ALB.Verdict": 17, "ALB.Mono": 9}


def font_family() -> str:
    if sys.platform == "win32":
        return "Segoe UI"
    if sys.platform == "darwin":
        return "Helvetica Neue"
    return "DejaVu Sans"


def mono_family() -> str:
    return {"win32": "Consolas", "darwin": "Menlo"}.get(sys.platform, "DejaVu Sans Mono")


class Theme:
    def __init__(self, root: tk.Misc, high_contrast: bool = False, large_text: bool = False) -> None:
        self.root = root
        self.style = ttk.Style(root)
        self.style.theme_use("clam")
        self.palette = FOREST
        self.scale = 1.0
        self.fonts = {name: tkfont.Font(root, name=name, exists=name in tkfont.names(root)) for name in FONT_NAMES}
        self.apply(high_contrast, large_text)

    def apply(self, high_contrast: bool, large_text: bool) -> None:
        self.palette = HIGH_CONTRAST if high_contrast else FOREST
        self.scale = 1.25 if large_text else 1.0
        family = font_family()
        for name, size in _BASE_SIZES.items():
            weight = "bold" if name in ("ALB.Bold", "ALB.Title", "ALB.Heading", "ALB.Verdict") else "normal"
            self.fonts[name].configure(
                family=mono_family() if name == "ALB.Mono" else family,
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
                    family=font_family(), size=round(10 * self.scale))

        s.configure(".", background=p.bg, foreground=p.ink, font="ALB.Body", bordercolor=p.border,
                    focuscolor=p.focus, lightcolor=p.bg, darkcolor=p.bg, troughcolor=p.border,
                    selectbackground=p.select, selectforeground=p.ink, insertcolor=p.ink)
        s.configure("TFrame", background=p.bg)
        s.configure("Card.TFrame", background=p.panel, relief="solid", borderwidth=1)
        s.configure("Panel.TFrame", background=p.panel)
        s.configure("Header.TFrame", background=p.header)
        s.configure("TLabel", background=p.bg, foreground=p.ink)
        s.configure("Card.TLabel", background=p.panel, foreground=p.ink)
        s.configure("Muted.TLabel", background=p.bg, foreground=p.muted, font="ALB.Small")
        s.configure("CardMuted.TLabel", background=p.panel, foreground=p.muted)
        s.configure("Heading.TLabel", background=p.panel, foreground=p.ink, font="ALB.Heading")
        s.configure("HeaderTitle.TLabel", background=p.header, foreground=p.header_ink, font="ALB.Title")
        s.configure("HeaderSub.TLabel", background=p.header, foreground=p.header_ink, font="ALB.Body")
        s.configure("Status.TLabel", background=p.bg, foreground=p.muted, font="ALB.Small")

        s.configure("TButton", background=p.panel, foreground=p.ink, padding=(12, 6), relief="flat",
                    borderwidth=1, focusthickness=2, focuscolor=p.focus)
        s.map("TButton", background=[("active", p.select), ("disabled", p.bg)],
              foreground=[("disabled", p.muted)], bordercolor=[("focus", p.focus)])
        s.configure("Accent.TButton", background=p.accent, foreground=p.accent_ink, font="ALB.Bold",
                    bordercolor=p.accent)
        s.map("Accent.TButton", background=[("active", p.accent_active), ("disabled", p.border)],
              bordercolor=[("focus", p.focus)])
        s.configure("Danger.TButton", background=p.danger[0], foreground="#ffffff" if p is FOREST else "#000000",
                    font="ALB.Bold", bordercolor=p.danger[0])
        s.map("Danger.TButton", background=[("active", p.ink)], bordercolor=[("focus", p.focus)])
        s.configure("Header.TButton", background=p.header, foreground=p.header_ink, bordercolor=p.header_ink,
                    padding=(10, 4))
        s.map("Header.TButton", background=[("active", p.accent)], bordercolor=[("focus", p.focus)])

        for name in ("TCheckbutton", "TRadiobutton"):
            s.configure(name, background=p.bg, foreground=p.ink, indicatorbackground=p.panel,
                        indicatorforeground=p.ink, focuscolor=p.focus)
            s.map(name, background=[("active", p.bg)], indicatorbackground=[("selected", p.accent)],
                  indicatorforeground=[("selected", p.accent_ink)])
        s.configure("Header.TCheckbutton", background=p.header, foreground=p.header_ink)
        s.map("Header.TCheckbutton", background=[("active", p.header)])

        s.configure("TEntry", fieldbackground=p.panel, foreground=p.ink, bordercolor=p.border)
        s.map("TEntry", bordercolor=[("focus", p.focus)])
        s.configure("TSpinbox", fieldbackground=p.panel, foreground=p.ink, arrowcolor=p.ink)
        s.configure("TNotebook", background=p.bg, borderwidth=0)
        s.configure("TNotebook.Tab", background=p.border, foreground=p.ink, padding=(12, 5))
        s.map("TNotebook.Tab", background=[("selected", p.panel)], foreground=[("selected", p.ink)])
        s.configure("Treeview", background=p.panel, fieldbackground=p.panel, foreground=p.ink,
                    rowheight=round(24 * self.scale), bordercolor=p.border)
        s.map("Treeview", background=[("selected", p.select)], foreground=[("selected", p.ink)])
        s.configure("Treeview.Heading", background=p.border, foreground=p.ink, font="ALB.Bold", relief="flat")
        s.configure("Horizontal.TProgressbar", background=p.accent, troughcolor=p.border, bordercolor=p.border,
                    lightcolor=p.accent, darkcolor=p.accent)
        s.configure("TScrollbar", background=p.border, troughcolor=p.bg, arrowcolor=p.ink)
        s.configure("TLabelframe", background=p.bg, bordercolor=p.border)
        s.configure("TLabelframe.Label", background=p.bg, foreground=p.ink, font="ALB.Bold")
