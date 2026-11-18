# Anti-Logging Bear by Priest

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from ..engine.findings import Verdict
from ..system import paths
from .theme import Theme

_image_cache: dict = {}


def load_image(root: tk.Misc, name: str) -> tk.PhotoImage:
    hidpi = float(root.tk.call("tk", "scaling")) > 1.7
    stem, ext = name.rsplit(".", 1)
    candidates = [f"{stem}@2x.{ext}", name] if hidpi else [name]
    for candidate in candidates:
        path = paths.asset(candidate)
        if path.exists():
            key = (id(root), candidate)
            if key not in _image_cache:
                _image_cache[key] = tk.PhotoImage(master=root, file=str(path))
            return _image_cache[key]
    raise FileNotFoundError(name)


class Barry(ttk.Label):
    POSE_TEXT = {
        "idle": "Barry the bear waving hello",
        "scan": "Barry looking through a magnifying glass",
        "happy": "Barry giving a thumbs up",
        "worried": "Barry looking worried",
        "alarm": "Barry holding a Stop the Loggers sign",
    }

    def __init__(self, master: tk.Misc, pose: str = "idle", **kwargs) -> None:
        super().__init__(master, **kwargs)
        self.pose = ""
        self.set_pose(pose)

    def set_pose(self, pose: str) -> None:
        if pose == self.pose:
            return
        self.pose = pose
        try:
            self.configure(image=load_image(self, f"barry-{pose}.png"))
        except (FileNotFoundError, tk.TclError):
            self.configure(text=self.POSE_TEXT[pose])


class VerdictIcon(tk.Canvas):
    def __init__(self, master: tk.Misc, theme: Theme, size: int = 44) -> None:
        super().__init__(master, width=size, height=size, highlightthickness=0, borderwidth=0)
        self.theme = theme
        self.size = size

    def draw(self, verdict: Verdict, background: str) -> None:
        fg, _bg = self.theme.verdict_colours(verdict)
        s = self.size
        self.configure(background=background)
        self.delete("all")
        pad = 3
        self.create_oval(pad, pad, s - pad, s - pad, fill=fg, outline="")
        mark = background if self.theme.palette.bg != "#000000" else "#000000"
        w = max(3, s // 9)
        if verdict is Verdict.CLEAN:
            self.create_line(s * .28, s * .52, s * .44, s * .68, s * .74, s * .34,
                             fill=mark, width=w, capstyle="round", joinstyle="round")
        elif verdict is Verdict.SUSPICIOUS:
            self.create_line(s / 2, s * .24, s / 2, s * .58, fill=mark, width=w, capstyle="round")
            self.create_oval(s / 2 - w / 1.4, s * .72 - w / 1.4, s / 2 + w / 1.4, s * .72 + w / 1.4,
                             fill=mark, outline="")
        else:
            self.create_line(s * .32, s * .32, s * .68, s * .68, fill=mark, width=w, capstyle="round")
            self.create_line(s * .68, s * .32, s * .32, s * .68, fill=mark, width=w, capstyle="round")


class DropZone(tk.Canvas):
    def __init__(self, master: tk.Misc, theme: Theme, on_click, height: int = 170) -> None:
        super().__init__(master, height=height, highlightthickness=2, borderwidth=0, takefocus=1,
                         cursor="hand2")
        self.theme = theme
        self.on_click = on_click
        self.hover = False
        self.bind("<Configure>", lambda _e: self.redraw())
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<Button-1>", lambda _e: self.on_click())
        self.bind("<Return>", lambda _e: self.on_click())
        self.bind("<space>", lambda _e: self.on_click())
        self.bind("<FocusIn>", lambda _e: self.redraw())
        self.bind("<FocusOut>", lambda _e: self.redraw())

    def _set_hover(self, value: bool) -> None:
        self.hover = value
        self.redraw()

    def set_drag_active(self, value: bool) -> None:
        self._set_hover(value)

    def redraw(self) -> None:
        p = self.theme.palette
        w, h = self.winfo_width(), self.winfo_height()
        focused = self.focus_get() is self
        self.configure(background=p.select if self.hover else p.panel,
                       highlightbackground=p.panel, highlightcolor=p.focus,
                       highlightthickness=2 if focused else 0)
        self.delete("all")
        self.create_rectangle(8, 8, w - 8, h - 8, outline=p.accent, width=2, dash=(8, 6))
        self.create_text(w / 2, h / 2 - 22, text="Drop a download here", fill=p.ink, font="ALB.Heading")
        self.create_text(w / 2, h / 2 + 6, text="Barry checks zips, programs, scripts and documents",
                         fill=p.muted, font="ALB.Body")
        self.create_text(w / 2, h / 2 + 30, text="without unzipping or running anything.",
                         fill=p.muted, font="ALB.Body")


class WrapLabel(ttk.Label):
    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self.bind("<Configure>", lambda e: self.configure(wraplength=max(e.width - 4, 100)))


def copy_to_clipboard(widget: tk.Misc, text: str) -> None:
    widget.clipboard_clear()
    widget.clipboard_append(text)
