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
    def __init__(self, master: tk.Misc, theme: Theme, on_click, height: int = 160) -> None:
        super().__init__(master, height=height, highlightthickness=0, borderwidth=2, relief="sunken",
                         takefocus=1, cursor="hand2")
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
        self.configure(background=p.field)
        self.delete("all")
        if self.hover:
            self.create_rectangle(6, 6, w - 6, h - 6, outline="", fill=p.clean[1] if p.field != "#000000" else p.field)
        self.create_rectangle(10, 10, w - 10, h - 10, outline=p.accent if p.accent != "#000000" else p.ink,
                              width=1, dash=(4, 3))
        if focused:
            self.create_rectangle(5, 5, w - 5, h - 5, outline=p.focus, width=1, dash=(1, 2))
        self.create_text(w / 2, h / 2 - 20, text="Drop a download here", fill=p.ink, font="ALB.Heading")
        self.create_text(w / 2, h / 2 + 6, text="Barry checks zips, programs, scripts and documents",
                         fill=p.muted, font="ALB.Body")
        self.create_text(w / 2, h / 2 + 26, text="without unzipping or running anything.",
                         fill=p.muted, font="ALB.Body")


class TitleBar(tk.Canvas):
    def __init__(self, master: tk.Misc, theme: Theme, text: str = "") -> None:
        super().__init__(master, highlightthickness=0, borderwidth=0)
        self.theme = theme
        self.text = text
        self.bind("<Configure>", lambda _e: self.redraw())
        self.retheme()

    def set_text(self, text: str) -> None:
        self.text = text
        self.redraw()

    def retheme(self) -> None:
        self.configure(height=round(22 * self.theme.scale))
        self.redraw()

    def redraw(self) -> None:
        p = self.theme.palette
        w, h = max(self.winfo_width(), 1), max(self.winfo_height(), 1)
        self.delete("all")
        start, end = _rgb(self, p.title), _rgb(self, p.title_end)
        step = 4
        for x in range(0, w, step):
            t = x / max(w - 1, 1)
            colour = "#" + "".join(f"{round(a + (b - a) * t):02x}" for a, b in zip(start, end))
            self.create_rectangle(x, 0, x + step, h, fill=colour, outline="")
        self.create_text(6, h / 2, text=self.text, anchor="w", fill=p.title_ink, font="ALB.Bold")


class Window(tk.Frame):
    def __init__(self, master: tk.Misc, theme: Theme, title: str = "", padding: int = 12) -> None:
        super().__init__(master, borderwidth=2, relief="raised", highlightthickness=0)
        self.theme = theme
        self.title_bar = TitleBar(self, theme, title)
        self.title_bar.pack(fill="x", padx=1, pady=1)
        self.body = ttk.Frame(self, style="Panel.TFrame", padding=padding)
        self.body.pack(fill="both", expand=True)
        self.retheme()

    def set_title(self, text: str) -> None:
        self.title_bar.set_text(text)

    def retheme(self) -> None:
        self.configure(background=self.theme.palette.panel)
        self.title_bar.retheme()


class BlockProgress(tk.Canvas):
    BLOCK, GAP = 9, 2

    def __init__(self, master: tk.Misc, theme: Theme) -> None:
        super().__init__(master, height=round(22 * theme.scale), highlightthickness=0, borderwidth=2,
                         relief="sunken")
        self.theme = theme
        self.position = 0
        self._job = None
        self.bind("<Configure>", lambda _e: self.redraw())

    def start(self, interval: int = 60) -> None:
        self.stop()
        self.position = 0

        def tick() -> None:
            width = max(self.winfo_width() - 8, 1)
            self.position = 0 if self.position >= width else self.position + self.BLOCK + self.GAP
            self.redraw()
            self._job = self.after(max(interval * 5, 60), tick)

        tick()

    def stop(self) -> None:
        if self._job is not None:
            self.after_cancel(self._job)
            self._job = None

    def redraw(self) -> None:
        p = self.theme.palette
        h = self.winfo_height()
        self.configure(background=p.field)
        self.delete("all")
        fill = p.accent if p.accent != "#000000" else p.select
        x = 4
        while x + self.BLOCK <= 4 + self.position:
            self.create_rectangle(x, 4, x + self.BLOCK, h - 4, fill=fill, outline="")
            x += self.BLOCK + self.GAP


def _rgb(widget: tk.Misc, colour: str) -> tuple:
    r, g, b = widget.winfo_rgb(colour)
    return r // 256, g // 256, b // 256


class WrapLabel(ttk.Label):
    def __init__(self, master: tk.Misc, **kwargs) -> None:
        super().__init__(master, **kwargs)
        self.bind("<Configure>", lambda e: self.configure(wraplength=max(e.width - 4, 100)))


def copy_to_clipboard(widget: tk.Misc, text: str) -> None:
    widget.clipboard_clear()
    widget.clipboard_append(text)
