# Anti-Logging Bear by Priest

from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

from .. import APP_NAME
from ..engine.findings import ScanReport, Severity, Verdict
from ..report import plain_reasons
from .widgets import (
    Barry,
    BlockProgress,
    DropZone,
    VerdictIcon,
    Window,
    WrapLabel,
    copy_to_clipboard,
    load_image,
)

if TYPE_CHECKING:
    from ..app import Application

POSE_FOR_VERDICT = {Verdict.CLEAN: "happy", Verdict.SUSPICIOUS: "worried", Verdict.DANGEROUS: "alarm"}
VERDICT_BLURB = {
    Verdict.CLEAN: "Barry didn't spot anything suspicious. No scanner can promise a file is safe, "
                   "so only run software from people you trust.",
    Verdict.SUSPICIOUS: "Something here is unusual. It might be harmless, but don't run it unless you "
                        "trust where it came from.",
    Verdict.DANGEROUS: "This download shows clear signs of malware. Don't unzip or open it - "
                       "quarantine or delete it.",
}


class MainWindow:
    def __init__(self, root: tk.Tk, app: Application) -> None:
        self.root = root
        self.app = app
        self.theme = app.theme
        self.report = None

        root.title(APP_NAME)
        root.minsize(760, 560)
        root.geometry("900x620")

        self._build_header()
        self._build_body()
        self._build_details()
        self._build_status()
        self._bind_keys()
        self.set_details_visible(app.settings.show_details)
        self.show_idle()

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, style="Header.TFrame", padding=(16, 10, 16, 0))
        header.pack(fill="x")
        self.header_icon = tk.Label(header, borderwidth=0)
        self.header_icon.pack(side="left", anchor="n", padx=(0, 10), pady=(2, 0))
        titles = ttk.Frame(header, style="Header.TFrame")
        titles.pack(side="left", anchor="w")
        ttk.Label(titles, text=APP_NAME, style="HeaderTitle.TLabel").pack(anchor="w")
        ttk.Label(titles, text="Stop the loggers. Protect your forest of files.",
                  style="HeaderSub.TLabel").pack(anchor="w", pady=(0, 4))
        buttons = ttk.Frame(header, style="Header.TFrame")
        buttons.pack(side="right", anchor="n")
        ttk.Button(buttons, text="Settings", style="Header.TButton",
                   command=self.app.open_settings).pack(side="right", padx=(8, 0))
        self.details_button = ttk.Button(buttons, text="Show details", style="Header.TButton",
                                         command=self.toggle_details)
        self.details_button.pack(side="right")

        self.forest = tk.Label(self.root, borderwidth=0, anchor="w")
        self.forest.pack(fill="x")
        self._paint_forest()

    def _paint_forest(self) -> None:
        p = self.theme.palette
        try:
            self.header_icon.configure(image=load_image(self.root, "icon-32.png"), background=p.header)
        except (FileNotFoundError, tk.TclError):
            self.header_icon.configure(background=p.header)
        try:
            self.forest.configure(image=load_image(self.root, "forest.png"), background=p.header, anchor="sw")
        except (FileNotFoundError, tk.TclError):
            self.forest.configure(height=1, background=p.header)

    def _build_body(self) -> None:
        body = ttk.Frame(self.root, padding=(16, 12, 16, 8))
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        self.barry = Barry(body, "idle")
        self.barry.grid(row=0, column=0, sticky="s", padx=(0, 18))

        self.pane = Window(body, self.theme, padding=14)
        self.pane.grid(row=0, column=1, sticky="nsew")
        self.card = self.pane.body
        self.card.columnconfigure(0, weight=1)
        self.card.rowconfigure(0, weight=1)

        self.idle_panel = self._build_idle(self.card)
        self.scan_panel = self._build_scanning(self.card)
        self.result_panel = ttk.Frame(self.card, style="Panel.TFrame")
        self.panel_titles = {self.idle_panel: "Check a download", self.scan_panel: "Checking...",
                             self.result_panel: "Result"}

    def _build_idle(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text="Check a download before you open it", style="Heading.TLabel").grid(
            row=0, column=0, sticky="w")
        self.drop_zone = DropZone(frame, self.theme, self.app.choose_and_scan)
        self.drop_zone.grid(row=1, column=0, sticky="ew", pady=(12, 12))
        actions = ttk.Frame(frame, style="Panel.TFrame")
        actions.grid(row=2, column=0, sticky="w")
        ttk.Button(actions, text="Choose a file...", style="Accent.TButton",
                   command=self.app.choose_and_scan).pack(side="left")
        ttk.Button(actions, text="Check a folder...", command=self.app.choose_folder_and_scan).pack(
            side="left", padx=(8, 0))
        self.auto_var = tk.BooleanVar(value=self.app.settings.auto_scan)
        ttk.Checkbutton(actions, text="Check new downloads automatically", variable=self.auto_var,
                        style="TCheckbutton",
                        command=lambda: self.app.set_auto_scan(self.auto_var.get())).pack(side="left", padx=16)
        return frame

    def _build_scanning(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.columnconfigure(0, weight=1)
        self.scan_title = ttk.Label(frame, text="", style="Heading.TLabel")
        self.scan_title.grid(row=0, column=0, sticky="w")
        ttk.Label(frame, text="Reading the files inside without unzipping or running them.",
                  style="CardMuted.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 14))
        self.progress = BlockProgress(frame, self.theme)
        self.progress.grid(row=2, column=0, sticky="ew")
        self.scan_file = ttk.Label(frame, text="", style="CardMuted.TLabel")
        self.scan_file.grid(row=3, column=0, sticky="w", pady=(8, 16))
        ttk.Button(frame, text="Cancel", command=self.app.cancel_scan).grid(row=4, column=0, sticky="w")
        return frame

    def _build_details(self) -> None:
        self.details = ttk.Notebook(self.root)
        self.findings_tree = self._tree(self.details, ("severity", "file", "finding"),
                                        ("Severity", "File", "What Barry found"), (90, 220, 420))
        self.findings_tree.bind("<<TreeviewSelect>>", self._show_finding_detail)
        findings_tab = self.findings_tree.tab_frame
        self.finding_detail = WrapLabel(findings_tab, text="", style="Muted.TLabel")
        self.finding_detail.pack(fill="x", padx=6, pady=(4, 6))
        self.details.add(findings_tab, text="Findings")

        self.files_tree = self._tree(self.details, ("file", "type", "size", "sha256"),
                                     ("File", "Type", "Size", "SHA-256"), (260, 90, 80, 420))
        self.files_tree.bind("<Control-c>", lambda _e: self._copy_selected_hash())
        self.files_tree.bind("<Button-3>", lambda e: self._copy_menu(e))
        files_tab = self.files_tree.tab_frame
        ttk.Label(files_tab, text="Select a file and press Ctrl+C to copy its fingerprint.",
                  style="Muted.TLabel").pack(anchor="w", padx=6, pady=(4, 6))
        self.details.add(files_tab, text="Files")

        ioc_tab = ttk.Frame(self.details, padding=6)
        self.ioc_list = tk.Listbox(ioc_tab, height=6, activestyle="none", borderwidth=2, highlightthickness=0,
                                   font="ALB.Mono", exportselection=False)
        self.ioc_list.pack(fill="both", expand=True)
        self.ioc_list.bind("<Control-c>", lambda _e: self._copy_ioc())
        ttk.Label(ioc_tab, text="Web addresses and endpoints found in the files. Don't visit them.",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 0))
        self.details.add(ioc_tab, text="Addresses")

        engine_tab = ttk.Frame(self.details, padding=10)
        self.engine_text = ttk.Label(engine_tab, text="", justify="left")
        self.engine_text.pack(anchor="w")
        self.details.add(engine_tab, text="Engines")

        self.history_tree = self._tree(self.details, ("when", "file", "verdict"),
                                       ("When", "File", "Verdict"), (140, 460, 140))
        self.history_tree.bind("<Double-1>", self._rescan_history)
        self.history_tree.bind("<Return>", self._rescan_history)
        history_tab = self.history_tree.tab_frame
        ttk.Label(history_tab, text="Double-click a file to check it again.",
                  style="Muted.TLabel").pack(anchor="w", padx=6, pady=(4, 6))
        self.details.add(history_tab, text="History")
        self._restyle_listbox()

    def _tree(self, parent, columns, headings, widths) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        holder = ttk.Frame(frame)
        holder.pack(fill="both", expand=True)
        tree = ttk.Treeview(holder, columns=columns, show="headings", height=6, selectmode="browse")
        for col, head, width in zip(columns, headings, widths):
            tree.heading(col, text=head, anchor="w")
            tree.column(col, width=width, anchor="w", stretch=col in ("finding", "file", "sha256"))
        scroll = ttk.Scrollbar(holder, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        tree.tab_frame = frame
        return tree

    def _build_status(self) -> None:
        bar = ttk.Frame(self.root, padding=(2, 2, 2, 2))
        bar.pack(fill="x", side="bottom")
        self.status = tk.Label(bar, text="", anchor="w", relief="sunken", borderwidth=1, font="ALB.Small",
                               padx=6, pady=1)
        self.status.pack(side="left", fill="x", expand=True)
        self.engine_status = tk.Label(bar, text="", anchor="w", relief="sunken", borderwidth=1, font="ALB.Small",
                                      padx=6, pady=1)
        self.engine_status.pack(side="right", padx=(2, 0))
        self._paint_status()

    def _bind_keys(self) -> None:
        mod = "Command" if self.root.tk.call("tk", "windowingsystem") == "aqua" else "Control"
        self.root.bind(f"<{mod}-o>", lambda _e: self.app.choose_and_scan())
        self.root.bind(f"<{mod}-O>", lambda _e: self.app.choose_folder_and_scan())
        self.root.bind(f"<{mod}-d>", lambda _e: self.toggle_details())
        self.root.bind(f"<{mod}-comma>", lambda _e: self.app.open_settings())
        self.root.bind(f"<{mod}-s>", lambda _e: self.report and self.app.save_report(self.report))
        self.root.bind("<Escape>", lambda _e: self._escape())

    def _escape(self) -> None:
        if self.scan_panel.winfo_ismapped():
            self.app.cancel_scan()
        elif self.result_panel.winfo_ismapped():
            self.show_idle()

    def _show(self, panel: ttk.Frame) -> None:
        for child in (self.idle_panel, self.scan_panel, self.result_panel):
            if child is not panel:
                child.grid_forget()
        panel.grid(row=0, column=0, sticky="nsew")
        self.pane.set_title(self.panel_titles[panel])

    def show_idle(self) -> None:
        self.progress.stop()
        self.barry.set_pose("idle")
        self._show(self.idle_panel)
        self.drop_zone.focus_set()

    def show_scanning(self, path: str) -> None:
        self.barry.set_pose("scan")
        self.scan_title.configure(text=f"Barry is checking {os.path.basename(path)}...")
        self.scan_file.configure(text="")
        self._show(self.scan_panel)
        self.progress.start(12)

    def update_progress(self, message: str) -> None:
        text = message if len(message) <= 80 else "..." + message[-77:]
        self.scan_file.configure(text=text)

    def show_result(self, report: ScanReport, quarantined: bool = False) -> None:
        self.progress.stop()
        self.report = report
        verdict = report.verdict
        self.barry.set_pose(POSE_FOR_VERDICT[verdict])
        for child in self.result_panel.winfo_children():
            child.destroy()
        panel = self.result_panel
        panel.columnconfigure(0, weight=1)

        fg, bg = self.theme.verdict_colours(verdict)
        banner = tk.Frame(panel, background=bg, borderwidth=2, relief="sunken")
        banner.grid(row=0, column=0, sticky="ew")
        icon = VerdictIcon(banner, self.theme)
        icon.draw(verdict, bg)
        icon.pack(side="left", padx=12, pady=10)
        words = tk.Frame(banner, background=bg)
        words.pack(side="left", fill="x", expand=True, pady=8)
        tk.Label(words, text=verdict.headline, font="ALB.Verdict", foreground=fg, background=bg,
                 anchor="w").pack(fill="x")
        name = os.path.basename(report.target)
        tk.Label(words, text=f"{name}  -  {len(report.files)} file(s) checked in {report.duration:.1f}s",
                 font="ALB.Small", foreground=fg, background=bg, anchor="w").pack(fill="x")

        WrapLabel(panel, text=VERDICT_BLURB[verdict], style="Card.TLabel").grid(
            row=1, column=0, sticky="ew", pady=(12, 8))

        reasons = ttk.Frame(panel, style="Panel.TFrame")
        reasons.grid(row=2, column=0, sticky="nsew")
        reasons.columnconfigure(1, weight=1)
        shown = plain_reasons(report)
        for i, (severity, line) in enumerate(shown):
            tk.Label(reasons, text=severity.label.upper(), font="ALB.Bold", background=self.theme.palette.panel,
                     foreground=self.theme.severity_colour(severity), anchor="nw", width=8).grid(
                row=i, column=0, sticky="nw", pady=2)
            WrapLabel(reasons, text=line, style="Card.TLabel").grid(row=i, column=1, sticky="ew", pady=2)
        hidden = len([f for f in report.findings if f.severity >= Severity.LOW]) - len(shown)
        if hidden > 0:
            ttk.Label(reasons, text=f"+ {hidden} more in Show details", style="CardMuted.TLabel").grid(
                row=99, column=1, sticky="w", pady=(4, 0))

        actions = ttk.Frame(panel, style="Panel.TFrame")
        actions.grid(row=3, column=0, sticky="w", pady=(14, 0))
        first = None
        if quarantined:
            ttk.Label(actions, text="Moved to quarantine.", style="Card.TLabel").pack(side="left", padx=(0, 12))
        elif verdict is not Verdict.CLEAN and os.path.isfile(report.target):
            first = ttk.Button(actions, text="Quarantine it", style="Danger.TButton",
                               command=lambda: self.app.quarantine_report(report))
            first.pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Save report...", command=lambda: self.app.save_report(report)).pack(
            side="left", padx=(0, 8))
        another = ttk.Button(actions, text="Check another file", style="Accent.TButton",
                             command=self.app.choose_and_scan)
        another.pack(side="left")
        self._show(panel)
        (first or another).focus_set()
        self._fill_details(report)

    def _fill_details(self, report: ScanReport) -> None:
        self.findings_tree.delete(*self.findings_tree.get_children())
        self._finding_rows = {}
        for f in report.ranked():
            iid = self.findings_tree.insert("", "end", values=(f.severity.label, f.path or "-", f.title))
            self._finding_rows[iid] = f
        self.finding_detail.configure(text="Select a finding to see the evidence.")
        self.files_tree.delete(*self.files_tree.get_children())
        for rec in report.files:
            self.files_tree.insert("", "end", values=(rec.path, rec.kind, _size(rec.size), rec.sha256))
        self.ioc_list.delete(0, "end")
        for ioc in report.indicators():
            self.ioc_list.insert("end", ioc)
        self.engine_text.configure(text="\n".join(f"{k}: {v}" for k, v in report.engines.items()))

    def _show_finding_detail(self, _event=None) -> None:
        selection = self.findings_tree.selection()
        if not selection:
            return
        f = self._finding_rows.get(selection[0])
        if f is None:
            return
        parts = [f"{f.check}"]
        if f.detail:
            parts.append(f.detail)
        if f.indicators:
            parts.append("Addresses: " + ", ".join(f.indicators[:6]))
        self.finding_detail.configure(text="  |  ".join(parts))

    def _copy_selected_hash(self) -> None:
        selection = self.files_tree.selection()
        if selection:
            copy_to_clipboard(self.root, self.files_tree.item(selection[0], "values")[3])
            self.set_status("Fingerprint copied.")

    def _copy_menu(self, event) -> None:
        row = self.files_tree.identify_row(event.y)
        if not row:
            return
        self.files_tree.selection_set(row)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy SHA-256", command=self._copy_selected_hash)
        menu.tk_popup(event.x_root, event.y_root)

    def _copy_ioc(self) -> None:
        selection = self.ioc_list.curselection()
        if selection:
            copy_to_clipboard(self.root, self.ioc_list.get(selection[0]))

    def refresh_history(self, entries) -> None:
        self.history_tree.delete(*self.history_tree.get_children())
        for entry in entries:
            self.history_tree.insert("", "end", values=(entry.get("when", ""), entry.get("path", ""),
                                                        Verdict(entry.get("verdict", "clean")).headline))

    def _rescan_history(self, _event=None) -> None:
        selection = self.history_tree.selection()
        if selection:
            path = self.history_tree.item(selection[0], "values")[1]
            if os.path.isfile(path):
                self.app.scan(path)
            else:
                self.set_status("That file has been moved or deleted.")

    def toggle_details(self) -> None:
        self.set_details_visible(not self.details.winfo_ismapped())
        self.app.settings.show_details = self.details.winfo_ismapped()
        self.app.save_settings()

    def set_details_visible(self, visible: bool) -> None:
        if visible:
            self.details.pack(fill="both", expand=True, padx=16, pady=(0, 6), before=self.status.master)
            self.details_button.configure(text="Hide details")
            if self.root.winfo_height() < 760:
                self.root.geometry(f"{max(self.root.winfo_width(), 900)}x820")
        else:
            self.details.pack_forget()
            self.details_button.configure(text="Show details")

    def set_status(self, text: str) -> None:
        self.status.configure(text=text)

    def set_engine_status(self, text: str) -> None:
        self.engine_status.configure(text=text)

    def set_auto_scan(self, value: bool) -> None:
        self.auto_var.set(value)

    def retheme(self) -> None:
        self._paint_forest()
        self._paint_status()
        self.pane.retheme()
        self.progress.configure(height=round(22 * self.theme.scale))
        self.drop_zone.redraw()
        self._restyle_listbox()
        if self.report is not None and self.result_panel.winfo_ismapped():
            self.show_result(self.report)

    def _paint_status(self) -> None:
        p = self.theme.palette
        for label in (self.status, self.engine_status):
            label.configure(background=p.bg, foreground=p.muted)

    def _restyle_listbox(self) -> None:
        p = self.theme.palette
        self.ioc_list.configure(background=p.field, foreground=p.ink, selectbackground=p.select,
                                selectforeground=p.select_ink, relief="sunken", borderwidth=2,
                                highlightthickness=0)


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)
