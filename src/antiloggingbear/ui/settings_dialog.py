# Anti-Logging Bear by Priest

from __future__ import annotations

import sys
import tkinter as tk
import webbrowser
from dataclasses import replace
from tkinter import filedialog, messagebox, ttk
from typing import TYPE_CHECKING

from .. import APP_NAME
from ..engine import antivirus
from ..engine.yara_rules import shared_engine
from ..settings import Settings
from ..system import integration

if TYPE_CHECKING:
    from ..app import Application

VT_SIGNUP = "https://www.virustotal.com/gui/join-us"


class SettingsDialog(tk.Toplevel):
    def __init__(self, app: Application) -> None:
        super().__init__(app.root)
        self.app = app
        self.original = app.settings
        self.draft = replace(app.settings, watch_folders=list(app.settings.watch_folders),
                             exclusions=list(app.settings.exclusions))
        self.title("Settings")
        self.configure(background=app.theme.palette.bg)
        self.transient(app.root)
        self.minsize(600, 500)
        self.resizable(True, True)

        outer = ttk.Frame(self, padding=14)
        outer.pack(fill="both", expand=True)
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        self._vars: dict = {}
        self._auto_tab()
        self._detection_tab()
        self._online_tab()
        self._system_tab()
        self._quarantine_tab()
        self._access_tab()

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Save", style="Accent.TButton", command=self._save).pack(side="right")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=8)
        self.bind("<Escape>", lambda _e: self.destroy())
        self.bind("<Return>", lambda e: None if isinstance(e.widget, (tk.Listbox, ttk.Treeview)) else self._save())
        self.grab_set()
        self.tabs.focus_set()

    def _var(self, name: str, kind=tk.BooleanVar):
        var = kind(value=getattr(self.draft, name))
        self._vars[name] = var
        return var

    def _page(self, title: str) -> ttk.Frame:
        page = ttk.Frame(self.tabs, padding=16)
        page.columnconfigure(0, weight=1)
        self.tabs.add(page, text=title)
        return page

    def _check(self, page, row, name, text, hint=""):
        ttk.Checkbutton(page, text=text, variable=self._var(name)).grid(row=row, column=0, columnspan=3,
                                                                         sticky="w", pady=(6, 0))
        if hint:
            ttk.Label(page, text=hint, style="Muted.TLabel", wraplength=520).grid(
                row=row + 1, column=0, columnspan=3, sticky="w", padx=(24, 0))

    def _auto_tab(self) -> None:
        page = self._page("Auto-scan")
        self._check(page, 0, "auto_scan", "Check new downloads automatically",
                    "Barry keeps an eye on these folders and checks each new file as soon as it finishes downloading.")
        ttk.Label(page, text="Folders to watch", style="TLabel").grid(row=2, column=0, sticky="w", pady=(14, 4))
        self.folder_list = tk.Listbox(page, height=4, activestyle="none", exportselection=False)
        self._style_listbox(self.folder_list)
        self.folder_list.grid(row=3, column=0, sticky="nsew")
        for folder in self.draft.watch_folders:
            self.folder_list.insert("end", folder)
        side = ttk.Frame(page)
        side.grid(row=3, column=1, sticky="n", padx=(8, 0))
        ttk.Button(side, text="Add...", command=self._add_folder).pack(fill="x")
        ttk.Button(side, text="Remove", command=self._remove_folder).pack(fill="x", pady=(6, 0))

        ttk.Label(page, text="Ignore files matching (comma separated, e.g. *.torrent, setup_*.exe)").grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(14, 4))
        self.exclusions = tk.StringVar(value=", ".join(self.draft.exclusions))
        ttk.Entry(page, textvariable=self.exclusions).grid(row=5, column=0, columnspan=2, sticky="ew")
        self._check(page, 6, "notify_clean", "Tell me when a download is clean too")
        self._check(page, 7, "auto_quarantine", "Quarantine dangerous downloads straight away",
                    "You can restore anything from the Quarantine tab.")
        self._check(page, 9, "scan_all_types", "Check every new file, not just programs, scripts, archives and documents")

    def _detection_tab(self) -> None:
        page = self._page("Detection")
        ttk.Label(page, text="How picky should Barry be?").grid(row=0, column=0, sticky="w")
        strict = tk.BooleanVar(value=self.draft.strict)
        self._vars["strict"] = strict
        ttk.Radiobutton(page, text="Normal - warn about high-risk signs", variable=strict, value=False).grid(
            row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Radiobutton(page, text="Strict - also warn about medium-risk signs (more false alarms)",
                        variable=strict, value=True).grid(row=2, column=0, sticky="w")

        self._check(page, 3, "use_yara", "Use YARA pattern rules", shared_engine(self.draft.custom_rules_dir).status)
        ttk.Label(page, text="Extra YARA rules folder (optional)").grid(row=5, column=0, sticky="w", pady=(12, 4))
        rules = ttk.Frame(page)
        rules.grid(row=6, column=0, sticky="ew")
        rules.columnconfigure(0, weight=1)
        self.rules_dir = tk.StringVar(value=self.draft.custom_rules_dir)
        ttk.Entry(rules, textvariable=self.rules_dir).grid(row=0, column=0, sticky="ew")
        ttk.Button(rules, text="Browse...", command=self._pick_rules).grid(row=0, column=1, padx=(8, 0))

        engine = antivirus.available_engine()
        self._check(page, 7, "use_antivirus", "Ask my antivirus for a second opinion",
                    f"Found: {engine}." if engine else "No supported antivirus found (Microsoft Defender or ClamAV).")

        sizes = ttk.Frame(page)
        sizes.grid(row=9, column=0, sticky="w", pady=(14, 0))
        ttk.Label(sizes, text="Skip files bigger than").pack(side="left")
        ttk.Spinbox(sizes, from_=16, to=8192, increment=64, width=7,
                    textvariable=self._var("max_file_mb", tk.IntVar)).pack(side="left", padx=6)
        ttk.Label(sizes, text="MB").pack(side="left")

    def _online_tab(self) -> None:
        page = self._page("Online check")
        ttk.Label(page, wraplength=540, justify="left", text=(
            "With a free VirusTotal key, Barry also looks up each file's fingerprint (SHA-256) in "
            "VirusTotal's database of scans. Only fingerprints are sent - never your files or their names.")
        ).grid(row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(page, text="API key").grid(row=1, column=0, sticky="w", pady=(14, 4))
        self.vt_key = tk.StringVar(value=self.draft.vt_api_key)
        key_entry = ttk.Entry(page, textvariable=self.vt_key, show="•")
        key_entry.grid(row=2, column=0, sticky="ew")
        shown = tk.BooleanVar(value=False)
        ttk.Checkbutton(page, text="Show", variable=shown,
                        command=lambda: key_entry.configure(show="" if shown.get() else "•")).grid(
            row=2, column=1, padx=8)
        ttk.Button(page, text="Get a free key", command=lambda: webbrowser.open(VT_SIGNUP)).grid(row=2, column=2)
        lookups = ttk.Frame(page)
        lookups.grid(row=3, column=0, columnspan=3, sticky="w", pady=(14, 0))
        ttk.Label(lookups, text="Look up at most").pack(side="left")
        ttk.Spinbox(lookups, from_=1, to=50, width=5,
                    textvariable=self._var("vt_max_lookups", tk.IntVar)).pack(side="left", padx=6)
        ttk.Label(lookups, text="files per scan (riskiest first; free keys allow 4 a minute)").pack(side="left")
        ttk.Label(page, text="The key is stored in your user profile's settings file.",
                  style="Muted.TLabel").grid(row=4, column=0, columnspan=3, sticky="w", pady=(10, 0))

    def _system_tab(self) -> None:
        page = self._page("System")
        self._check(page, 0, "start_at_login", f"Start {APP_NAME} when I log in",
                    "Barry starts quietly in the background so downloads are checked straight away.")
        if integration.supports_context_menu():
            self._check(page, 2, "context_menu", f"Add \"Check with {APP_NAME}\" to the right-click menu")
            self._check(page, 3, "close_to_tray", "Keep watching from the system tray when I close the window")
        elif sys.platform == "darwin":
            ttk.Label(page, wraplength=520, justify="left", text=(
                "To check a file from Finder, right-click it and choose Open With > Barry Bear.")
            ).grid(row=2, column=0, sticky="w", pady=(14, 0))

    def _quarantine_tab(self) -> None:
        page = self._page("Quarantine")
        page.rowconfigure(1, weight=1)
        ttk.Label(page, text="Quarantined files are renamed so they can't be opened by accident.",
                  style="Muted.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.q_tree = ttk.Treeview(page, columns=("when", "name", "verdict", "from"), show="headings", height=7)
        for col, head, width in (("when", "When", 120), ("name", "File", 180), ("verdict", "Verdict", 90),
                                 ("from", "Original folder", 220)):
            self.q_tree.heading(col, text=head, anchor="w")
            self.q_tree.column(col, width=width, anchor="w")
        self.q_tree.grid(row=1, column=0, sticky="nsew")
        buttons = ttk.Frame(page)
        buttons.grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Button(buttons, text="Restore", command=self._restore).pack(side="left")
        ttk.Button(buttons, text="Delete for good", command=self._delete).pack(side="left", padx=8)
        ttk.Button(buttons, text="Open quarantine folder",
                   command=lambda: integration.open_folder(str(self.app.quarantine.folder))).pack(side="left")
        self._fill_quarantine()

    def _access_tab(self) -> None:
        page = self._page("Accessibility")
        self._check(page, 0, "high_contrast", "High-contrast colours")
        self._check(page, 1, "large_text", "Larger text")
        ttk.Label(page, style="Muted.TLabel", wraplength=520, justify="left", text=(
            "Keyboard: Ctrl+O choose a file, Ctrl+D show or hide details, Ctrl+S save the report, "
            "Ctrl+, settings, Esc cancel or go back. Tab moves between controls.")
        ).grid(row=2, column=0, sticky="w", pady=(16, 0))

    def _fill_quarantine(self) -> None:
        self.q_tree.delete(*self.q_tree.get_children())
        for item in self.app.quarantine.items():
            folder = item.original_path.rsplit("\\" if "\\" in item.original_path else "/", 1)[0]
            self.q_tree.insert("", "end", iid=item.id, values=(item.when, item.name, item.verdict.title(), folder))

    def _selected_item(self):
        selection = self.q_tree.selection()
        return selection[0] if selection else None

    def _restore(self) -> None:
        item_id = self._selected_item()
        if not item_id:
            return
        if not messagebox.askyesno("Restore file", "Put this file back where it came from? "
                                   "Only do this if you're sure it's safe.", parent=self):
            return
        try:
            where = self.app.quarantine.restore(item_id)
        except OSError as exc:
            messagebox.showerror("Restore failed", str(exc), parent=self)
            return
        self._fill_quarantine()
        self.app.window.set_status(f"Restored to {where}")

    def _delete(self) -> None:
        item_id = self._selected_item()
        if not item_id:
            return
        if not messagebox.askyesno("Delete for good", "Permanently delete this file? This can't be undone.",
                                   parent=self, icon="warning"):
            return
        self.app.quarantine.delete(item_id)
        self._fill_quarantine()

    def _add_folder(self) -> None:
        folder = filedialog.askdirectory(parent=self, title="Choose a folder to watch")
        if folder and folder not in self.folder_list.get(0, "end"):
            self.folder_list.insert("end", folder)

    def _remove_folder(self) -> None:
        for index in reversed(self.folder_list.curselection()):
            self.folder_list.delete(index)

    def _pick_rules(self) -> None:
        folder = filedialog.askdirectory(parent=self, title="Choose a folder of .yar rules")
        if folder:
            self.rules_dir.set(folder)

    def _style_listbox(self, box: tk.Listbox) -> None:
        p = self.app.theme.palette
        box.configure(background=p.field, foreground=p.ink, selectbackground=p.select, selectforeground=p.select_ink,
                      highlightthickness=0, relief="sunken", borderwidth=2)

    def _save(self) -> None:
        new: Settings = self.draft
        for name, var in self._vars.items():
            try:
                setattr(new, name, var.get())
            except tk.TclError:
                messagebox.showerror("Settings", f"Please enter a number for {name.replace('_', ' ')}.", parent=self)
                return
        new.watch_folders = list(self.folder_list.get(0, "end"))
        new.exclusions = [p.strip() for p in self.exclusions.get().split(",") if p.strip()]
        new.custom_rules_dir = self.rules_dir.get().strip()
        new.vt_api_key = self.vt_key.get().strip()
        new.max_file_mb = max(16, int(new.max_file_mb))
        new.vt_max_lookups = max(1, min(50, int(new.vt_max_lookups)))
        errors = self.app.apply_settings(new)
        if errors:
            messagebox.showwarning("Settings", "\n".join(errors), parent=self)
        self.destroy()
