# Anti-Logging Bear by Priest

from __future__ import annotations

import contextlib
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from . import APP_NAME
from . import report as fmt
from . import settings as config
from .engine import antivirus
from .engine.findings import ScanReport, Verdict
from .engine.scanner import ScanCancelled, scan_path
from .history import History
from .system import integration, paths
from .system.notify import notify
from .system.single_instance import InstanceServer, send_to_running
from .ui.theme import Theme
from .watch.quarantine import Quarantine
from .watch.watcher import FolderWatcher

FILE_TYPES = [
    ("Downloads", "*.zip *.exe *.msi *.dll *.asi *.bat *.cmd *.ps1 *.vbs *.js *.hta *.lnk *.py *.lua *.cs "
                  "*.doc *.docm *.docx *.xls *.xlsm *.xlsx *.ppt *.pptm *.pptx *.pdf *.jar"),
    ("All files", "*"),
]


class Job:
    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.cancel = threading.Event()


def run_app(initial: list[str], background: bool = False) -> int:
    targets = [os.path.abspath(p) for p in initial if os.path.isfile(p)]
    if send_to_running(targets, show=not background):
        return 0
    integration.enable_dpi_awareness()
    return Application(targets, background).run()


def _make_root() -> tuple[tk.Tk, bool]:
    try:
        from tkinterdnd2 import TkinterDnD
        return TkinterDnD.Tk(), True
    except (ImportError, RuntimeError, tk.TclError):
        return tk.Tk(), False


class Application:
    def __init__(self, initial: list[str], background: bool) -> None:
        self.settings = config.load()
        self.root, self._dnd = _make_root()
        if background:
            self.root.withdraw()
        self.root.title(APP_NAME)
        self._set_icon()
        self.theme = Theme(self.root, self.settings.high_contrast, self.settings.large_text)

        self.events: queue.Queue = queue.Queue()
        self.jobs: queue.Queue = queue.Queue()
        self.current: Job | None = None
        self.history = History()
        self.quarantine = Quarantine(paths.quarantine_dir())
        self.watcher: FolderWatcher | None = None
        self.tray = None
        self._told_about_tray = False

        from .ui.main_window import MainWindow
        self.window = MainWindow(self.root, self)
        self.window.refresh_history(self.history.entries)
        self._setup_drag_and_drop()
        self._setup_platform_hooks()

        threading.Thread(target=self._worker, name="scanner", daemon=True).start()
        server = InstanceServer(lambda msg: self.post(lambda: self._on_instance_message(msg)))
        if server.bind():
            server.start()

        if self.settings.close_to_tray or background:
            from .ui.tray import create_tray
            self.tray = create_tray(self)
        self._refresh_integration()
        self._restart_watcher()
        self._refresh_engine_status()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._pump)
        for path in initial:
            self.scan(path)

    def run(self) -> int:
        self.root.mainloop()
        return 0

    def _refresh_integration(self) -> None:
        if not getattr(sys, "frozen", False):
            return
        with contextlib.suppress(OSError):
            if self.settings.start_at_login:
                integration.set_start_at_login(True)
            if self.settings.context_menu:
                integration.set_context_menu(True)

    def _set_icon(self) -> None:
        try:
            if sys.platform == "win32":
                self.root.iconbitmap(default=str(paths.asset("app.ico")))
            else:
                big = tk.PhotoImage(master=self.root, file=str(paths.asset("icon-512.png")))
                small = tk.PhotoImage(master=self.root, file=str(paths.asset("icon-32.png")))
                self.root.iconphoto(True, big, small)
                self._icons = (big, small)
        except tk.TclError:
            pass

    def _setup_drag_and_drop(self) -> None:
        if not self._dnd:
            return
        from tkinterdnd2 import DND_FILES

        def dropped(event):
            self.window.drop_zone.set_drag_active(False)
            for path in self.root.tk.splitlist(event.data):
                if os.path.isfile(path):
                    self.scan(path)
            return event.action

        def entered(event):
            self.window.drop_zone.set_drag_active(True)
            return event.action

        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind("<<Drop>>", dropped)
        self.root.dnd_bind("<<DropEnter>>", entered)
        self.root.dnd_bind("<<DropLeave>>", lambda e: (self.window.drop_zone.set_drag_active(False), e.action)[1])

    def _setup_platform_hooks(self) -> None:
        if self.root.tk.call("tk", "windowingsystem") != "aqua":
            return
        self.root.createcommand("::tk::mac::ReopenApplication", self.show_window)
        self.root.createcommand("::tk::mac::Quit", self.quit)
        self.root.createcommand("::tk::mac::ShowPreferences", self.open_settings)
        self.root.createcommand("::tk::mac::OpenDocument",
                                lambda *files: [self.scan(f) for f in files if os.path.isfile(f)])

    def post(self, fn) -> None:
        self.events.put(("call", fn))

    def _pump(self) -> None:
        try:
            while True:
                kind, *payload = self.events.get_nowait()
                if kind == "call":
                    payload[0]()
                elif kind == "started":
                    self._on_started(payload[0])
                elif kind == "progress":
                    job, message = payload
                    if job is self.current and job.source == "manual":
                        self.window.update_progress(message)
                elif kind == "done":
                    self._on_done(*payload)
                elif kind == "failed":
                    self._on_failed(*payload)
                elif kind == "new-download":
                    self.scan(payload[0], source="auto")
        except queue.Empty:
            pass
        self.root.after(100, self._pump)

    def _worker(self) -> None:
        while True:
            job = self.jobs.get()
            if job.cancel.is_set():
                continue
            self.current = job
            self.events.put(("started", job))
            try:
                result = scan_path(job.path, self.settings.scan_options(),
                                   progress=lambda msg, j=job: self.events.put(("progress", j, msg)),
                                   cancelled=job.cancel.is_set)
                self.events.put(("done", job, result))
            except ScanCancelled:
                pass
            except Exception as exc:
                self.events.put(("failed", job, exc))
            finally:
                self.current = None

    def scan(self, path: str, source: str = "manual") -> None:
        job = Job(os.path.abspath(path), source)
        if source == "manual":
            self.show_window()
            self.window.show_scanning(job.path)
        self.jobs.put(job)

    def _on_started(self, job: Job) -> None:
        if job.source == "manual":
            self.window.show_scanning(job.path)
        else:
            self.window.set_status(f"Checking new download {os.path.basename(job.path)}...")

    def _on_done(self, job: Job, result: ScanReport) -> None:
        self.history.add(result, job.source)
        self.window.refresh_history(self.history.entries)
        name = os.path.basename(job.path)
        self.window.set_status(f"Last check: {name} - {result.verdict.headline}")
        if job.source == "manual":
            self.window.show_result(result)
            return
        if result.verdict is Verdict.CLEAN:
            if self.settings.notify_clean:
                notify(APP_NAME, f"{name}: no threats found", self.tray)
            return
        quarantined = False
        if self.settings.auto_quarantine and result.verdict is Verdict.DANGEROUS:
            quarantined = self._move_to_quarantine(result, quiet=True)
        notify(APP_NAME, f"{name}: {result.verdict.headline}", self.tray)
        from .ui.alert import DownloadAlert
        DownloadAlert(self, result, quarantined)

    def _on_failed(self, job: Job, exc: Exception) -> None:
        message = f"Barry couldn't check {os.path.basename(job.path)}: {exc}"
        self.window.set_status(message)
        if job.source == "manual":
            self.window.show_idle()
            messagebox.showerror(APP_NAME, message, parent=self.root)

    def cancel_scan(self) -> None:
        if self.current is not None:
            self.current.cancel.set()
        self.window.show_idle()
        self.window.set_status("Check cancelled.")

    def choose_and_scan(self) -> None:
        self.show_window()
        initial = self.settings.watch_folders[0] if self.settings.watch_folders else str(paths.downloads_dir())
        path = filedialog.askopenfilename(parent=self.root, title="Choose a download to check",
                                          initialdir=initial, filetypes=FILE_TYPES)
        if path:
            self.scan(path)

    def quarantine_report(self, result: ScanReport) -> bool:
        if self._move_to_quarantine(result, quiet=False):
            if self.window.report is result:
                self.window.show_result(result, quarantined=True)
            return True
        return False

    def _move_to_quarantine(self, result: ScanReport, quiet: bool) -> bool:
        reasons = fmt.plain_reasons(result, 1)
        sha = result.files[0].sha256 if result.files else ""
        try:
            self.quarantine.add(result.target, sha, result.verdict.value, reasons[0][1] if reasons else "")
        except OSError as exc:
            if not quiet:
                messagebox.showerror(APP_NAME, f"Couldn't move the file to quarantine. Close any program "
                                               f"using it and try again.\n\n{exc}", parent=self.root)
            return False
        self.window.set_status(f"{os.path.basename(result.target)} moved to quarantine.")
        return True

    def save_report(self, result: ScanReport) -> None:
        stem = os.path.splitext(os.path.basename(result.target))[0]
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Save report", initialfile=f"{stem} - Barry report.html",
            defaultextension=".html",
            filetypes=[("Web page", "*.html"), ("JSON", "*.json"), ("Text", "*.txt")])
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        text = fmt.to_json(result) if ext == ".json" else fmt.to_text(result, True) if ext == ".txt" \
            else fmt.to_html(result)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            messagebox.showerror(APP_NAME, f"Couldn't save the report.\n\n{exc}", parent=self.root)
            return
        self.window.set_status(f"Report saved to {path}")

    def open_settings(self) -> None:
        from .ui.settings_dialog import SettingsDialog
        self.show_window()
        SettingsDialog(self)

    def apply_settings(self, new: config.Settings) -> list[str]:
        old = self.settings
        errors: list[str] = []
        if new.start_at_login != old.start_at_login:
            try:
                integration.set_start_at_login(new.start_at_login)
            except OSError as exc:
                errors.append(f"Couldn't change start-at-login: {exc}")
                new.start_at_login = old.start_at_login
        if new.context_menu != old.context_menu:
            try:
                integration.set_context_menu(new.context_menu)
            except OSError as exc:
                errors.append(f"Couldn't change the right-click menu: {exc}")
                new.context_menu = old.context_menu
        self.settings = new
        self.save_settings()
        if (new.high_contrast, new.large_text) != (old.high_contrast, old.large_text):
            self.theme.apply(new.high_contrast, new.large_text)
            self.window.retheme()
        watch_keys = ("auto_scan", "watch_folders", "exclusions", "scan_all_types")
        if any(getattr(new, k) != getattr(old, k) for k in watch_keys):
            self._restart_watcher()
        if new.close_to_tray and self.tray is None:
            from .ui.tray import create_tray
            self.tray = create_tray(self)
        self.window.set_auto_scan(new.auto_scan)
        self._refresh_engine_status()
        return errors

    def save_settings(self) -> None:
        try:
            config.save(self.settings)
        except OSError as exc:
            self.window.set_status(f"Couldn't save settings: {exc}")

    def set_auto_scan(self, value: bool) -> None:
        self.settings.auto_scan = value
        self.save_settings()
        self.window.set_auto_scan(value)
        self._restart_watcher()
        if self.tray is not None:
            self.tray.update_menu()

    def _restart_watcher(self) -> None:
        if self.watcher is not None:
            self.watcher.stop()
            self.watcher = None
        s = self.settings
        folders = [f for f in s.watch_folders if os.path.isdir(f)]
        if s.auto_scan and folders:
            self.watcher = FolderWatcher(folders, lambda p: self.events.put(("new-download", p)),
                                         s.exclusions, s.scan_all_types)
            self.watcher.start()
            names = ", ".join(os.path.basename(f.rstrip("\\/")) or f for f in folders)
            self.window.set_status(f"Watching {names} for new downloads.")
        elif s.auto_scan:
            self.window.set_status("Auto-scan is on, but none of the watched folders exist.")
        else:
            self.window.set_status("Auto-scan is off.")

    def _refresh_engine_status(self) -> None:
        s = self.settings
        av = (antivirus.available_engine() or "none found") if s.use_antivirus else "off"
        parts = [f"Antivirus: {av}", "YARA: " + ("on" if s.use_yara else "off"),
                 "VirusTotal: " + ("on" if s.vt_api_key else "off")]
        self.window.set_engine_status("   |   ".join(parts))

    def _on_instance_message(self, message: dict) -> None:
        if message.get("show", True):
            self.show_window()
        for path in message.get("paths") or []:
            if isinstance(path, str) and os.path.isfile(path):
                self.scan(path)

    def show_window(self) -> None:
        self.root.deiconify()
        self.root.lift()
        with contextlib.suppress(tk.TclError):
            self.root.focus_force()

    def on_close(self) -> None:
        keep_running = self.tray is not None and self.settings.close_to_tray
        if self.root.tk.call("tk", "windowingsystem") == "aqua" and self.settings.auto_scan:
            keep_running = True
        if not keep_running:
            self.quit()
            return
        self.root.withdraw()
        if not self._told_about_tray and self.settings.auto_scan:
            self._told_about_tray = True
            notify(APP_NAME, "Barry is still watching your downloads. Open him from the tray.", self.tray)

    def quit(self) -> None:
        if self.watcher is not None:
            self.watcher.stop()
        if self.tray is not None:
            with contextlib.suppress(Exception):
                self.tray.stop()
        self.root.destroy()
