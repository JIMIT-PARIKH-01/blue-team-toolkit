"""
Tkinter GUI for the Blue Team Toolkit (standard library only).

Tabs: Password · Secrets · Integrity · Logs. Longer scans run on background
threads; only the main thread touches widgets (via a queue).

Launch with run.bat, or:  python blueteam/gui.py
"""

from __future__ import annotations

import queue
import threading

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

try:
    from blueteam import passwd, secrets_scan, integrity, logwatch
except ImportError:  # pragma: no cover
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from blueteam import passwd, secrets_scan, integrity, logwatch


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Blue Team Toolkit")
        self.geometry("840x660")
        self.minsize(720, 540)
        self.ui_queue: "queue.Queue" = queue.Queue()
        self.after(60, self._drain)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        for tab, title in ((PasswordTab, "  Password  "), (SecretsTab, "  Secrets  "),
                           (IntegrityTab, "  Integrity  "), (LogsTab, "  Logs  ")):
            nb.add(tab(nb, self), text=title)

        self.status = ttk.Label(self, relief="sunken", anchor="w", text="Ready")
        self.status.pack(fill="x", side="bottom")

    def set_status(self, msg: str) -> None:
        self.status.configure(text=msg)

    def _drain(self) -> None:
        try:
            while True:
                cb = self.ui_queue.get_nowait()
                try:
                    cb()
                except Exception:  # noqa: BLE001
                    self.set_status("A UI update failed.")
        except queue.Empty:
            pass
        self.after(60, self._drain)


class _Tab(ttk.Frame):
    def __init__(self, master, app: App) -> None:
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

    def _output(self, row: int) -> scrolledtext.ScrolledText:
        box = scrolledtext.ScrolledText(self, wrap="word", font=("Consolas", 10),
                                        state="disabled")
        box.grid(row=row, column=0, sticky="nsew", pady=(8, 0))
        return box

    def _show(self, widget, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _run_async(self, work, on_done, button, busy: str) -> None:
        if button:
            button.configure(state="disabled")
        self.app.set_status(busy)

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                result = f"Error: {exc}"

            def finish() -> None:
                on_done(result)
                if button:
                    button.configure(state="normal")
                self.app.set_status("Done.")
            self.app.ui_queue.put(finish)

        threading.Thread(target=runner, daemon=True).start()


class PasswordTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Password to analyze").grid(row=0, column=0, sticky="w")
        self.pw = tk.StringVar()
        row = ttk.Frame(self); row.grid(row=1, column=0, sticky="ew")
        row.columnconfigure(0, weight=1)
        self.entry = ttk.Entry(row, textvariable=self.pw, show="•")
        self.entry.grid(row=0, column=0, sticky="ew")
        self.show = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="show", variable=self.show,
                        command=self._toggle).grid(row=0, column=1, padx=6)
        ttk.Button(row, text="Analyze", command=self.run).grid(row=0, column=2)
        self.out = self._output(3)
        self.pw.trace_add("write", lambda *_: self.run())

    def _toggle(self):
        self.entry.configure(show="" if self.show.get() else "•")

    def run(self):
        pw = self.pw.get()
        self._show(self.out, passwd.analyze(pw).as_text() if pw else "Type a password.")


class SecretsTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="File or folder to scan").grid(row=0, column=0, sticky="w")
        self.path = tk.StringVar()
        ttk.Entry(self, textvariable=self.path).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Button(ctl, text="Browse…", command=self._browse).pack(side="left")
        self.btn = ttk.Button(ctl, text="Scan", command=self.run); self.btn.pack(side="right")
        self.out = self._output(3)

    def _browse(self):
        d = filedialog.askdirectory(title="Choose a folder to scan")
        if d:
            self.path.set(d)

    def run(self):
        path = self.path.get().strip()
        if not path:
            messagebox.showinfo("No path", "Choose a file or folder."); return
        self._run_async(lambda: secrets_scan.report(secrets_scan.scan_path(path)),
                        lambda r: self._show(self.out, r), self.btn, "Scanning for secrets…")


class IntegrityTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Folder to monitor").grid(row=0, column=0, sticky="w")
        self.root = tk.StringVar()
        ttk.Entry(self, textvariable=self.root).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Button(ctl, text="Browse…", command=self._browse).pack(side="left")
        ttk.Label(ctl, text="Baseline file").pack(side="left", padx=(10, 4))
        self.base = tk.StringVar(value="integrity.baseline.json")
        ttk.Entry(ctl, textvariable=self.base, width=28).pack(side="left")
        self.btn_b = ttk.Button(ctl, text="Save baseline", command=self.save)
        self.btn_b.pack(side="left", padx=6)
        self.btn_c = ttk.Button(ctl, text="Check", command=self.check); self.btn_c.pack(side="left")
        self.out = self._output(3)

    def _browse(self):
        d = filedialog.askdirectory(title="Folder to monitor")
        if d:
            self.root.set(d)

    def save(self):
        if not self.root.get().strip():
            messagebox.showinfo("No folder", "Choose a folder."); return
        self._run_async(
            lambda: f"Baselined {integrity.save_baseline(self.root.get(), self.base.get())} "
                    f"file(s) -> {self.base.get()}",
            lambda r: self._show(self.out, r), self.btn_b, "Building baseline…")

    def check(self):
        if not self.root.get().strip():
            messagebox.showinfo("No folder", "Choose a folder."); return
        self._run_async(
            lambda: integrity.check(self.root.get(), self.base.get()).as_text(),
            lambda r: self._show(self.out, r), self.btn_c, "Checking integrity…")


class LogsTab(_Tab):
    def __init__(self, master, app):
        super().__init__(master, app)
        ttk.Label(self, text="Auth log file").grid(row=0, column=0, sticky="w")
        self.file = tk.StringVar()
        ttk.Entry(self, textvariable=self.file).grid(row=1, column=0, sticky="ew")
        ctl = ttk.Frame(self); ctl.grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Button(ctl, text="Browse…", command=self._browse).pack(side="left")
        ttk.Label(ctl, text="Threshold").pack(side="left", padx=(10, 4))
        self.threshold = tk.StringVar(value="5")
        ttk.Entry(ctl, textvariable=self.threshold, width=5).pack(side="left")
        self.btn = ttk.Button(ctl, text="Analyze", command=self.run); self.btn.pack(side="right")
        self.out = self._output(3)

    def _browse(self):
        f = filedialog.askopenfilename(title="Choose an auth log")
        if f:
            self.file.set(f)

    def run(self):
        path = self.file.get().strip()
        if not path:
            messagebox.showinfo("No file", "Choose a log file."); return
        try:
            th = int(self.threshold.get())
        except ValueError:
            th = 5
        self._run_async(lambda: logwatch.analyze_file(path, threshold=th).as_text(),
                        lambda r: self._show(self.out, r), self.btn, "Analyzing log…")


def main() -> int:
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
