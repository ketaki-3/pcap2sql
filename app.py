"""
app.py  --  Desktop GUI for the PCAP-to-SQLite Network Traffic Analyzer.
=======================================================================
A single-window Tkinter application that drives the engine in core.py.

Workflow for the user, left to right / top to bottom:
    1. CAPTURE:  pick a .pcap (or generate a sample), then load it into the
                 SQLite database.
    2. ANALYZE:  choose an analysis from the dropdown and run it; results
                 appear in the table, and the exact SQL that produced them is
                 shown below.

WHY TKINTER
Tkinter ships with Python itself -- no extra install beyond scapy. That keeps
the application trivially runnable on any machine with Python.

THREADING NOTE (important concept)
Reading/parsing a capture can take a moment on large files. If we did that on
the GUI's main thread, the window would freeze ("Not Responding") until it
finished. So the slow operations run on a BACKGROUND THREAD. But Tkinter
widgets may only be touched from the main thread, so the worker never updates
widgets directly: it stashes its result, and a periodic poller on the main
thread (via root.after) picks it up and updates the screen. This is the
standard safe pattern for long work in a Tkinter app.
"""

import os
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import core


# Paths are resolved relative to this file, so the app works no matter what
# directory it's launched from.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DEFAULT_PCAP = os.path.join(DATA_DIR, "sample.pcap")
DEFAULT_DB = os.path.join(DATA_DIR, "traffic.db")

# A simple colour palette so the app looks intentional rather than default-grey.
BG = "#f4f6f8"        # window background
PANEL = "#ffffff"     # panel/card background
ACCENT = "#1f3a5f"    # dark slate-navy for the header and primary buttons
ACCENT_TEXT = "#ffffff"
MUTED = "#5b6b7b"     # secondary text


class AnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.pcap_path = tk.StringVar(value=(DEFAULT_PCAP if os.path.exists(DEFAULT_PCAP) else ""))
        self.status = tk.StringVar(value="Ready. Start by choosing or generating a capture.")
        self.explanation = tk.StringVar(value="")
        self._result_q = queue.Queue()   # background workers post results here

        self._build_style()
        self._build_header()
        self._build_capture_panel()
        self._build_analysis_panel()
        self._build_results_panel()
        self._build_statusbar()

        # If a database is already present from a previous run, allow analysis.
        self._refresh_analysis_enabled()
        self._on_analysis_selected()      # seed the explanation text
        self._poll_results()              # start the result poller

    # ------------------------------------------------------------------ style
    def _build_style(self):
        self.root.title("PCAP2SQL  --  Network Traffic Analyzer")
        self.root.geometry("920x720")
        self.root.minsize(780, 600)
        self.root.configure(bg=BG)

        style = ttk.Style()
        # 'clam' is the most style-able built-in theme; the OS default often
        # ignores colour settings, so we switch to it explicitly.
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL, relief="flat")
        style.configure("TLabel", background=BG, font=("Segoe UI", 10))
        style.configure("Panel.TLabel", background=PANEL, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=PANEL, foreground=MUTED,
                        font=("Segoe UI", 9))
        style.configure("Heading.TLabel", background=PANEL, foreground=ACCENT,
                        font=("Segoe UI", 11, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"),
                        foreground=ACCENT_TEXT, background=ACCENT, padding=7)
        style.map("Accent.TButton",
                  background=[("active", "#2b4f7e"), ("disabled", "#9aa7b4")])
        style.configure("TCombobox", font=("Segoe UI", 10), padding=4)
        style.configure("Treeview", font=("Consolas", 10), rowheight=24,
                        fieldbackground=PANEL, background=PANEL)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    # ----------------------------------------------------------------- header
    def _build_header(self):
        header = tk.Frame(self.root, bg=ACCENT)
        header.pack(side="top", fill="x")
        tk.Label(header, text="PCAP2SQL", bg=ACCENT, fg=ACCENT_TEXT,
                 font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=18, pady=(12, 0))
        tk.Label(header,
                 text="Parse a packet capture into SQLite and analyse the traffic",
                 bg=ACCENT, fg="#c7d4e3",
                 font=("Segoe UI", 10)).pack(anchor="w", padx=18, pady=(0, 12))

    def _panel(self, title):
        """Create a titled white 'card' frame and return its inner body frame."""
        outer = ttk.Frame(self.root, style="TFrame")
        outer.pack(side="top", fill="x", padx=16, pady=(14, 0))
        card = ttk.Frame(outer, style="Panel.TFrame")
        card.pack(fill="x")
        inner = ttk.Frame(card, style="Panel.TFrame")
        inner.pack(fill="x", padx=16, pady=12)
        ttk.Label(inner, text=title, style="Heading.TLabel").pack(anchor="w", pady=(0, 8))
        return inner

    # --------------------------------------------------------- capture panel
    def _build_capture_panel(self):
        body = self._panel("1.  Capture  →  Database")

        row1 = ttk.Frame(body, style="Panel.TFrame")
        row1.pack(fill="x", pady=(0, 8))
        ttk.Label(row1, text="Capture file:", style="Panel.TLabel").pack(side="left")
        entry = ttk.Entry(row1, textvariable=self.pcap_path)
        entry.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row1, text="Browse…", command=self._browse).pack(side="left")

        row2 = ttk.Frame(body, style="Panel.TFrame")
        row2.pack(fill="x")
        self.btn_generate = ttk.Button(row2, text="Generate sample capture",
                                        command=self._generate_sample)
        self.btn_generate.pack(side="left")
        self.btn_load = ttk.Button(row2, text="Load into database  →",
                                   style="Accent.TButton", command=self._load)
        self.btn_load.pack(side="left", padx=8)
        ttk.Label(body,
                  text="PyShark alternative: this build parses with scapy (no "
                       "Wireshark needed). The database schema and queries are "
                       "identical either way.",
                  style="Muted.TLabel", wraplength=820).pack(anchor="w", pady=(8, 0))

    # -------------------------------------------------------- analysis panel
    def _build_analysis_panel(self):
        body = self._panel("2.  Analyze")

        row = ttk.Frame(body, style="Panel.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="Analysis:", style="Panel.TLabel").pack(side="left")
        self.analysis_choice = tk.StringVar(value=list(core.ANALYSES.keys())[0])
        self.combo = ttk.Combobox(row, textvariable=self.analysis_choice,
                                  values=list(core.ANALYSES.keys()),
                                  state="readonly", width=34)
        self.combo.pack(side="left", padx=8)
        self.combo.bind("<<ComboboxSelected>>", lambda e: self._on_analysis_selected())
        self.btn_run = ttk.Button(row, text="Run analysis",
                                  style="Accent.TButton", command=self._run_analysis)
        self.btn_run.pack(side="left")

        ttk.Label(body, textvariable=self.explanation, style="Muted.TLabel",
                  wraplength=820).pack(anchor="w", pady=(8, 0))

    # --------------------------------------------------------- results panel
    def _build_results_panel(self):
        outer = ttk.Frame(self.root, style="TFrame")
        outer.pack(side="top", fill="both", expand=True, padx=16, pady=(14, 0))
        card = ttk.Frame(outer, style="Panel.TFrame")
        card.pack(fill="both", expand=True)
        inner = ttk.Frame(card, style="Panel.TFrame")
        inner.pack(fill="both", expand=True, padx=16, pady=12)

        ttk.Label(inner, text="Results", style="Heading.TLabel").pack(anchor="w")

        # The results table. Columns are (re)configured per analysis at runtime.
        tree_wrap = ttk.Frame(inner, style="Panel.TFrame")
        tree_wrap.pack(fill="both", expand=True, pady=(6, 10))
        self.tree = ttk.Treeview(tree_wrap, show="headings", height=8)
        vsb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_wrap.rowconfigure(0, weight=1)
        tree_wrap.columnconfigure(0, weight=1)

        # The SQL that produced the current results -- shown so it's clear the
        # database is doing the work, not hidden Python.
        ttk.Label(inner, text="SQL executed", style="Heading.TLabel").pack(anchor="w")
        self.sql_view = tk.Text(inner, height=6, wrap="word", font=("Consolas", 9),
                                bg="#0f1b2a", fg="#d6e4f0", insertbackground="#d6e4f0",
                                relief="flat", padx=10, pady=8)
        self.sql_view.pack(fill="x", pady=(6, 0))
        self.sql_view.configure(state="disabled")

    # ------------------------------------------------------------- statusbar
    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg="#e4e9ef")
        bar.pack(side="bottom", fill="x")
        tk.Label(bar, textvariable=self.status, bg="#e4e9ef", fg=MUTED,
                 anchor="w", font=("Segoe UI", 9), padx=12, pady=5).pack(fill="x")

    # ================================================================ actions
    def _browse(self):
        path = filedialog.askopenfilename(
            title="Choose a packet capture",
            initialdir=DATA_DIR if os.path.isdir(DATA_DIR) else BASE_DIR,
            filetypes=[("Packet captures", "*.pcap *.pcapng *.cap"), ("All files", "*.*")],
        )
        if path:
            self.pcap_path.set(path)
            self.status.set(f"Selected capture: {os.path.basename(path)}")

    def _set_busy(self, busy, msg=None):
        """Enable/disable the action buttons while a background job runs."""
        state = "disabled" if busy else "normal"
        for b in (self.btn_generate, self.btn_load, self.btn_run):
            b.configure(state=state)
        if msg:
            self.status.set(msg)
        self.root.configure(cursor="watch" if busy else "")

    def _run_bg(self, fn, done_msg, tag):
        """Run fn() on a worker thread; post (tag, result_or_exception) to queue."""
        def worker():
            try:
                result = fn()
                self._result_q.put((tag, done_msg, result, None))
            except Exception as exc:                     # report, never crash UI
                self._result_q.put((tag, None, None, exc))
        threading.Thread(target=worker, daemon=True).start()

    def _poll_results(self):
        """Main-thread poller: applies background results to the widgets."""
        try:
            while True:
                tag, done_msg, result, exc = self._result_q.get_nowait()
                self._set_busy(False)
                if exc is not None:
                    messagebox.showerror("Error", f"{type(exc).__name__}: {exc}")
                    self.status.set("Error -- see dialog.")
                    continue
                if tag == "generate":
                    self.pcap_path.set(DEFAULT_PCAP)
                    self.status.set(f"{done_msg}  ({result} packets). "
                                    f"Now click 'Load into database'.")
                elif tag == "load":
                    n_packets, n_flows = result
                    self.status.set(f"{done_msg}  {n_packets} packets, "
                                    f"{n_flows} flows. Pick an analysis and run it.")
                    self._refresh_analysis_enabled()
        except queue.Empty:
            pass
        self.root.after(120, self._poll_results)   # keep polling ~8x/second

    def _generate_sample(self):
        self._set_busy(True, "Generating sample capture…")
        self._run_bg(lambda: core.generate_sample(DEFAULT_PCAP),
                     "Sample capture generated.", "generate")

    def _load(self):
        path = self.pcap_path.get().strip()
        if not path:
            messagebox.showwarning("No capture", "Choose or generate a .pcap first.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Not found", f"File does not exist:\n{path}")
            return
        self._set_busy(True, "Loading capture into database…")
        self._run_bg(lambda: core.load_pcap(path, DEFAULT_DB),
                     "Loaded.", "load")

    def _on_analysis_selected(self):
        name = self.analysis_choice.get()
        self.explanation.set(core.ANALYSES[name]["explanation"])

    def _refresh_analysis_enabled(self):
        ready = core.database_ready(DEFAULT_DB)
        self.btn_run.configure(state="normal" if ready else "disabled")
        if ready and "Ready." in self.status.get():
            self.status.set("Database ready. Pick an analysis and run it.")

    def _run_analysis(self):
        name = self.analysis_choice.get()
        if not core.database_ready(DEFAULT_DB):
            messagebox.showwarning("No database",
                                   "Load a capture into the database first.")
            return
        try:
            headers, rows, sql = core.run_analysis(DEFAULT_DB, name)
        except Exception as exc:
            messagebox.showerror("Query failed", f"{type(exc).__name__}: {exc}")
            return
        self._populate_table(headers, rows)
        self._show_sql(sql)
        self.status.set(f"'{name}' -- {len(rows)} row(s).")

    # --------------------------------------------------------- table helpers
    def _populate_table(self, headers, rows):
        """Rebuild the Treeview's columns and rows for the current analysis."""
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = headers
        for h in headers:
            self.tree.heading(h, text=h)
            # Width heuristic: size to the header, widen a little for data.
            self.tree.column(h, width=max(90, len(h) * 11), anchor="w", stretch=True)
        for r in rows:
            self.tree.insert("", "end", values=r)

    def _show_sql(self, sql):
        self.sql_view.configure(state="normal")
        self.sql_view.delete("1.0", "end")
        self.sql_view.insert("1.0", sql)
        self.sql_view.configure(state="disabled")


def main():
    root = tk.Tk()
    AnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
