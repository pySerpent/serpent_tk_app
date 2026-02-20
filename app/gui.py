"""
gui.py

Tkinter (ttk) GUI for the Serpent encryption/decryption app.
"""

from __future__ import annotations

import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .utils import (
    CryptoError,
    ValidationError,
    canonical_key_hex,
    decrypt_text,
    encrypt_text,
    generate_key_hex,
    parse_key_hex,
    read_text_file_utf8,
    write_text_file_utf8,
)

_HEX_ALLOWED_RE = re.compile(r"^[0-9a-fA-FxX\s]*$")


class SerpentGUI(ttk.Frame):
    def __init__(self, master: tk.Misc) -> None:
        super().__init__(master)
        self.master = master

        self.key_var = tk.StringVar()
        self.key_info_var = tk.StringVar(value="Ключ: —")
        self.status_var = tk.StringVar(value="Готово.")
        self.key_size_var = tk.StringVar(value="256")

        self._build_style()
        self._build_layout()
        self._bind_events()

        self.key_var.trace_add("write", lambda *_: self._update_key_info())

    # ---------- UI style ----------

    def _build_style(self) -> None:
        style = ttk.Style()
        for theme in ("clam", "vista", "xpnative", style.theme_use()):
            try:
                style.theme_use(theme)
                break
            except tk.TclError:
                continue

        default_font = ("Segoe UI", 10)
        mono_font = ("Cascadia Mono", 9)

        self.master.option_add("*Font", default_font)
        self.master.option_add("*Text.font", mono_font)

        style.configure("TButton", padding=(10, 6))
        style.configure("TLabel", padding=(2, 2))
        style.configure("TLabelframe", padding=(10, 8))
        style.configure("TLabelframe.Label", padding=(4, 2))
        style.configure("Status.TLabel", anchor="w", padding=(10, 6))
