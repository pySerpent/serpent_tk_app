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
    # ---------- Layout ----------

    def _build_layout(self) -> None:
        self.grid(row=0, column=0, sticky="nsew")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)

        # Header
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        header.columnconfigure(0, weight=1)

        ttk.Label(
            header,
            text="Serpent (CTR) — шифрование и расшифрование",
            font=("Segoe UI", 12, "bold"),
        ).grid(row=0, column=0, sticky="w")

        ttk.Label(
            header,
            text="Формат шифртекста: v1:<nonce_base64>:<ciphertext_base64>",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        # Key frame
        key_frame = ttk.Labelframe(self, text="Ключ (hex)")
        key_frame.grid(row=1, column=0, sticky="ew", padx=12, pady=6)
        key_frame.columnconfigure(0, weight=1)

        self._key_entry = ttk.Entry(
            key_frame,
            textvariable=self.key_var,
            validate="key",
            validatecommand=(self.register(self._validate_key_entry), "%P"),
        )
        self._key_entry.grid(row=0, column=0, sticky="ew", padx=(4, 8), pady=(4, 2))

        controls = ttk.Frame(key_frame)
        controls.grid(row=0, column=1, sticky="e", padx=(0, 4), pady=(4, 2))

        ttk.Label(controls, text="Размер:").grid(row=0, column=0, padx=(0, 6))

        size_combo = ttk.Combobox(
            controls,
            textvariable=self.key_size_var,
            values=("128", "192", "256"),
            width=6,
            state="readonly",
        )
        size_combo.grid(row=0, column=1, padx=(0, 8))

        ttk.Button(controls, text="Сгенерировать", command=self._generate_key).grid(
            row=0, column=2, padx=(0, 8)
        )
        ttk.Button(controls, text="Загрузить…", command=self._load_key_from_file).grid(
            row=0, column=3, padx=(0, 8)
        )
        ttk.Button(controls, text="Сохранить…", command=self._save_key_to_file).grid(
            row=0, column=4, padx=(0, 8)
        )
        ttk.Button(controls, text="Какой ключ?", command=self._show_key_help).grid(
            row=0, column=5, padx=(0, 8)
        )
        ttk.Button(controls, text="Очистить", command=self._clear_key).grid(
            row=0, column=6
        )

        ttk.Label(key_frame, textvariable=self.key_info_var).grid(
            row=1, column=0, columnspan=2, sticky="w", padx=4, pady=(0, 4)
        )
