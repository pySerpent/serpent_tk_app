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
    def _create_text_with_scrollbar(self, parent: ttk.Labelframe, *, row: int) -> tk.Text:
        """
        Create Text + vertical scrollbar in the SAME container frame.
        This prevents misalignment issues.
        """
        container = ttk.Frame(parent)
        container.grid(row=row, column=0, sticky="nsew", padx=4, pady=4)
        parent.columnconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        text = tk.Text(
            container,
            wrap="word",
            height=14,
            undo=True,
            borderwidth=1,
            relief="solid",
        )
        vsb = ttk.Scrollbar(container, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vsb.set)

        text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        return text

    # ---------- Hotkeys ----------

    def _bind_events(self) -> None:
        self.master.bind_all("<Control-Return>", lambda _e: self._encrypt())
        self.master.bind_all("<Control-Shift-Return>", lambda _e: self._decrypt())
        self.master.bind_all("<Control-l>", lambda _e: self._clear_all())
        self.master.after(50, self._update_key_info)

    # ---------- Helpers ----------

    def _get_plain(self) -> str:
        return self.plain_text.get("1.0", "end-1c")

    def _set_plain(self, value: str) -> None:
        self.plain_text.delete("1.0", "end")
        self.plain_text.insert("1.0", value)

    def _get_cipher(self) -> str:
        return self.cipher_text.get("1.0", "end-1c")

    def _set_cipher(self, value: str) -> None:
        self.cipher_text.delete("1.0", "end")
        self.cipher_text.insert("1.0", value)

    def _set_status(self, message: str) -> None:
        self.status_var.set(message)

    # ---------- Key validation ----------

    def _validate_key_entry(self, proposed: str) -> bool:
        if proposed == "":
            return True
        return _HEX_ALLOWED_RE.match(proposed) is not None

    def _update_key_info(self) -> None:
        key_s = self.key_var.get()

        if not key_s.strip():
            self.key_info_var.set("Ключ: — (введите 64/96/128 hex-символов для 128/192/256 бит)")
            self._btn_encrypt.state(["disabled"])
            self._btn_decrypt.state(["disabled"])
            return

        try:
            key_bytes = parse_key_hex(key_s)
            bits = len(key_bytes) * 8
            self.key_info_var.set(f"Ключ: корректный ({bits} бит)")
            self._btn_encrypt.state(["!disabled"])
            self._btn_decrypt.state(["!disabled"])
        except ValidationError as exc:
            self.key_info_var.set(f"Ключ: ошибка — {exc}")
            self._btn_encrypt.state(["disabled"])
            self._btn_decrypt.state(["disabled"])
        # Body
        body = ttk.Frame(self)
        body.grid(row=2, column=0, sticky="nsew", padx=12, pady=6)
        self.rowconfigure(2, weight=1)
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=0)
        body.columnconfigure(2, weight=1)

        # Plaintext panel
        plain_box = ttk.Labelframe(body, text="Открытый текст")
        plain_box.grid(row=0, column=0, sticky="nsew")
        plain_box.columnconfigure(0, weight=1)
        plain_box.rowconfigure(1, weight=1)

        plain_toolbar = ttk.Frame(plain_box)
        plain_toolbar.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 0))
        plain_toolbar.columnconfigure(0, weight=1)

        ttk.Button(plain_toolbar, text="Загрузить…", command=self._load_plain_from_file).grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )
        ttk.Button(plain_toolbar, text="Сохранить…", command=self._save_plain_to_file).grid(
            row=0, column=1, sticky="w"
        )

        self.plain_text = self._create_text_with_scrollbar(plain_box, row=1)

        # Middle buttons
        mid = ttk.Frame(body)
        mid.grid(row=0, column=1, sticky="ns", padx=10)
        mid.columnconfigure(0, weight=1)

        self._btn_encrypt = ttk.Button(mid, text="Зашифровать →", command=self._encrypt)
        self._btn_encrypt.grid(row=0, column=0, sticky="ew", pady=(8, 8))

        self._btn_decrypt = ttk.Button(mid, text="← Расшифровать", command=self._decrypt)
        self._btn_decrypt.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        ttk.Separator(mid).grid(row=2, column=0, sticky="ew", pady=10)

        ttk.Button(mid, text="Копировать текст", command=self._copy_plain).grid(
            row=3, column=0, sticky="ew", pady=(0, 8)
        )
        ttk.Button(mid, text="Копировать шифртекст", command=self._copy_cipher).grid(
            row=4, column=0, sticky="ew", pady=(0, 8)
        )
        ttk.Button(mid, text="Очистить всё", command=self._clear_all).grid(
            row=5, column=0, sticky="ew"
        )

        # Ciphertext panel
        cipher_box = ttk.Labelframe(body, text="Шифртекст (контейнер)")
        cipher_box.grid(row=0, column=2, sticky="nsew")
        cipher_box.columnconfigure(0, weight=1)
        cipher_box.rowconfigure(1, weight=1)

        cipher_toolbar = ttk.Frame(cipher_box)
        cipher_toolbar.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 0))
        cipher_toolbar.columnconfigure(0, weight=1)

        ttk.Button(cipher_toolbar, text="Загрузить…", command=self._load_cipher_from_file).grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )
        ttk.Button(cipher_toolbar, text="Сохранить…", command=self._save_cipher_to_file).grid(
            row=0, column=1, sticky="w"
        )

        self.cipher_text = self._create_text_with_scrollbar(cipher_box, row=1)

        # Status bar
        ttk.Label(self, textvariable=self.status_var, style="Status.TLabel").grid(
            row=3, column=0, sticky="ew", pady=(6, 0)
        )
        ttk.Frame(self).grid(row=4, column=0, sticky="ew", pady=(0, 10))
    # ---------- File dialogs ----------

    def _ask_open_txt(self, title: str) -> str:
        return filedialog.askopenfilename(
            parent=self.master,
            title=title,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )

    def _ask_save_txt(self, title: str, default_name: str) -> str:
        return filedialog.asksaveasfilename(
            parent=self.master,
            title=title,
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )

    # ---------- Actions: key ----------

    def _generate_key(self) -> None:
        try:
            bits = int(self.key_size_var.get())
            self.key_var.set(generate_key_hex(bits, grouped=True))
            self._set_status(f"Сгенерирован ключ {bits} бит.")
        except (ValueError, ValidationError) as exc:
            self._set_status(f"Ошибка генерации ключа: {exc}")
            messagebox.showerror("Ошибка", str(exc), parent=self.master)

    def _load_key_from_file(self) -> None:
        path = self._ask_open_txt("Выберите файл с ключом (UTF-8)")
        if not path:
            return
        try:
            content = read_text_file_utf8(path, max_bytes=50_000).strip()
            self.key_var.set(content)
            self._set_status("Ключ загружен из файла.")
        except ValidationError as exc:
            self._set_status(f"Ошибка загрузки ключа: {exc}")
            messagebox.showerror("Ошибка", str(exc), parent=self.master)

    def _save_key_to_file(self) -> None:
        path = self._ask_save_txt("Сохранить ключ в файл", "key_hex.txt")
        if not path:
            return
        try:
            key_canon = canonical_key_hex(self.key_var.get())
            write_text_file_utf8(path, key_canon + "\n", max_bytes=50_000)
            self._set_status("Ключ сохранён.")
        except ValidationError as exc:
            self._set_status(f"Ошибка сохранения ключа: {exc}")
            messagebox.showerror("Ошибка", str(exc), parent=self.master)

    def _clear_key(self) -> None:
        self.key_var.set("")
        self._set_status("Ключ очищен.")
    # ---------- Actions: load/save plain/cipher ----------

    def _load_plain_from_file(self) -> None:
        path = self._ask_open_txt("Выберите текстовый файл (UTF-8)")
        if not path:
            return
        try:
            self._set_plain(read_text_file_utf8(path))
            self._set_status("Открытый текст загружен из файла.")
        except ValidationError as exc:
            self._set_status(f"Ошибка загрузки: {exc}")
            messagebox.showerror("Ошибка загрузки", str(exc), parent=self.master)

    def _save_plain_to_file(self) -> None:
        path = self._ask_save_txt("Сохранить открытый текст", "plaintext.txt")
        if not path:
            return
        try:
            write_text_file_utf8(path, self._get_plain())
            self._set_status("Открытый текст сохранён.")
        except ValidationError as exc:
            self._set_status(f"Ошибка сохранения: {exc}")
            messagebox.showerror("Ошибка сохранения", str(exc), parent=self.master)
    def _load_cipher_from_file(self) -> None:
        path = self._ask_open_txt("Выберите файл с контейнером шифртекста (UTF-8)")
        if not path:
            return
        try:
            content = read_text_file_utf8(path, max_bytes=2_000_000).strip()
            self._set_cipher(content)
            self._set_status("Шифртекст загружен из файла.")
        except ValidationError as exc:
            self._set_status(f"Ошибка загрузки: {exc}")
            messagebox.showerror("Ошибка загрузки", str(exc), parent=self.master)

    def _save_cipher_to_file(self) -> None:
        path = self._ask_save_txt("Сохранить шифртекст (контейнер)", "cipher_container.txt")
        if not path:
            return
        try:
            write_text_file_utf8(path, self._get_cipher().strip() + "\n", max_bytes=2_000_000)
            self._set_status("Шифртекст сохранён.")
        except ValidationError as exc:
            self._set_status(f"Ошибка сохранения: {exc}")
            messagebox.showerror("Ошибка сохранения", str(exc), parent=self.master)
    # ---------- Actions: encrypt/decrypt ----------

    def _encrypt(self) -> None:
        try:
            result = encrypt_text(plaintext=self._get_plain(), key_hex=self.key_var.get())
            self._set_cipher(result)
            self._set_status("Шифрование выполнено.")
        except ValidationError as exc:
            self._set_status(f"Ошибка ввода: {exc}")
            messagebox.showerror("Ошибка ввода", str(exc), parent=self.master)
        except Exception as exc:
            self._set_status("Внутренняя ошибка при шифровании.")
            messagebox.showerror("Внутренняя ошибка", f"{exc}", parent=self.master)

    def _decrypt(self) -> None:
        try:
            result = decrypt_text(container=self._get_cipher(), key_hex=self.key_var.get())
            self._set_plain(result)
            self._set_status("Расшифрование выполнено.")
        except (ValidationError, CryptoError) as exc:
            title = "Ошибка ввода" if isinstance(exc, ValidationError) else "Ошибка расшифрования"
            self._set_status(f"{title}: {exc}")
            messagebox.showerror(title, str(exc), parent=self.master)
        except Exception as exc:
            self._set_status("Внутренняя ошибка при расшифровании.")
            messagebox.showerror("Внутренняя ошибка", f"{exc}", parent=self.master)
    # ---------- Clipboard / clear ----------

    def _copy_plain(self) -> None:
        text = self._get_plain()
        if not text.strip():
            self._set_status("Нечего копировать: поле текста пустое.")
            return
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        self.master.update_idletasks()
        self._set_status("Текст скопирован в буфер обмена.")

    def _copy_cipher(self) -> None:
        text = self._get_cipher()
        if not text.strip():
            self._set_status("Нечего копировать: поле шифртекста пустое.")
            return
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        self.master.update_idletasks()
        self._set_status("Шифртекст скопирован в буфер обмена.")

    def _clear_all(self) -> None:
        self._set_plain("")
        self._set_cipher("")
        self._set_status("Поля очищены.")

    # ---------- Help ----------

    def _show_key_help(self) -> None:
        message = (
            "Ключ вводится в формате HEX.\n\n"
            "Допустимые длины ключа Serpent:\n"
            "• 128 бит  = 16 байт  = 64 hex-символа\n"
            "• 192 бита = 24 байта = 96 hex-символов\n"
            "• 256 бит  = 32 байта = 128 hex-символов\n\n"
            "Пробелы игнорируются. Префикс 0x допускается.\n"
            "Можно сгенерировать ключ и сохранить его в файл."
        )
        messagebox.showinfo("Подсказка по ключу", message, parent=self.master)


def setup_main_window(root: tk.Tk) -> None:
    root.title("Serpent (CTR) — Tkinter")
    root.minsize(980, 620)
    root.rowconfigure(0, weight=1)
    root.columnconfigure(0, weight=1)


def create_app(root: tk.Tk) -> SerpentGUI:
    setup_main_window(root)
    return SerpentGUI(root)
