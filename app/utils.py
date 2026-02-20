"""
utils.py

High-level helpers for the Serpent tkinter app.

- Validates/parses user inputs (key, plaintext, ciphertext container)
- Implements Serpent-CTR (padding-free)
- Packs/unpacks encrypted data into a printable container
- Generates random keys
- Reads/writes UTF-8 text files with size limits
"""

from __future__ import annotations

import base64
import binascii
import secrets
from typing import Tuple

from .serpent import SerpentCipher

# -------- Configuration --------

MAX_TEXT_BYTES = 1_000_000  # 1 MB safety limit
NONCE_SIZE = 8              # bytes
COUNTER_SIZE = 8            # bytes
CONTAINER_VERSION = "v1"
CONTAINER_ALG = "serpent-ctr"


# -------- Exceptions --------

class AppError(Exception):
    """Base class for app-level errors."""
    pass


class ValidationError(AppError):
    """Raised when user input is missing or malformed."""
    pass


class CryptoError(AppError):
    """Raised when decryption fails or plaintext cannot be decoded."""
    pass
# -------- Key / Text parsing --------

def parse_key_hex(key_hex: str) -> bytes:
    if key_hex is None:
        raise ValidationError("Ключ не задан.")

    s = "".join(key_hex.strip().split())
    if not s:
        raise ValidationError("Ключ не задан.")

    if s.startswith(("0x", "0X")):
        s = s[2:]

    if len(s) % 2 != 0:
        raise ValidationError("Ключ в hex должен иметь чётную длину (по 2 символа на байт).")

    try:
        key_bytes = bytes.fromhex(s)
    except ValueError as exc:
        raise ValidationError("Ключ содержит недопустимые символы. Ожидается hex (0-9, a-f).") from exc

    if len(key_bytes) not in (16, 24, 32):
        raise ValidationError(
            "Некорректная длина ключа. Допустимо: 128/192/256 бит "
            "(16/24/32 байта; 64/96/128 hex-символов)."
        )

    return key_bytes


def canonical_key_hex(key_hex: str) -> str:
    """
    Convert user-entered hex key into canonical lowercase hex without spaces.
    Raises ValidationError if invalid.
    """
    key_bytes = parse_key_hex(key_hex)
    return key_bytes.hex()
