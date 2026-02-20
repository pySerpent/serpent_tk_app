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
