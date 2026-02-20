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
def generate_key_hex(bits: int, *, grouped: bool = True) -> str:
    if bits not in (128, 192, 256):
        raise ValidationError("Размер ключа должен быть 128/192/256 бит.")

    raw = secrets.token_bytes(bits // 8)
    hex_str = raw.hex()

    if not grouped:
        return hex_str

    chunks = [hex_str[i:i + 8] for i in range(0, len(hex_str), 8)]
    return " ".join(chunks)
def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_SIZE)


def _make_counter_block(nonce: bytes, counter: int) -> bytes:
    if counter < 0 or counter > 0xFFFFFFFFFFFFFFFF:
        raise ValidationError("Счётчик CTR вышел за допустимые пределы.")
    return nonce + counter.to_bytes(COUNTER_SIZE, byteorder="big", signed=False)


def serpent_ctr_crypt(cipher: SerpentCipher, nonce: bytes, data: bytes) -> bytes:
    if len(nonce) != NONCE_SIZE:
        raise ValidationError(f"Nonce должен быть длиной {NONCE_SIZE} байт.")

    if data is None:
        data = b""

    out = bytearray(len(data))
    counter = 0
    offset = 0

    while offset < len(data):
        counter_block = _make_counter_block(nonce, counter)
        keystream = cipher.encrypt_block(counter_block)

        chunk = data[offset: offset + 16]
        out[offset: offset + len(chunk)] = _xor_bytes(chunk, keystream[:len(chunk)])

        offset += len(chunk)
        counter = (counter + 1) & 0xFFFFFFFFFFFFFFFF

    return bytes(out)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Internal error: XOR length mismatch.")
    return bytes(x ^ y for x, y in zip(a, b))
# -------- Container --------

def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(s: str, *, field_name: str) -> bytes:
    if s is None:
        raise ValidationError(f"Отсутствует поле {field_name} в контейнере.")

    s2 = s.strip()
    if not s2:
        raise ValidationError(f"Пустое поле {field_name} в контейнере.")

    try:
        return base64.b64decode(s2, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError(f"Поле {field_name} не является корректным base64.") from exc


def pack_container(*, nonce: bytes, ciphertext: bytes) -> str:
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Internal error: invalid nonce length.")

    n_b64 = _b64encode(nonce)
    c_b64 = _b64encode(ciphertext)
    return f"{CONTAINER_VERSION}:{n_b64}:{c_b64}"


def unpack_container(container: str) -> Tuple[bytes, bytes]:
    if container is None:
        raise ValidationError("Поле шифртекста пустое.")

    s = container.strip()
    if not s:
        raise ValidationError("Поле шифртекста пустое.")

    parts = s.split(":")
    if len(parts) == 3:
        ver, nonce_b64, ct_b64 = parts
        alg = None
    elif len(parts) == 4:
        ver, alg, nonce_b64, ct_b64 = parts
    else:
        raise ValidationError(
            "Неверный формат шифртекста. Ожидается контейнер вида "
            "'v1:<nonce_b64>:<ciphertext_b64>'."
        )

    if ver != CONTAINER_VERSION:
        raise ValidationError(
            f"Неподдерживаемая версия контейнера: {ver!r}. Ожидается {CONTAINER_VERSION!r}."
        )

    if alg is not None and alg != CONTAINER_ALG:
        raise ValidationError(
            f"Неподдерживаемый алгоритм/режим: {alg!r}. Ожидается {CONTAINER_ALG!r}."
        )

    nonce = _b64decode(nonce_b64, field_name="nonce")
    if len(nonce) != NONCE_SIZE:
        raise ValidationError(
            f"Некорректная длина nonce: {len(nonce)} байт. Ожидается {NONCE_SIZE} байт."
        )

    ciphertext = _b64decode(ct_b64, field_name="ciphertext")
    return nonce, ciphertext
