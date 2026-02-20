"""
serpent.py

Pure-Python implementation of the Serpent block cipher (NESSIE finalist).

- Block size: 128 bits (16 bytes)
- Key sizes: 128 / 192 / 256 bits (16 / 24 / 32 bytes)
- Rounds: 32
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Sequence, Tuple


_MASK32 = 0xFFFFFFFF
_PHI = 0x9E3779B9  # fractional part of golden ratio


# 8 Serpent S-boxes, each mapping 4-bit -> 4-bit (0..15)
_SBOXES: Tuple[Tuple[int, ...], ...] = (
    (3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12),   # S0
    (15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4),   # S1
    (8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2),   # S2
    (0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14),   # S3
    (1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13),   # S4
    (15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1),   # S5
    (7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0),   # S6
    (1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6),   # S7
)
def _invert_sbox(sbox: Sequence[int]) -> Tuple[int, ...]:
    inv = [0] * 16
    for i, v in enumerate(sbox):
        inv[v] = i
    return tuple(inv)


_INV_SBOXES: Tuple[Tuple[int, ...], ...] = tuple(_invert_sbox(s) for s in _SBOXES)


def _rotl32(x: int, n: int) -> int:
    x &= _MASK32
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _rotr32(x: int, n: int) -> int:
    x &= _MASK32
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _words_from_block(block16: bytes) -> Tuple[int, int, int, int]:
    if len(block16) != 16:
        raise ValueError("Block must be exactly 16 bytes (128 bits).")
    return struct.unpack("<4I", block16)


def _block_from_words(words4: Tuple[int, int, int, int]) -> bytes:
    a0, a1, a2, a3 = (w & _MASK32 for w in words4)
    return struct.pack("<4I", a0, a1, a2, a3)
def _permute_ip(words4: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    """
    Initial Permutation (IP): transpose bits into bit-slice form.
    """
    in_w = words4
    out_w = [0, 0, 0, 0]

    for p in range(128):
        in_word = p // 32
        in_bit = p % 32
        bit = (in_w[in_word] >> in_bit) & 1

        q = 32 * (p % 4) + (p // 4)
        out_word = q // 32
        out_bit = q % 32
        out_w[out_word] |= bit << out_bit

    return (out_w[0] & _MASK32, out_w[1] & _MASK32, out_w[2] & _MASK32, out_w[3] & _MASK32)


def _permute_fp(words4: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    """
    Final Permutation (FP): inverse of IP.
    """
    in_w = words4
    out_w = [0, 0, 0, 0]

    for q in range(128):
        in_word = q // 32
        in_bit = q % 32
        bit = (in_w[in_word] >> in_bit) & 1

        p = 4 * (q % 32) + (q // 32)
        out_word = p // 32
        out_bit = p % 32
        out_w[out_word] |= bit << out_bit

    return (out_w[0] & _MASK32, out_w[1] & _MASK32, out_w[2] & _MASK32, out_w[3] & _MASK32)
def _apply_sbox_bitslice(
    words4: Tuple[int, int, int, int],
    sbox: Sequence[int],
) -> Tuple[int, int, int, int]:
    """
    Apply a 4-bit S-box in *bit-slice* form.
    """
    x0, x1, x2, x3 = (w & _MASK32 for w in words4)
    y0 = y1 = y2 = y3 = 0

    for j in range(32):
        v = ((x0 >> j) & 1) | (((x1 >> j) & 1) << 1) | (((x2 >> j) & 1) << 2) | (((x3 >> j) & 1) << 3)
        u = sbox[v] & 0xF
        y0 |= (u & 1) << j
        y1 |= ((u >> 1) & 1) << j
        y2 |= ((u >> 2) & 1) << j
        y3 |= ((u >> 3) & 1) << j

    return (y0 & _MASK32, y1 & _MASK32, y2 & _MASK32, y3 & _MASK32)
def _lt(words4: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    """
    Serpent linear transform (LT), operating on 4x32-bit words.
    """
    x0, x1, x2, x3 = (w & _MASK32 for w in words4)

    x0 = _rotl32(x0, 13)
    x2 = _rotl32(x2, 3)
    x1 = (x1 ^ x0 ^ x2) & _MASK32
    x3 = (x3 ^ x2 ^ ((x0 << 3) & _MASK32)) & _MASK32
    x1 = _rotl32(x1, 1)
    x3 = _rotl32(x3, 7)
    x0 = (x0 ^ x1 ^ x3) & _MASK32
    x2 = (x2 ^ x3 ^ ((x1 << 7) & _MASK32)) & _MASK32
    x0 = _rotl32(x0, 5)
    x2 = _rotl32(x2, 22)

    return (x0, x1, x2, x3)


def _inv_lt(words4: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    """
    Inverse of Serpent LT.
    """
    x0, x1, x2, x3 = (w & _MASK32 for w in words4)

    x2 = _rotr32(x2, 22)
    x0 = _rotr32(x0, 5)
    x2 = (x2 ^ x3 ^ ((x1 << 7) & _MASK32)) & _MASK32
    x0 = (x0 ^ x1 ^ x3) & _MASK32
    x3 = _rotr32(x3, 7)
    x1 = _rotr32(x1, 1)
    x3 = (x3 ^ x2 ^ ((x0 << 3) & _MASK32)) & _MASK32
    x1 = (x1 ^ x0 ^ x2) & _MASK32
    x2 = _rotr32(x2, 3)
    x0 = _rotr32(x0, 13)

    return (x0, x1, x2, x3)
def _pad_user_key(key: bytes) -> bytes:
    """
    Serpent key padding to 256 bits.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes (128/192/256 bits).")
    if len(key) == 32:
        return key
    # append 0x01 then zeros to reach 32 bytes total
    padded = key + b"\x01" + b"\x00" * (31 - len(key))
    return padded


def _make_subkeys(user_key: bytes) -> List[Tuple[int, int, int, int]]:
    """
    Key schedule: generate 33 round keys from user key.
    """
    key256 = _pad_user_key(user_key)
    w = [0] * 140  # indices 0..139 correspond to w[-8]..w[131]

    k_words = struct.unpack("<8I", key256)  # little-endian
    for i in range(8):
        w[i] = k_words[i] & _MASK32  # w[-8 + i]

    # Expand: for i=0..131, compute w[i] (stored at w[i+8])
    for i in range(132):
        t = (w[i] ^ w[i + 3] ^ w[i + 5] ^ w[i + 7] ^ _PHI ^ i) & _MASK32
        w[i + 8] = _rotl32(t, 11)

    # Build subkeys K[0..32]
    subkeys: List[Tuple[int, int, int, int]] = []
    for r in range(33):
        a0 = w[4 * r + 8]
        a1 = w[4 * r + 9]
        a2 = w[4 * r + 10]
        a3 = w[4 * r + 11]
        # Key schedule uses S-boxes in reverse order
        sbox = _SBOXES[(3 - r) % 8]
        k = _apply_sbox_bitslice((a0, a1, a2, a3), sbox)
        subkeys.append(k)

    return subkeys
@dataclass(frozen=True)
class SerpentCipher:
    """
    Serpent block cipher.

    Usage:
        cipher = SerpentCipher(key_bytes)
        c = cipher.encrypt_block(plaintext16)
        p = cipher.decrypt_block(ciphertext16)
    """
    key: bytes
    _subkeys: Tuple[Tuple[int, int, int, int], ...] = ()

    def __post_init__(self) -> None:
        subkeys = _make_subkeys(self.key)
        object.__setattr__(self, "_subkeys", tuple(subkeys))

    def encrypt_block(self, block16: bytes) -> bytes:
        x = _words_from_block(block16)
        x = _permute_ip(x)

        # 32 rounds
        for r in range(32):
            k = self._subkeys[r]
            x = ((x[0] ^ k[0]) & _MASK32, (x[1] ^ k[1]) & _MASK32,
                 (x[2] ^ k[2]) & _MASK32, (x[3] ^ k[3]) & _MASK32)
            x = _apply_sbox_bitslice(x, _SBOXES[r % 8])
            if r != 31:
                x = _lt(x)

        # Final whitening
        kf = self._subkeys[32]
        x = ((x[0] ^ kf[0]) & _MASK32, (x[1] ^ kf[1]) & _MASK32,
             (x[2] ^ kf[2]) & _MASK32, (x[3] ^ kf[3]) & _MASK32)

        x = _permute_fp(x)
        return _block_from_words(x)

    def decrypt_block(self, block16: bytes) -> bytes:
        x = _words_from_block(block16)
        x = _permute_ip(x)

        # Undo final whitening
        kf = self._subkeys[32]
        x = ((x[0] ^ kf[0]) & _MASK32, (x[1] ^ kf[1]) & _MASK32,
             (x[2] ^ kf[2]) & _MASK32, (x[3] ^ kf[3]) & _MASK32)

        # Inverse rounds: r = 31..0
        for r in range(31, -1, -1):
            if r != 31:
                x = _inv_lt(x)
            x = _apply_sbox_bitslice(x, _INV_SBOXES[r % 8])
            k = self._subkeys[r]
            x = ((x[0] ^ k[0]) & _MASK32, (x[1] ^ k[1]) & _MASK32,
                 (x[2] ^ k[2]) & _MASK32, (x[3] ^ k[3]) & _MASK32)

        x = _permute_fp(x)
        return _block_from_words(x)


# Optional minimal sanity check (round-trip)
if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # 128-bit
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = SerpentCipher(key)
    ct = cipher.encrypt_block(pt)
    rt = cipher.decrypt_block(ct)
    assert rt == pt, "Serpent round-trip self-test failed."
    print("Serpent round-trip self-test OK.")
