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
