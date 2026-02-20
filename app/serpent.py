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
