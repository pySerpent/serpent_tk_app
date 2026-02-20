"""
app package for the Serpent tkinter application.

This package contains:
- serpent.py : Serpent block cipher core (encrypt/decrypt 16-byte blocks)
- utils.py   : input validation + Serpent-CTR mode + container helpers
- gui.py     : tkinter/ttk user interface

Public API:
- create_app (GUI factory)
"""

from __future__ import annotations

__all__ = ["__version__", "create_app"]

__version__ = "1.0.0"

from .gui import create_app  # noqa: E402
