"""
Entry point for the Serpent tkinter application.
"""

from __future__ import annotations
import tkinter as tk
from app import create_app

def main() -> None:
    root = tk.Tk()
    create_app(root)
    root.mainloop()

if __name__ == "__main__":
    main()