"""Isolated backend handoff package for eleVADR Detection Context.

The production backend is intentionally not modified by this package. For local
handoff/testing, the detector package is vendored under backend_bryan/vendor.
This package bootstrap adds that vendor root to sys.path so imports such as
``from elevadr_modules.registry import MODULES`` work on Windows and Unix
without requiring pip installation or launcher-specific PYTHONPATH behavior.
"""
from __future__ import annotations

import sys
from pathlib import Path

_VENDOR_ROOT = Path(__file__).resolve().parent / "vendor"
if _VENDOR_ROOT.is_dir():
    vendor_text = str(_VENDOR_ROOT)
    if vendor_text not in sys.path:
        sys.path.insert(0, vendor_text)
