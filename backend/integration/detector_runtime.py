"""Resolve and verify the bundled eleVADR detector package for local handoff use."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any


def _vendor_root() -> Path:
    return Path(__file__).resolve().parents[1] / "vendor"


def ensure_detector_package() -> tuple[Any, Any, Path]:
    """Ensure the vendored detector package is importable and return core objects.

    Returns ``(AnalysisContext, MODULES, module_file)``. This function intentionally
    repairs ``sys.path`` at the service boundary so it does not depend on launcher
    environment variables or package-import side effects.
    """
    vendor_root = _vendor_root()
    package_dir = vendor_root / "elevadr_modules"
    if not package_dir.is_dir():
        raise ImportError(
            f"Bundled detector package is missing: expected {package_dir}"
        )

    vendor_text = str(vendor_root)
    if vendor_text not in sys.path:
        sys.path.insert(0, vendor_text)

    try:
        models = importlib.import_module("elevadr_modules.models")
        registry = importlib.import_module("elevadr_modules.registry")
        package = importlib.import_module("elevadr_modules")
    except ImportError as exc:
        raise ImportError(
            f"Unable to import bundled detector package from {vendor_root}: {exc}"
        ) from exc

    modules = getattr(registry, "MODULES", None)
    if not isinstance(modules, dict):
        raise ImportError("elevadr_modules.registry.MODULES is missing or invalid")
    if len(modules) != 75:
        raise ImportError(
            f"Expected 75 detector modules, found {len(modules)} in {registry.__file__}"
        )

    context_type = getattr(models, "AnalysisContext", None)
    if context_type is None:
        raise ImportError("elevadr_modules.models.AnalysisContext is missing")

    return context_type, modules, Path(package.__file__).resolve()
