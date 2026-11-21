"""Built-in detectors.

Third-party detectors can be registered through the ``chainmail.detectors``
entry-point group; each entry point must resolve to a :class:`Detector`
subclass (or a module that registers detectors on import).
"""

from __future__ import annotations

import importlib
from importlib import metadata

from .base import Detector, DetectorContext, all_detectors, get_detector, register

BUILTIN_MODULES = (
    "reentrancy",
    "calls",
    "access_control",
    "arithmetic",
    "randomness",
    "compiler",
    "crypto",
    "dos",
    "defi",
    "quality",
)

_loaded = False


def load_builtin_detectors() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    for name in BUILTIN_MODULES:
        importlib.import_module(f"{__name__}.{name}")
    _load_plugins()


def _load_plugins() -> None:
    try:
        eps = metadata.entry_points(group="chainmail.detectors")
    except Exception:  # pragma: no cover - very old importlib.metadata
        return
    for ep in eps:
        try:
            obj = ep.load()
        except Exception as exc:  # pragma: no cover - plugin errors are user errors
            import warnings

            warnings.warn(f"failed to load chainmail plugin {ep.name!r}: {exc}", stacklevel=2)
            continue
        if isinstance(obj, type) and issubclass(obj, Detector):
            register(obj)


__all__ = ["Detector", "DetectorContext", "all_detectors", "get_detector", "register", "load_builtin_detectors"]
