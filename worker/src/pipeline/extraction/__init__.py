"""Static APK extraction (spec §7.7).

    from pipeline.extraction import InvalidApkError, analyze_apk

    facts = analyze_apk("/path/to/app.apk")   # JSON-serialisable dict

Androguard is imported on first use, not when this package is imported.
"""

from __future__ import annotations

from typing import Any

from .errors import InvalidApkError
from .models import SCHEMA_VERSION, ExtractionResult

__all__ = [
    "SCHEMA_VERSION",
    "ExtractionResult",
    "InvalidApkError",
    "analyze_apk",
    "extract",
    "set_parser_log_level",
]


def analyze_apk(path: str) -> dict[str, Any]:
    """Statically analyse the APK at ``path`` and return a JSON-serialisable dict."""
    from .analyze import analyze_apk as _analyze_apk

    return _analyze_apk(path)


def extract(path: str) -> ExtractionResult:
    """Like :func:`analyze_apk`, but returns the typed pydantic model."""
    from .analyze import extract as _extract

    return _extract(path)


def set_parser_log_level(level: str) -> None:
    """Drop the APK parser's (Androguard's) log records below ``level``, e.g. ``"ERROR"``."""
    from .androguard_adapter import configure_logging

    configure_logging(level)
