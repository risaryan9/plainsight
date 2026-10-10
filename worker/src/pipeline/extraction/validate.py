"""APK validation that runs before any parsing (spec §9.2).

Only the standard library is used here, and nothing is ever extracted: every check
reads either the first bytes of the file or the ZIP central directory.
"""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass

from .errors import InvalidApkError

__all__ = [
    "MAX_APK_BYTES",
    "MAX_TOTAL_UNCOMPRESSED_BYTES",
    "MAX_ZIP_ENTRIES",
    "InvalidApkError",
    "ValidatedApk",
    "validate_apk",
]

ZIP_MAGIC = b"PK\x03\x04"
MAX_APK_BYTES = 100 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_ZIP_ENTRIES = 50_000

MANIFEST_NAME = "AndroidManifest.xml"
_DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")


@dataclass(frozen=True)
class ValidatedApk:
    """What validation learned about the file, from the central directory only."""

    path: str
    size_bytes: int
    entry_count: int
    total_uncompressed_bytes: int
    dex_names: tuple[str, ...]


def _mb(n_bytes: int) -> str:
    return f"{n_bytes / (1024 * 1024):.1f} MB"


def validate_apk(
    path: str,
    *,
    max_apk_bytes: int = MAX_APK_BYTES,
    max_total_uncompressed_bytes: int = MAX_TOTAL_UNCOMPRESSED_BYTES,
    max_entries: int = MAX_ZIP_ENTRIES,
) -> ValidatedApk:
    """Check that ``path`` looks like a sane APK, or raise :class:`InvalidApkError`."""
    if not os.path.isfile(path):
        raise InvalidApkError(f"No such file: {path}")

    size_bytes = os.path.getsize(path)
    if size_bytes == 0:
        raise InvalidApkError("The file is empty.")
    if size_bytes > max_apk_bytes:
        raise InvalidApkError(
            f"The file is {_mb(size_bytes)}, larger than the {_mb(max_apk_bytes)} limit."
        )

    with open(path, "rb") as fh:
        if fh.read(len(ZIP_MAGIC)) != ZIP_MAGIC:
            raise InvalidApkError("Not an APK: the file does not start with the ZIP signature.")

    try:
        with zipfile.ZipFile(path) as zf:
            # infolist() comes from the central directory; nothing is decompressed.
            infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError) as exc:
        raise InvalidApkError(f"Not an APK: the file cannot be opened as a ZIP ({exc}).") from exc

    if len(infos) > max_entries:
        raise InvalidApkError(
            f"The archive has {len(infos):,} entries, more than the {max_entries:,} allowed."
        )

    total_uncompressed = sum(info.file_size for info in infos)
    if total_uncompressed > max_total_uncompressed_bytes:
        raise InvalidApkError(
            f"The archive would unpack to {_mb(total_uncompressed)}, more than the "
            f"{_mb(max_total_uncompressed_bytes)} allowed (possible zip bomb)."
        )

    names = {info.filename for info in infos}
    if MANIFEST_NAME not in names:
        raise InvalidApkError("Not an APK: the archive has no AndroidManifest.xml.")
    dex_names = tuple(sorted(name for name in names if _DEX_NAME_RE.match(name)))
    if not dex_names:
        raise InvalidApkError("Not an APK: the archive has no classes.dex.")

    return ValidatedApk(
        path=path,
        size_bytes=size_bytes,
        entry_count=len(infos),
        total_uncompressed_bytes=total_uncompressed,
        dex_names=dex_names,
    )
