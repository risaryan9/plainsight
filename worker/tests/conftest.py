from __future__ import annotations

import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

ZipMaker = Callable[[Mapping[str, bytes]], Path]


@pytest.fixture
def make_zip(tmp_path: Path) -> ZipMaker:
    """Build a throwaway ZIP with the given entries and return its path."""

    def _make(entries: Mapping[str, bytes]) -> Path:
        path = tmp_path / "sample.apk"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return path

    return _make
