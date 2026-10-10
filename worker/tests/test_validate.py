from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

import pytest

from pipeline.extraction import InvalidApkError, analyze_apk
from pipeline.extraction.validate import MAX_ZIP_ENTRIES, validate_apk

ZipMaker = Callable[[Mapping[str, bytes]], Path]

MINIMAL = {"AndroidManifest.xml": b"not really a manifest", "classes.dex": b"not really dex"}


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(InvalidApkError, match="No such file"):
        validate_apk(str(tmp_path / "nope.apk"))


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "empty.apk"
    path.write_bytes(b"")
    with pytest.raises(InvalidApkError, match="empty"):
        validate_apk(str(path))


def test_non_zip_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "fake.apk"
    path.write_bytes(b"MZ this is not a zip archive at all" * 10)
    with pytest.raises(InvalidApkError, match="ZIP signature"):
        validate_apk(str(path))


def test_zip_magic_but_corrupt_archive_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.apk"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    with pytest.raises(InvalidApkError, match="cannot be opened as a ZIP"):
        validate_apk(str(path))


def test_zip_without_manifest_is_rejected(make_zip: ZipMaker) -> None:
    path = make_zip({"classes.dex": b"dex", "res/readme.txt": b"hello"})
    with pytest.raises(InvalidApkError, match=r"no AndroidManifest\.xml"):
        validate_apk(str(path))


def test_zip_without_dex_is_rejected(make_zip: ZipMaker) -> None:
    path = make_zip({"AndroidManifest.xml": b"x", "assets/classes.dex": b"not at the root"})
    with pytest.raises(InvalidApkError, match=r"no classes\.dex"):
        validate_apk(str(path))


def test_oversized_entry_list_is_rejected(make_zip: ZipMaker) -> None:
    entries = dict(MINIMAL)
    entries.update({f"res/file_{i}.txt": b"" for i in range(MAX_ZIP_ENTRIES)})
    path = make_zip(entries)
    with pytest.raises(InvalidApkError, match="entries"):
        validate_apk(str(path))


def test_zip_bomb_is_rejected_from_the_central_directory(make_zip: ZipMaker) -> None:
    # 8 MB of zeros compresses to a few KB; the declared size alone must trip the guard.
    path = make_zip({**MINIMAL, "assets/bomb.bin": b"\x00" * (8 * 1024 * 1024)})
    assert path.stat().st_size < 100_000
    with pytest.raises(InvalidApkError, match="zip bomb"):
        validate_apk(str(path), max_total_uncompressed_bytes=1024 * 1024)


def test_file_over_the_size_cap_is_rejected(make_zip: ZipMaker) -> None:
    path = make_zip(MINIMAL)
    with pytest.raises(InvalidApkError, match="larger than"):
        validate_apk(str(path), max_apk_bytes=16)


def test_structurally_valid_archive_passes_validation(make_zip: ZipMaker) -> None:
    path = make_zip({**MINIMAL, "classes2.dex": b"more"})
    validated = validate_apk(str(path))
    assert validated.entry_count == 3
    assert validated.dex_names == ("classes.dex", "classes2.dex")


def test_analyze_apk_raises_invalid_apk_error_for_a_non_apk(tmp_path: Path) -> None:
    path = tmp_path / "fake.apk"
    path.write_text("just some text")
    with pytest.raises(InvalidApkError) as excinfo:
        analyze_apk(str(path))
    assert excinfo.value.reason


def test_analyze_apk_rejects_garbage_inside_a_valid_zip(make_zip: ZipMaker) -> None:
    with pytest.raises(InvalidApkError):
        analyze_apk(str(make_zip(MINIMAL)))
