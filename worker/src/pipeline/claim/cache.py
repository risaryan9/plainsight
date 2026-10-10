"""Per-package cache of the Play listing and privacy policy (decision D-029).

# DEV-ONLY (D-029): local JSON files, kept for 3 days. The spec puts this in S3 (§7.8).

The caption is never cached: it belongs to one scan, not to the package.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from .models import CachedClaim, PlayLookup, PolicyResult
from .play import is_valid_package_name

logger = logging.getLogger("plainsight.worker.claim")

TTL = timedelta(days=3)


def cache_path(cache_dir: Path, package_name: str) -> Path | None:
    """Where a package's entry lives, or None if the name is not safe as a file name."""
    if not is_valid_package_name(package_name):
        return None
    return cache_dir / f"{package_name}.json"


def load(cache_dir: Path, package_name: str, *, now: datetime | None = None) -> CachedClaim | None:
    """The cached entry if it exists, is readable and is younger than :data:`TTL`."""
    path = cache_path(cache_dir, package_name)
    if path is None:
        return None
    try:
        entry = CachedClaim.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, ValidationError):
        # Also where an entry written by an older claim-cache version ends up.
        logger.warning("Ignoring unreadable or outdated claim cache entry %s", path)
        return None
    age = (now or datetime.now(UTC)) - entry.fetched_at
    if entry.package_name != package_name or not timedelta(0) <= age < TTL:
        return None
    return entry


def save(
    cache_dir: Path,
    package_name: str,
    play: PlayLookup,
    policy: PolicyResult | None,
    *,
    fetched_at: datetime | None = None,
) -> None:
    """Store a lookup. Best effort: a cache that cannot be written never fails a scan."""
    path = cache_path(cache_dir, package_name)
    if path is None:
        return
    entry = CachedClaim(
        package_name=package_name,
        fetched_at=fetched_at or datetime.now(UTC),
        play=play,
        policy=policy,
    )
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(entry.model_dump_json(indent=2), encoding="utf-8")
        os.replace(tmp_path, path)
    except OSError as exc:
        logger.warning("Could not write claim cache entry %s: %r", path, exc)
    finally:
        tmp_path.unlink(missing_ok=True)
