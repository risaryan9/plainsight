"""Plainsight API.

    uv run uvicorn api.main:app --port 8000

# DEV-ONLY (D-021): ``POST /scan`` is synchronous. It runs the pipeline inside the request
# and has no auth and no rate limit, so it is for local use only. The asynchronous,
# Lambda-backed flow from the spec (§7.2) replaces it.
# DEV-ONLY (D-026): reports are cached as JSON files instead of PostgreSQL + S3.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from pipeline.claim import Claim
from pipeline.extraction import InvalidApkError, analyze_apk, set_parser_log_level
from pipeline.extraction.validate import validate_apk
from pipeline.run import run_pipeline

from .metrics import ScanMeter
from .schemas import ScanResponse, summarise
from .settings import Settings, get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("plainsight.api")

BUSY_MESSAGE = "Another scan is running, please try again in a minute"
_CHUNK_BYTES = 1024 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Multipart framing adds a little to the body on top of the file itself.
_CONTENT_LENGTH_SLACK_BYTES = 64 * 1024
# Telegram captions are at most 4096 characters.
_MAX_CAPTION_CHARS = 4096


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    set_parser_log_level(get_settings().parser_log_level)
    yield


app = FastAPI(title="Plainsight API", version="0.1.0", lifespan=_lifespan)

# DEV-ONLY (D-023): one scan at a time, because a single scan can peak above 1 GB of
# memory. The lock is in-process, so run a single uvicorn worker.
_scan_lock = threading.Lock()

SettingsDep = Annotated[Settings, Depends(get_settings)]


def report_path_for(settings: Settings, sha256: str) -> Path:
    """The cached extraction report for an APK (D-012, D-026)."""
    return settings.reports_dir / f"{sha256}__{settings.pipeline_version}.json"


def combined_report_path_for(settings: Settings, sha256: str) -> Path:
    """The latest combined (extraction + claim) report for an APK.

    # DEV-ONLY (D-034): saved for inspection only and overwritten by every request. It
    # contains the sender's caption, so no endpoint serves it.
    """
    return settings.reports_dir / f"{sha256}__{settings.pipeline_version}.combined.json"


def _too_large(settings: Settings) -> HTTPException:
    return HTTPException(413, f"The file is larger than the {settings.max_upload_mb} MB limit.")


def _save_upload(upload: UploadFile, max_bytes: int) -> tuple[Path, str, int]:
    """Copy the upload to a temp file in chunks, hashing as it goes.

    Returns (path, sha256, size). The caller must delete the file. If the upload is larger
    than ``max_bytes`` the copy stops and size is ``max_bytes + 1`` or more.
    """
    digest = hashlib.sha256()
    size = 0
    with tempfile.NamedTemporaryFile(prefix="plainsight-", suffix=".apk", delete=False) as tmp:
        path = Path(tmp.name)
        while size <= max_bytes and (chunk := upload.file.read(_CHUNK_BYTES)):
            size += len(chunk)
            digest.update(chunk)
            tmp.write(chunk)
    return path, digest.hexdigest(), size


def _load_report(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as fh:
            report: dict[str, Any] = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        logger.warning("Ignoring unreadable cached report %s", path)
        return None
    return report


def _write_report(path: Path, report: dict[str, Any]) -> None:
    """Write atomically, so a half-written report is never served."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _extraction_for(
    settings: Settings, apk_path: Path, sha256: str, size: int
) -> tuple[dict[str, Any], bool]:
    """The extraction report for an APK, and whether it came from the cache.

    Only extraction is cached per APK: it depends on nothing but the file (D-028).
    """
    report_path = report_path_for(settings, sha256)
    cached = _load_report(report_path)
    if cached is not None:
        logger.info("scan sha256=%s cached=true", sha256)
        return cached, True

    if not _scan_lock.acquire(timeout=settings.scan_lock_timeout_s):
        logger.info("scan sha256=%s rejected: another scan is running", sha256)
        raise HTTPException(503, BUSY_MESSAGE, headers={"Retry-After": "60"})
    try:
        # The scan we waited for may have been this same file.
        cached = _load_report(report_path)
        if cached is not None:
            logger.info("scan sha256=%s cached=true (finished while waiting)", sha256)
            return cached, True

        with ScanMeter() as meter:
            try:
                report = analyze_apk(str(apk_path))
            except InvalidApkError as exc:
                raise HTTPException(400, exc.reason) from exc
        _write_report(report_path, report)
    finally:
        _scan_lock.release()

    peak = f"{meter.peak_rss_mb:.0f}" if meter.peak_rss_mb is not None else "unknown"
    logger.info(
        "scan sha256=%s cached=false package=%s size_mb=%.1f duration_s=%.1f peak_rss_mb=%s",
        sha256,
        report["apk"]["package_name"],
        size / 1_048_576,
        meter.duration_s,
        peak,
    )
    return report, False


@app.get("/healthz")
def healthz() -> dict[str, bool]:
    return {"ok": True}


# A plain `def` route: FastAPI runs it in a worker thread, so the blocking analysis does
# not stall the event loop.
@app.post("/scan")
def scan(
    file: UploadFile,
    request: Request,
    settings: SettingsDep,
    caption: Annotated[str | None, Form(max_length=_MAX_CAPTION_CHARS)] = None,
) -> ScanResponse:
    # The caption is the sender's own words: it goes into the claim, never into the
    # per-APK cache and never into the logs.
    caption = (caption or "").strip() or None
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > (
        settings.max_upload_bytes + _CONTENT_LENGTH_SLACK_BYTES
    ):
        raise _too_large(settings)

    apk_path, sha256, size = _save_upload(file, settings.max_upload_bytes)
    try:
        if size > settings.max_upload_bytes:
            raise _too_large(settings)
        try:
            validate_apk(str(apk_path), max_apk_bytes=settings.max_upload_bytes)
        except InvalidApkError as exc:
            raise HTTPException(400, exc.reason) from exc

        extraction, cached = _extraction_for(settings, apk_path, sha256, size)

        # The claim is rebuilt on every request, outside the scan lock: it is cheap, has
        # its own per-package cache, and depends on this request's caption (D-028).
        combined = run_pipeline(
            apk_path, caption, extraction=extraction, claims_dir=settings.claims_dir
        )
        _write_report(combined_report_path_for(settings, sha256), combined)
        claim = Claim.model_validate(combined["claim"])
        logger.info(
            "claim sha256=%s source=%s play=%s policy=%s chunks=%d flags=%s from_cache=%s ms=%s",
            sha256,
            claim.source,
            claim.play_lookup,
            claim.policy_status,
            len(claim.policy_chunks),
            ",".join(claim.flags) or "-",
            claim.from_cache,
            combined["meta"]["stage_ms"]["claim"],
        )
        return ScanResponse(
            sha256=sha256,
            cached=cached,
            pipeline_version=settings.pipeline_version,
            report_path=str(report_path_for(settings, sha256)),
            summary=summarise(extraction),
            claim=claim,
        )
    finally:
        apk_path.unlink(missing_ok=True)


@app.get("/reports/{sha256}")
def get_report(sha256: str, settings: SettingsDep) -> FileResponse:
    """The stored extraction report for an APK hash, under the current pipeline version.

    # DEV-ONLY (D-022): reports are addressed by APK hash. Public URLs will use scan ids.
    """
    sha256 = sha256.lower()
    if not _SHA256_RE.match(sha256):
        raise HTTPException(404, "No report for that hash.")
    path = report_path_for(settings, sha256)
    if not path.is_file():
        raise HTTPException(404, "No report for that hash.")
    return FileResponse(path, media_type="application/json", filename=f"{sha256}.json")
