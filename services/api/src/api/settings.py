"""API configuration. Everything comes from environment variables or ``.env``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Where scan reports are written: <reports_dir>/<sha256>__<pipeline_version>.json
    reports_dir: Path = Path("data/reports")
    # DEV-ONLY (D-029): the Play listing and privacy policy are cached per package as
    # <claims_dir>/<package>.json.
    claims_dir: Path = Path("data/claims")
    # Part of the cache key: change it to make every APK re-scan. It is used in file
    # names, so only letters, digits, dot, dash and underscore are allowed.
    pipeline_version: str = Field(default="dev-0", pattern=r"^[A-Za-z0-9._-]{1,64}$")
    max_upload_mb: int = Field(default=100, gt=0)
    # How long a request waits for a running scan to finish before giving up with 503.
    scan_lock_timeout_s: float = Field(default=20.0, ge=0)
    # Androguard warns about harmless quirks in most APKs; keep the console readable.
    parser_log_level: str = "ERROR"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
