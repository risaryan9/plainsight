"""Bot configuration. Everything comes from environment variables or ``.env``."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # From @BotFather. Never hardcode it or log it.
    telegram_bot_token: SecretStr
    api_url: str = "http://localhost:8000"
    scan_timeout_s: float = Field(default=120.0, gt=0)
    # DEV-ONLY (D-035): also send the raw extraction and claim JSON files to the chat.
    dev_send_json: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # the token comes from the environment
