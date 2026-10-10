"""HTTP client for the Plainsight API. The bot never touches the API's disk."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("plainsight.bot.api")

MSG_OFFLINE = "I can't reach the scanner right now. Please try again in a few minutes."
MSG_TIMEOUT = (
    "That scan is taking longer than I can wait. Please send the file again in a few minutes."
)
MSG_BUSY = "Another scan is running right now. Please send the file again in a minute."
MSG_TOO_LARGE = "That file is too large for me to scan."
MSG_FAILED = "Something went wrong while scanning that file. Please try again later."


class ApiError(Exception):
    """A scan could not be completed. ``user_message`` is safe to show in the chat."""

    def __init__(self, user_message: str) -> None:
        super().__init__(user_message)
        self.user_message = user_message


@dataclass(frozen=True)
class ScanResult:
    sha256: str
    cached: bool
    pipeline_version: str
    summary: dict[str, Any]


def _detail(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        return ""
    return detail if isinstance(detail, str) else ""


class ApiClient:
    def __init__(
        self,
        base_url: str,
        timeout_s: float = 120.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = httpx.Timeout(timeout_s, connect=10.0)
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._base_url, timeout=self._timeout, transport=self._transport
        )

    async def scan(self, apk_path: Path, file_name: str) -> ScanResult:
        """Upload one APK and wait for the result. Raises :class:`ApiError` on any failure."""
        try:
            async with self._client() as client:
                with open(apk_path, "rb") as fh:
                    files = {"file": (file_name, fh, "application/vnd.android.package-archive")}
                    response = await client.post("/scan", files=files)
        except httpx.TimeoutException as exc:
            logger.warning("POST /scan timed out: %r", exc)
            raise ApiError(MSG_TIMEOUT) from exc
        except httpx.HTTPError as exc:
            logger.warning("POST /scan failed: %r", exc)
            raise ApiError(MSG_OFFLINE) from exc

        if response.status_code == 200:
            try:
                body = response.json()
                return ScanResult(
                    sha256=body["sha256"],
                    cached=bool(body["cached"]),
                    pipeline_version=str(body["pipeline_version"]),
                    summary=body["summary"],
                )
            except (ValueError, KeyError, TypeError) as exc:
                logger.error("POST /scan returned an unexpected body: %r", exc)
                raise ApiError(MSG_FAILED) from exc

        detail = _detail(response)
        logger.warning("POST /scan -> %s %s", response.status_code, detail or response.text[:200])
        if response.status_code == 400:
            reason = f" {detail}" if detail else ""
            raise ApiError(f"That file doesn't look like an APK I can scan.{reason}")
        if response.status_code == 413:
            raise ApiError(MSG_TOO_LARGE)
        if response.status_code == 503:
            raise ApiError(MSG_BUSY)
        raise ApiError(MSG_FAILED)

    async def fetch_report(self, sha256: str) -> bytes:
        """Download the stored JSON report. Raises :class:`ApiError` if it is unavailable."""
        try:
            async with self._client() as client:
                response = await client.get(f"/reports/{sha256}")
        except httpx.HTTPError as exc:
            logger.warning("GET /reports/%s failed: %r", sha256, exc)
            raise ApiError(MSG_OFFLINE) from exc
        if response.status_code != 200:
            logger.warning("GET /reports/%s -> %s", sha256, response.status_code)
            raise ApiError(MSG_FAILED)
        return response.content
