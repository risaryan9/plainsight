from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest

from bot import formatting
from bot.api_client import MSG_BUSY, MSG_OFFLINE, MSG_TIMEOUT, ApiClient, ApiError
from bot.handlers import _report_file_name

SUMMARY: dict[str, Any] = {
    "package": "com.example.recorder",
    "label": "Recorder",
    "permission_count": 14,
    "dangerous_permissions": [
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
    ],
    "capabilities": [
        {"capability": "MICROPHONE", "requested": True, "used": True},
        {"capability": "CONTACTS", "requested": True, "used": False},
        {"capability": "PRECISE_LOCATION", "requested": False, "used": True},
        {"capability": "STORAGE", "requested": True, "used": None},
        {"capability": "CAMERA", "requested": False, "used": False},
    ],
}


def test_summary_reads_well() -> None:
    text = formatting.format_summary(SUMMARY, cached=False)
    assert text.splitlines()[0] == "Recorder (com.example.recorder)"
    assert "Permissions: 14 declared, 2 dangerous" in text
    assert "Dangerous: RECORD_AUDIO, READ_CONTACTS" in text
    assert "• Microphone: asks for it and uses it" in text
    assert "• Contacts: asks for it, but no code uses it" in text
    assert "• Precise location: code can use it, but it is not asked for" in text
    assert "• Storage: asks for it" in text
    assert "Camera" not in text
    assert text.endswith("Fresh scan.")


def test_summary_says_when_the_result_was_cached() -> None:
    assert formatting.format_summary(SUMMARY, cached=True).endswith(
        "Saved result from an earlier scan."
    )


def test_summary_shows_the_caption_on_one_line() -> None:
    text = formatting.format_summary(
        {**SUMMARY, "caption": "my cousin sent this\nas a wedding invite"}, cached=False
    )
    assert 'Your caption: "my cousin sent this as a wedding invite"' in text
    assert text.endswith("Fresh scan.")
    assert "caption" not in formatting.format_summary(SUMMARY, cached=False)


def test_summary_stays_under_the_limit_for_huge_or_hostile_input() -> None:
    summary = {
        "package": "com." + "x" * 5000,
        "label": "L" * 5000,
        "permission_count": 900,
        "dangerous_permissions": [f"android.permission.{'P' * 300}_{i}" for i in range(200)],
        "capabilities": [
            {"capability": "C" * 400 + str(i), "requested": True, "used": True} for i in range(100)
        ],
        "caption": "c" * 5000,
    }
    assert len(formatting.format_summary(summary, cached=False)) < formatting.MAX_SUMMARY_CHARS


def test_summary_copes_with_missing_fields() -> None:
    text = formatting.format_summary({}, cached=False)
    assert "unknown package" in text and "0 declared" in text


def test_only_apk_files_up_to_20_mb_are_accepted() -> None:
    assert formatting.check_document("app.apk", 5 * 1024 * 1024) is None
    assert formatting.check_document("APP.APK", None) is None
    assert formatting.check_document("exactly.apk", 20 * 1024 * 1024) is None
    assert formatting.check_document("photo.jpg", 100) == formatting.NOT_APK_TEXT
    assert formatting.check_document(None, 100) == formatting.NOT_APK_TEXT
    too_big = formatting.check_document("big.apk", 21 * 1024 * 1024)
    assert too_big is not None and "21.0 MB" in too_big and "20 MB" in too_big


def test_report_file_name_is_safe() -> None:
    name = _report_file_name("../../etc/passwd\n", "ab" * 32)
    assert name == ".._.._etc_passwd_-abababababab.json"
    assert "/" not in name


def _client(handler: Any) -> ApiClient:  # noqa: ANN401
    return ApiClient("http://api.test", timeout_s=1, transport=httpx.MockTransport(handler))


@pytest.fixture
def apk(tmp_path: Path) -> Path:
    path = tmp_path / "upload.apk"
    path.write_bytes(b"PK\x03\x04 pretend apk")
    return path


def test_scan_posts_the_file_and_parses_the_result(apk: Path) -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = request.read()
        return httpx.Response(
            200,
            json={
                "sha256": "a" * 64,
                "cached": True,
                "pipeline_version": "dev-0",
                "report_path": "data/reports/x.json",
                "summary": SUMMARY,
            },
        )

    result = asyncio.run(_client(handler).scan(apk, "upload.apk", caption="a wedding invite"))

    assert seen["url"] == "http://api.test/scan"
    assert b"pretend apk" in seen["body"]
    assert b'name="caption"' in seen["body"] and b"a wedding invite" in seen["body"]
    assert (result.sha256, result.cached, result.pipeline_version) == ("a" * 64, True, "dev-0")
    assert result.summary == SUMMARY


@pytest.mark.parametrize(
    ("status", "detail", "expected"),
    [
        (503, "Another scan is running, please try again in a minute", MSG_BUSY),
        (400, "Not an APK: the archive has no classes.dex.", "no classes.dex"),
        (413, "too big", "too large"),
        (500, "boom", "Something went wrong"),
    ],
)
def test_api_errors_become_friendly_messages(
    apk: Path, status: int, detail: str, expected: str
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"detail": detail})

    with pytest.raises(ApiError) as excinfo:
        asyncio.run(_client(handler).scan(apk, "upload.apk"))
    assert expected in excinfo.value.user_message


def test_timeouts_and_connection_failures_become_friendly_messages(apk: Path) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    for handler, expected in ((timeout, MSG_TIMEOUT), (refused, MSG_OFFLINE)):
        with pytest.raises(ApiError) as excinfo:
            asyncio.run(_client(handler).scan(apk, "upload.apk"))
        assert excinfo.value.user_message == expected


def test_fetch_report_returns_the_bytes_or_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/reports/" + "a" * 64:
            return httpx.Response(200, content=b'{"ok": true}')
        return httpx.Response(404, json={"detail": "No report for that hash."})

    client = _client(handler)
    assert asyncio.run(client.fetch_report("a" * 64)) == b'{"ok": true}'
    with pytest.raises(ApiError):
        asyncio.run(client.fetch_report("b" * 64))
