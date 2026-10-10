from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from bot import formatting, handlers
from bot.api_client import (
    MSG_BUSY,
    MSG_OFFLINE,
    MSG_TIMEOUT,
    ApiClient,
    ApiError,
    ScanResult,
)
from bot.settings import Settings

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


PLAY_CLAIM: dict[str, Any] = {
    "source": "play_store",
    "play_lookup": "found",
    "category": "Tools",
    "policy_status": "fetched",
    "policy_chunks": [{"id": f"pol_{n:03d}", "text": "A sentence."} for n in range(1, 43)],
    "flags": [],
}


def _claim(**changes: Any) -> dict[str, Any]:  # noqa: ANN401
    return {**PLAY_CLAIM, **changes}


@pytest.mark.parametrize(
    ("claim", "expected"),
    [
        (PLAY_CLAIM, "Claim: Play Store · Tools · policy fetched (42 sentences)"),
        (
            _claim(policy_status="no_url", policy_chunks=[], category=None),
            "Claim: Play Store · no privacy policy",
        ),
        (
            _claim(policy_status="fetch_failed", policy_chunks=[]),
            "Claim: Play Store · Tools · policy fetch failed",
        ),
        (
            _claim(flags=["claim_possible_impersonation"]),
            "Claim: Play Store · Tools · policy fetched (42 sentences) · "
            "app name differs from the listing",
        ),
        (
            {"source": "caption", "play_lookup": "not_found"},
            "Claim: not on Play Store · using caption",
        ),
        (
            {"source": "app_label", "play_lookup": "not_found"},
            "Claim: not on Play Store · using app name",
        ),
        (
            {"source": "caption", "play_lookup": "error"},
            "Claim: Play Store lookup failed · using caption",
        ),
    ],
)
def test_claim_line(claim: dict[str, Any], expected: str) -> None:
    assert formatting.format_claim_line(claim) == expected


def test_summary_includes_the_claim_line_but_never_the_caption() -> None:
    claim = {"source": "caption", "play_lookup": "not_found", "caption": "my cousin sent this"}
    text = formatting.format_summary(SUMMARY, cached=False, claim=claim)
    lines = text.splitlines()
    assert lines[-3:] == ["Claim: not on Play Store · using caption", "", "Fresh scan."]
    assert "my cousin" not in text
    assert "Claim:" not in formatting.format_summary(SUMMARY, cached=False)
    assert formatting.format_claim_line({}) is None


def test_summary_stays_under_the_limit_for_huge_or_hostile_input() -> None:
    summary = {
        "package": "com." + "x" * 5000,
        "label": "L" * 5000,
        "permission_count": 900,
        "dangerous_permissions": [f"android.permission.{'P' * 300}_{i}" for i in range(200)],
        "capabilities": [
            {"capability": "C" * 400 + str(i), "requested": True, "used": True} for i in range(100)
        ],
    }
    claim = _claim(category="G" * 5000)
    text = formatting.format_summary(summary, cached=False, claim=claim)
    assert len(text) < formatting.MAX_SUMMARY_CHARS


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


def test_dev_file_names_are_safe() -> None:
    assert handlers.dev_file_name("claim", "com.example.app") == "claim_com.example.app.json"
    name = handlers.dev_file_name("extraction", "../../etc/passwd\n")
    assert name == "extraction_.._.._etc_passwd_.json"
    assert "/" not in name
    assert handlers.dev_file_name("claim", None) == "claim_unknown.json"


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
                "claim": PLAY_CLAIM,
            },
        )

    result = asyncio.run(_client(handler).scan(apk, "upload.apk", caption="a wedding invite"))

    assert seen["url"] == "http://api.test/scan"
    assert b"pretend apk" in seen["body"]
    assert b'name="caption"' in seen["body"] and b"a wedding invite" in seen["body"]
    assert (result.sha256, result.cached, result.pipeline_version) == ("a" * 64, True, "dev-0")
    assert result.summary == SUMMARY
    assert result.claim == PLAY_CLAIM


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


# --------------------------------------------------------------------------- dev JSON


class FakeMessage:
    """Records what the bot sends to the chat."""

    def __init__(self) -> None:
        self.texts: list[str] = []
        self.documents: list[tuple[str, bytes]] = []

    async def reply_text(self, text: str) -> None:
        self.texts.append(text)

    async def reply_document(self, document: bytes, filename: str) -> None:
        self.documents.append((filename, document))


class FakeApi:
    def __init__(self, report: bytes | None) -> None:
        self.report = report

    async def fetch_report(self, _sha256: str) -> bytes:
        if self.report is None:
            raise ApiError(MSG_OFFLINE)
        return self.report


RESULT = ScanResult(
    sha256="a" * 64,
    cached=False,
    pipeline_version="dev-0",
    summary=SUMMARY,
    claim={"source": "caption", "caption": "नमस्ते", "play_lookup": "not_found"},
)


def _send_dev_json(api: FakeApi, result: ScanResult = RESULT) -> FakeMessage:
    message = FakeMessage()
    asyncio.run(handlers.send_dev_json(message, api, result))  # type: ignore[arg-type]
    return message


def test_dev_json_sends_the_extraction_and_the_claim_pretty_printed() -> None:
    message = _send_dev_json(FakeApi(b'{"apk":{"package_name":"com.example.recorder"}}'))

    assert [name for name, _ in message.documents] == [
        "extraction_com.example.recorder.json",
        "claim_com.example.recorder.json",
    ]
    extraction, claim = (data.decode() for _, data in message.documents)
    assert extraction == '{\n  "apk": {\n    "package_name": "com.example.recorder"\n  }\n}'
    assert json.loads(claim) == RESULT.claim
    assert '\n  "caption": "नमस्ते"' in claim
    assert message.texts == []


def test_dev_json_skips_a_file_over_45_mb_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(handlers, "MAX_DEV_FILE_BYTES", 200)
    huge = json.dumps({"padding": "x" * 1000}).encode()

    message = _send_dev_json(FakeApi(huge))

    assert [name for name, _ in message.documents] == ["claim_com.example.recorder.json"]
    (text,) = message.texts
    assert text.startswith("Skipped extraction_com.example.recorder.json") and "45 MB" in text


def test_dev_json_still_sends_the_claim_when_the_report_is_unavailable() -> None:
    message = _send_dev_json(FakeApi(None))
    assert [name for name, _ in message.documents] == ["claim_com.example.recorder.json"]
    assert message.texts == [formatting.REPORT_UNAVAILABLE_TEXT]


def test_dev_send_json_is_a_flag_that_defaults_to_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEV_SEND_JSON", raising=False)
    assert Settings(_env_file=None, telegram_bot_token="t").dev_send_json is True
    monkeypatch.setenv("DEV_SEND_JSON", "false")
    assert Settings(_env_file=None, telegram_bot_token="t").dev_send_json is False
