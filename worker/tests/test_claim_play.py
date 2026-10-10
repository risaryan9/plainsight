from __future__ import annotations

from datetime import date
from typing import Any

import httpx
import pytest

from pipeline.claim import play

DETAILS: dict[str, Any] = {
    "title": "Super Flashlight",
    "description": "The brightest flashlight. " * 200,
    "genre": "Tools",
    "developer": "Example Apps",
    "developerWebsite": "https://example-apps.test/",
    "privacyPolicy": "https://example-apps.test/privacy",
    "installs": "1,000,000+",
    "updated": 1759881600,  # 2025-10-08 UTC
}


class Play:
    """Stands in for play.google.com and for google-play-scraper's page parser."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.urls: list[str] = []
        self.status = 200
        self.details: dict[str, Any] = dict(DETAILS)
        self.parse_error: Exception | None = None
        self.transport_error: type[httpx.TransportError] | None = None
        monkeypatch.setattr(play, "parse_dom", self._parse_dom)
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        if self.transport_error is not None:
            raise self.transport_error("boom", request=request)
        return httpx.Response(self.status, text="<html>listing page</html>")

    def _parse_dom(self, dom: str, app_id: str, url: str) -> dict[str, Any]:
        assert dom == "<html>listing page</html>"
        if self.parse_error is not None:
            raise self.parse_error
        return {**self.details, "appId": app_id, "url": url}


@pytest.fixture
def fake_play(monkeypatch: pytest.MonkeyPatch) -> Play:
    return Play(monkeypatch)


def test_listing_found(fake_play: Play) -> None:
    result = play.fetch_listing("com.example.flashlight", transport=fake_play.transport)

    assert result.status == "found" and result.note is None
    listing = result.listing
    assert listing is not None
    assert listing.title == "Super Flashlight"
    assert listing.category == "Tools"
    assert listing.developer == "Example Apps"
    assert listing.developer_website == "https://example-apps.test/"
    assert listing.privacy_policy_url == "https://example-apps.test/privacy"
    assert listing.installs == "1,000,000+"
    assert listing.updated_on == date(2025, 10, 8)
    assert listing.url == "https://play.google.com/store/apps/details?id=com.example.flashlight"
    # Country "in", language "en", looked up by package name.
    assert fake_play.urls == [
        "https://play.google.com/store/apps/details?id=com.example.flashlight&hl=en&gl=in"
    ]


def test_description_is_truncated_to_2000_chars(fake_play: Play) -> None:
    listing = play.fetch_listing("com.example.app", transport=fake_play.transport).listing
    assert listing is not None and listing.description is not None
    assert len(listing.description) == play.MAX_DESCRIPTION_CHARS


def test_listing_not_found_after_both_urls_404(fake_play: Play) -> None:
    fake_play.status = 404

    result = play.fetch_listing("com.example.sideloaded", transport=fake_play.transport)

    assert result.status == "not_found" and result.listing is None
    assert len(fake_play.urls) == 2 and "gl=in" not in fake_play.urls[1]


def test_scraper_error_is_reported_not_raised(fake_play: Play) -> None:
    fake_play.parse_error = KeyError("Play changed its page")

    result = play.fetch_listing("com.example.app", transport=fake_play.transport)

    assert result.status == "error" and result.listing is None
    assert result.note == "The Play Store page could not be parsed."


def test_a_page_without_a_title_is_an_error(fake_play: Play) -> None:
    fake_play.details["title"] = None
    assert play.fetch_listing("com.example.app", transport=fake_play.transport).status == "error"


@pytest.mark.parametrize(
    ("error", "expected"),
    [(httpx.ReadTimeout, "timed out"), (httpx.ConnectError, "ConnectError")],
)
def test_network_failures_are_reported_not_raised(
    fake_play: Play, error: type[httpx.TransportError], expected: str
) -> None:
    fake_play.transport_error = error

    result = play.fetch_listing("com.example.app", transport=fake_play.transport)

    assert result.status == "error" and expected in (result.note or "")


def test_other_http_statuses_are_errors(fake_play: Play) -> None:
    fake_play.status = 503
    result = play.fetch_listing("com.example.app", transport=fake_play.transport)
    assert result.status == "error" and "503" in (result.note or "")


@pytest.mark.parametrize(
    "package",
    ["", "nodots", "../../etc/passwd", "com.example/../x", "com..example", "com.1abc", "a.b&gl=us"],
)
def test_an_invalid_package_name_is_never_sent_to_play(fake_play: Play, package: str) -> None:
    result = play.fetch_listing(package, transport=fake_play.transport)
    assert result.status == "skipped"
    assert fake_play.urls == []


def test_listing_fields_of_the_wrong_type_are_dropped() -> None:
    listing = play.listing_from_details(
        "com.example.app",
        {
            "title": "  App\x00 ",
            "description": 42,
            "genre": ["Tools"],
            "developerWebsite": "javascript:alert(1)",
            "privacyPolicy": "file:///etc/passwd",
            "updated": "yesterday",
        },
    )
    assert listing is not None
    assert listing.title == "App"
    assert listing.description is None and listing.category is None
    assert listing.developer_website is None and listing.privacy_policy_url is None
    assert listing.updated_on is None
