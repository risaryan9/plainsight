"""Play Store listing lookup by package name (spec §7.8, decision D-030).

``google-play-scraper`` is used only to parse the listing page. The page itself is fetched
here with httpx, because the library's own ``app()`` has no timeout.
"""

from __future__ import annotations

import logging
import re
import ssl
import time
from datetime import UTC, date, datetime
from typing import Any

import httpx
from google_play_scraper.constants.request import Formats
from google_play_scraper.features.app import parse_dom

from .models import PlayListing, PlayLookup

# Importing google_play_scraper (1.2.7) replaces this hook with the *unverified* context,
# which turns off TLS certificate checks for every urllib request in the process. Put the
# standard library default back (D-030). tests/test_claim_tls.py guards this.
ssl._create_default_https_context = ssl.create_default_context

logger = logging.getLogger("plainsight.worker.claim")

COUNTRY = "in"
LANGUAGE = "en"
TIMEOUT_S = 10.0
MAX_DESCRIPTION_CHARS = 2000
MAX_FIELD_CHARS = 300
MAX_URL_CHARS = 2000
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

# A Java package name as Android accepts it: dotted segments, each starting with a letter.
# It comes from the APK, so it is checked before it goes into a URL or a file name.
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
MAX_PACKAGE_CHARS = 200


def is_valid_package_name(package_name: str) -> bool:
    return len(package_name) <= MAX_PACKAGE_CHARS and bool(_PACKAGE_RE.match(package_name))


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _text(value: object, limit: int = MAX_FIELD_CHARS) -> str | None:
    """A clipped plain string, or None. Listing text is untrusted."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable() or ch in "\n\t").strip()
    return _clip(cleaned, limit) if cleaned else None


def _web_url(value: object) -> str | None:
    url = _text(value, MAX_URL_CHARS)
    return url if url and url.lower().startswith(("http://", "https://")) else None


def _updated_on(value: object) -> date | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC).date()
    except (OverflowError, OSError, ValueError):
        return None


def listing_from_details(package_name: str, details: dict[str, Any]) -> PlayListing | None:
    """Turn google-play-scraper's dict into a :class:`PlayListing`. None if it has no title."""
    title = _text(details.get("title"))
    if title is None:
        return None
    return PlayListing(
        title=title,
        description=_text(details.get("description"), MAX_DESCRIPTION_CHARS),
        category=_text(details.get("genre")),
        developer=_text(details.get("developer")),
        developer_website=_web_url(details.get("developerWebsite")),
        privacy_policy_url=_web_url(details.get("privacyPolicy")),
        installs=_text(details.get("installs"), 40),
        updated_on=_updated_on(details.get("updated")),
        url=f"https://play.google.com/store/apps/details?id={package_name}",
    )


def fetch_listing(
    package_name: str,
    *,
    transport: httpx.BaseTransport | None = None,
    timeout_s: float = TIMEOUT_S,
) -> PlayLookup:
    """Look the package up on Google Play. Never raises: failures come back as a status."""
    if not is_valid_package_name(package_name):
        return PlayLookup(status="skipped", note="The package name is not a valid Play Store id.")

    # Same two URLs the library tries: with the country first, then without it.
    urls = [
        Formats.Detail.build(app_id=package_name, lang=LANGUAGE, country=COUNTRY),
        Formats.Detail.fallback_build(app_id=package_name, lang=LANGUAGE),
    ]
    deadline = time.monotonic() + timeout_s
    try:
        with httpx.Client(
            transport=transport,
            follow_redirects=True,
            max_redirects=3,
            headers={"User-Agent": USER_AGENT, "Accept-Language": "en"},
        ) as client:
            for url in urls:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise httpx.ReadTimeout("deadline passed")
                response = client.get(url, timeout=remaining)
                if response.status_code == 404:
                    continue
                if response.status_code != 200:
                    return PlayLookup(
                        status="error",
                        note=f"Play Store answered HTTP {response.status_code}.",
                    )
                details = parse_dom(dom=response.text, app_id=package_name, url=url)
                listing = listing_from_details(package_name, details)
                if listing is None:
                    return PlayLookup(
                        status="error", note="The Play Store page could not be parsed."
                    )
                return PlayLookup(status="found", listing=listing)
    except httpx.TimeoutException:
        return PlayLookup(status="error", note=f"Play Store lookup timed out ({timeout_s:.0f} s).")
    except httpx.HTTPError as exc:
        return PlayLookup(status="error", note=f"Play Store lookup failed ({type(exc).__name__}).")
    except Exception as exc:
        # The scraper is unofficial and breaks when Play changes its pages (spec §17).
        logger.warning("Play listing for %s could not be parsed: %r", package_name, exc)
        return PlayLookup(status="error", note="The Play Store page could not be parsed.")
    return PlayLookup(status="not_found", note="No Play Store listing for this package name.")
