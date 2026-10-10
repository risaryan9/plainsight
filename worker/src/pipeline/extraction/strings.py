"""String-pool analysis: endpoints (URLs, IPv4 addresses) and secrets.

Pure functions over plain strings, so they are easy to test without an APK.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

MAX_ENDPOINTS = 50
MAX_ENDPOINT_CHARS = 300

_URL_RE = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s\"'<>\\^`{}|]+")
_URL_HOST_RE = re.compile(r"(?i)^[a-z]+://(?:[^/@]*@)?(\[[0-9a-f:.]+\]|[^/:?#]+)")
_HOSTNAME_RE = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$")
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_RE = re.compile(rf"(?<![\w.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\w.])")
_URL_TRAILING_JUNK = ".,;:!?)]}*"

# Hosts that only appear as XML namespaces, DTDs or licence text. Matches the host
# itself and any subdomain.
IGNORED_URL_HOSTS: frozenset[str] = frozenset(
    {
        "schemas.android.com",
        "w3.org",
        "ns.adobe.com",
        "xmlpull.org",
        "xml.org",
        "apache.org",
        "schemas.xmlsoap.org",
        "schemas.microsoft.com",
        "java.sun.com",
        "purl.org",
    }
)

# Dotted quads that are almost never real endpoints. ASN.1 object identifiers always
# start with 0, 1 or 2 ("1.3.101.110", "2.5.4.3") and crypto code is full of them, so a
# quad with one of those first octets is dropped unless it is a well-known address.
# Quads made only of single digits ("5.5.7.6") are nearly always version numbers.
IGNORED_IP_FIRST_OCTETS: frozenset[str] = frozenset({"0", "1", "2", "127", "255"})
ALLOWED_IPS: frozenset[str] = frozenset({"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"})

# Detection is strict: the key must stand alone as a token.
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    "google_api_key": re.compile(r"(?<![\w-])AIza[0-9A-Za-z_\-]{35}(?![\w-])"),
}
# Masking is deliberately looser: anything shaped like a key is masked wherever it sits,
# even glued to other characters, so a key can never reach the output by accident.
_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
)


@dataclass(frozen=True)
class Endpoint:
    value: str
    kind: Literal["url", "ip"]


@dataclass(frozen=True)
class SecretHit:
    kind: str
    value: str  # the raw secret: never put this in output, use mask_secret()


def mask_secret(value: str) -> str:
    """Mask a secret as its first 4 characters, an ellipsis and its length: ``AIza…(39)``."""
    return f"{value[:4]}…({len(value)})"


def redact_secrets(text: str) -> str:
    """Replace every secret found inside ``text`` with its masked form."""
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub(lambda m: mask_secret(m.group(0)), text)
    return text


def find_secrets(text: str) -> list[SecretHit]:
    """Return the secrets found in one string."""
    return [
        SecretHit(kind=kind, value=match.group(0))
        for kind, pattern in SECRET_PATTERNS.items()
        for match in pattern.finditer(text)
    ]


def _url_host(url: str) -> str | None:
    match = _URL_HOST_RE.match(url)
    return match.group(1).lower() if match else None


def _is_ignored_host(host: str) -> bool:
    return any(host == ignored or host.endswith("." + ignored) for ignored in IGNORED_URL_HOSTS)


def _is_real_host(host: str) -> bool:
    """True for a dotted hostname, an IPv4/IPv6 literal or localhost; false for templates."""
    if host == "localhost" or host.startswith("["):
        return True
    return bool(_IPV4_RE.fullmatch(host) or _HOSTNAME_RE.match(host))


def extract_urls(text: str) -> list[str]:
    """Return the URLs in one string, minus namespace/schema URLs and template fragments."""
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(_URL_TRAILING_JUNK)
        host = _url_host(url)
        if host is None or not _is_real_host(host) or _is_ignored_host(host):
            continue
        urls.append(url)
    return urls


def _is_plausible_ip(ip: str) -> bool:
    if ip in ALLOWED_IPS:
        return True
    octets = ip.split(".")
    return octets[0] not in IGNORED_IP_FIRST_OCTETS and any(len(octet) > 1 for octet in octets)


def extract_ipv4(text: str) -> list[str]:
    """Return the IPv4 addresses in one string that are not part of a URL."""
    remainder = _URL_RE.sub(" ", text)
    return [
        match.group(0) for match in _IPV4_RE.finditer(remainder) if _is_plausible_ip(match.group(0))
    ]


def find_endpoints(strings: Iterable[str]) -> dict[Endpoint, str]:
    """Map each distinct endpoint to the (first, in sort order) pool string it came from.

    Secrets inside URLs are masked in the endpoint value.
    """
    found: dict[Endpoint, str] = {}

    def _record(endpoint: Endpoint, source: str) -> None:
        if endpoint not in found or source < found[endpoint]:
            found[endpoint] = source

    for text in strings:
        if "." not in text:
            continue
        for url in extract_urls(text):
            _record(Endpoint(value=redact_secrets(url)[:MAX_ENDPOINT_CHARS], kind="url"), text)
        for ip in extract_ipv4(text):
            _record(Endpoint(value=ip, kind="ip"), text)
    return found


def extract_endpoints(strings: Iterable[str]) -> list[Endpoint]:
    """Deduplicated endpoints from a string pool, sorted (IPs first, then URLs)."""
    return sorted(find_endpoints(strings), key=lambda e: (e.kind, e.value))
