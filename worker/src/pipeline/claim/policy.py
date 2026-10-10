"""Privacy-policy fetch, text extraction and chunking (spec §7.8, decision D-031).

The URL comes from a Play listing, which an attacker controls, so the fetch is guarded:

- http/https only, no credentials in the URL;
- every address the host resolves to must be public (SSRF guard), checked again on each
  redirect;
- the connection goes to the address that was checked, so a DNS answer that changes
  between the check and the fetch cannot bypass the guard. TLS still uses the original
  hostname for SNI and certificate verification;
- 10 s overall, 2 MB, at most 3 redirects, HTML, plain text or markdown only.

A GitHub page (``github.com/<owner>/<repo>/blob/<ref>/<path>.md``) is fetched as the raw
markdown file from ``raw.githubusercontent.com`` instead, under the same guard and limits.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .chunking import ChunkedPolicy, chunk_markdown
from .models import PolicyFormat, PolicyResult

logger = logging.getLogger("plainsight.worker.claim")

TIMEOUT_S = 10.0
MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
MAX_URL_CHARS = 2000
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
# What a browser sends when someone opens a link. Some sites (whatsapp.com is one) answer
# HTTP 400 to a browser user-agent that arrives without the Sec-Fetch headers.
_BROWSER_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_MARKDOWN_TYPES = frozenset({"text/markdown", "text/x-markdown"})
# raw.githubusercontent.com serves markdown as text/plain.
_TEXT_TYPES = _HTML_TYPES | _MARKDOWN_TYPES | {"text/plain"}
_MARKDOWN_SUFFIXES = (".md", ".markdown")
_GITHUB_HOSTS = frozenset({"github.com", "www.github.com"})
_GITHUB_FILE = re.compile(r"^/([^/]+)/([^/]+)/(?:blob|raw)/(.+)$")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")

# (host, port) -> the IP addresses the host resolves to.
Resolver = Callable[[str, int], list[str]]


class PolicyFetchError(Exception):
    """The policy could not be fetched. ``reason`` is safe to store in the report."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class BlockedUrlError(PolicyFetchError):
    """The URL was refused by the guard before any request was sent to it."""


class _NotFoundError(PolicyFetchError):
    pass


# --------------------------------------------------------------------------- SSRF guard


def is_public_ip(address: str) -> bool:
    """True only for addresses on the public internet."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None or ip.teredo is not None or ip in _NAT64:
            # Tunnelling prefixes that can smuggle a private IPv4 address.
            return False
    return ip.is_global and not (
        ip.is_multicast
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
    )


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def check_url(url: str) -> httpx.URL:
    """Parse ``url`` and apply the checks that need no network. Raises BlockedUrlError."""
    if len(url) > MAX_URL_CHARS:
        raise BlockedUrlError("The policy URL is too long.")
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError, TypeError) as exc:
        raise BlockedUrlError("The policy URL is not a valid URL.") from exc
    if parsed.scheme not in ("http", "https"):
        raise BlockedUrlError(f"Only http and https URLs are fetched, not {parsed.scheme!r}.")
    if not parsed.raw_host:
        raise BlockedUrlError("The policy URL has no host.")
    if parsed.userinfo:
        raise BlockedUrlError("The policy URL contains credentials.")
    return parsed


def _resolve(host: str, port: int, resolver: Resolver, deadline: float) -> list[str]:
    """Resolve within the deadline (``getaddrinfo`` has no timeout of its own)."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PolicyFetchError("The policy fetch timed out.")
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="policy-dns")
    try:
        return executor.submit(resolver, host, port).result(timeout=remaining)
    except FutureTimeoutError as exc:
        raise PolicyFetchError("The policy host name took too long to resolve.") from exc
    except OSError as exc:
        raise PolicyFetchError("The policy host name could not be resolved.") from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def public_addresses(url: httpx.URL, resolver: Resolver, deadline: float) -> list[str]:
    """The addresses to connect to, IPv4 first. Raises BlockedUrlError unless all are public."""
    host = url.raw_host.decode("ascii")
    port = url.port or (443 if url.scheme == "https" else 80)
    addresses = _resolve(host, port, resolver, deadline)
    if not addresses:
        raise PolicyFetchError("The policy host name could not be resolved.")
    if not all(is_public_ip(address) for address in addresses):
        # One private answer is enough: a host that mixes public and private records
        # is exactly what a DNS-rebinding attack looks like.
        raise BlockedUrlError("The policy URL points to a private or reserved network address.")
    return sorted(addresses, key=lambda address: ":" in address)


# --------------------------------------------------------------------------- HTTP fetch


@dataclass(frozen=True)
class _Document:
    """A fetched policy before chunking."""

    final_url: str
    body: bytes
    format: PolicyFormat
    charset: str | None


def github_raw_url(url: str) -> str | None:
    """The raw-file URL for a GitHub markdown page, or None for any other URL.

    ``https://github.com/<owner>/<repo>/blob/<ref>/<path>.md`` becomes
    ``https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>.md``. The page itself
    is an app shell around the file; the raw file is the policy as its author wrote it.
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError, TypeError):
        return None
    if parsed.scheme not in ("http", "https") or parsed.host.lower() not in _GITHUB_HOSTS:
        return None
    match = _GITHUB_FILE.match(parsed.path)
    if match is None or not parsed.path.lower().endswith(_MARKDOWN_SUFFIXES):
        return None
    owner, repo, rest = match.groups()
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{rest}"


def _format_of(url: httpx.URL, content_type: str) -> PolicyFormat:
    if content_type in _HTML_TYPES:
        return "html"
    if content_type in _MARKDOWN_TYPES or url.path.lower().endswith(_MARKDOWN_SUFFIXES):
        return "markdown"
    return "text"


@dataclass(frozen=True)
class _Response:
    status: int
    location: str | None
    content_type: str
    charset: str | None
    body: bytes


def get_pinned(
    url: httpx.URL,
    address: str,
    *,
    deadline: float,
    transport: httpx.BaseTransport | None = None,
    verify: ssl.SSLContext | bool = True,
) -> _Response:
    """GET ``url``, connecting to ``address`` instead of resolving the host again.

    Pinning must never weaken TLS: the ``sni_hostname`` extension makes httpx send the
    original hostname as SNI **and** verify the certificate against it, not against the
    IP address in the request URL. ``verify`` stays on; tests pass their own CA context.
    """
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PolicyFetchError("The policy fetch timed out.")
    hostname = url.raw_host.decode("ascii")
    headers = {"Host": url.netloc.decode("ascii"), **_BROWSER_HEADERS}
    # A new client per request: a pooled connection verified for one hostname must not
    # be reused for another hostname on the same address. trust_env=False ignores proxy
    # variables, because a proxy would resolve the name itself.
    with (
        httpx.Client(
            transport=transport,
            verify=verify,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(remaining),
        ) as client,
        client.stream(
            "GET",
            url.copy_with(host=address),
            headers=headers,
            extensions={"sni_hostname": hostname},
        ) as response,
    ):
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        status = response.status_code
        location = response.headers.get("location")
        if status != 200 or content_type not in _TEXT_TYPES:
            return _Response(status, location, content_type, None, b"")

        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_BYTES:
            raise PolicyFetchError("The policy page is larger than 2 MB.")
        body = bytearray()
        # iter_bytes yields decompressed data, so the cap also stops compression bombs.
        for chunk in response.iter_bytes():
            body += chunk
            if len(body) > MAX_BYTES:
                raise PolicyFetchError("The policy page is larger than 2 MB.")
            if time.monotonic() > deadline:
                raise PolicyFetchError("The policy fetch timed out.")
        return _Response(status, location, content_type, response.charset_encoding, bytes(body))


def _is_tls_error(exc: BaseException) -> bool:
    """True if a TLS failure (e.g. a bad certificate) is anywhere in the cause chain."""
    seen: BaseException | None = exc
    for _ in range(6):
        if seen is None:
            return False
        if isinstance(seen, ssl.SSLError):
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def _get(
    url: httpx.URL,
    addresses: list[str],
    deadline: float,
    transport: httpx.BaseTransport | None,
    verify: ssl.SSLContext | bool,
) -> _Response:
    last_error: httpx.TransportError | None = None
    for address in addresses:
        try:
            return get_pinned(url, address, deadline=deadline, transport=transport, verify=verify)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            if _is_tls_error(exc):
                # A certificate problem is not a reason to try another address.
                raise
            last_error = exc
    assert last_error is not None
    raise last_error


def _fetch_document(
    url: str,
    transport: httpx.BaseTransport | None,
    resolver: Resolver,
    deadline: float,
    verify: ssl.SSLContext | bool,
) -> _Document:
    """Fetch one URL under the guard and the limits. Raises PolicyFetchError."""
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        parsed = check_url(current)
        addresses = public_addresses(parsed, resolver, deadline)
        try:
            response = _get(parsed, addresses, deadline, transport, verify)
        except httpx.TimeoutException as exc:
            raise PolicyFetchError("The policy fetch timed out.") from exc
        except httpx.HTTPError as exc:
            if _is_tls_error(exc):
                raise PolicyFetchError("The policy site's TLS certificate is not valid.") from exc
            raise PolicyFetchError(f"The policy fetch failed ({type(exc).__name__}).") from exc

        if response.status in _REDIRECT_STATUSES and response.location:
            current = urljoin(str(parsed), response.location)
            continue
        if response.status in (404, 410):
            raise _NotFoundError(f"The policy page answered HTTP {response.status}.")
        if response.status != 200:
            raise PolicyFetchError(f"The policy page answered HTTP {response.status}.")
        if response.content_type not in _TEXT_TYPES:
            shown = re.sub(r"[^a-z0-9.+/-]", "", response.content_type)[:60] or "unknown"
            raise PolicyFetchError(f"The policy is not a web page (content type {shown}).")
        return _Document(
            final_url=str(parsed),
            body=response.body,
            format=_format_of(parsed, response.content_type),
            charset=response.charset,
        )
    raise PolicyFetchError(f"The policy URL redirected more than {MAX_REDIRECTS} times.")


def fetch_policy(
    url: str | None,
    *,
    transport: httpx.BaseTransport | None = None,
    resolver: Resolver | None = None,
    timeout_s: float = TIMEOUT_S,
    verify: ssl.SSLContext | bool = True,
) -> PolicyResult:
    """Fetch and chunk the privacy policy. Never raises: failures come back as a status."""
    if not url:
        return PolicyResult(status="no_url", note="The listing has no privacy-policy URL.")
    shown_url = url[:MAX_URL_CHARS]
    resolver = resolver or system_resolver
    deadline = time.monotonic() + timeout_s
    try:
        document = None
        raw_url = github_raw_url(url)
        if raw_url is not None:
            try:
                document = _fetch_document(raw_url, transport, resolver, deadline, verify)
            except PolicyFetchError as exc:
                # Fall back to the page the listing links, within the same time budget.
                logger.info("raw GitHub fetch failed (%s); trying the page itself", exc.reason)
        if document is None:
            document = _fetch_document(url, transport, resolver, deadline, verify)
        chunked = chunk_document(document)
    except _NotFoundError as exc:
        return PolicyResult(status="not_found", url=shown_url, note=exc.reason)
    except PolicyFetchError as exc:
        return PolicyResult(status="fetch_failed", url=shown_url, note=exc.reason)
    except Exception as exc:
        logger.warning("policy fetch failed unexpectedly: %r", exc)
        return PolicyResult(
            status="fetch_failed", url=shown_url, note="The policy page could not be read."
        )
    if not chunked.chunks:
        return PolicyResult(
            status="fetch_failed",
            url=shown_url,
            note="No readable text was found on the policy page.",
        )
    return PolicyResult(
        status="fetched",
        url=shown_url,
        final_url=document.final_url,
        format=document.format,
        title=chunked.title,
        chunks=chunked.chunks,
        truncated=chunked.truncated,
    )


# --------------------------------------------------------------------------- text


def _decode(body: bytes, charset: str | None) -> str:
    try:
        return body.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _soup_to_markdown(html: str | bytes) -> str:
    """Fallback HTML-to-markdown: headings and paragraphs only."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "template", "svg"]):
        tag.decompose()
    block_names = ["h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "td", "th", "dt", "dd"]
    parts: list[str] = []
    for element in soup.find_all(block_names):
        if element.find(block_names) is not None:
            continue  # its inner blocks are emitted on their own
        # A space, not a newline, between inline pieces: links must not break sentences.
        text = " ".join(element.get_text(" ").split())
        if not text:
            continue
        level = int(element.name[1]) if re.fullmatch(r"h[1-6]", element.name) else 0
        parts.append(f"{'#' * level} {text}" if level else text)
    return "\n\n".join(parts) if parts else soup.get_text("\n\n")


def html_to_markdown(html: str | bytes) -> str:
    """Main text of an HTML page as markdown, so that headings and tables survive."""
    # Imported here: trafilatura is slow to import and only needed for a fresh fetch.
    import trafilatura

    try:
        extracted = trafilatura.extract(
            html,
            output_format="markdown",
            include_comments=False,
            include_tables=True,
            favor_recall=True,
        )
    except Exception as exc:
        logger.warning("trafilatura failed on a policy page: %r", exc)
        extracted = None
    if extracted and extracted.strip():
        return str(extracted)
    return _soup_to_markdown(html)


def chunk_document(document: _Document) -> ChunkedPolicy:
    """Chunk a fetched policy. The result is plain text; nothing is rendered or run."""
    if document.format == "html":
        # With a declared charset decode here; otherwise let the parsers sniff the bytes.
        html = _decode(document.body, document.charset) if document.charset else document.body
        # Many sites style headings with <strong> instead of <h2>.
        return chunk_markdown(html_to_markdown(html), bold_headings=True)
    return chunk_markdown(_decode(document.body, document.charset))
