from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import httpx
import pytest

from pipeline.claim import policy

PUBLIC_IP = "93.184.216.34"
BINARY_EYE_POLICY = (Path(__file__).parent / "fixtures" / "binaryeye_PRIVACY.md").read_text(
    encoding="utf-8"
)
BLOB_URL = "https://github.com/markusfisch/BinaryEye/blob/master/PRIVACY.md"
RAW_URL = "https://raw.githubusercontent.com/markusfisch/BinaryEye/master/PRIVACY.md"
POLICY_HTML = """<!doctype html><html><head><title>Privacy</title>
<script>alert("never run")</script></head><body><main><article>
<h1>Privacy Policy</h1>
<p>We collect your email address when you create an account. We use it to sign you in.</p>
<h2>2. Sharing</h2>
<p>We do not sell your personal information to anyone! Contact us at any time.</p>
</article></main></body></html>"""


class Web:
    """A fake internet: host names -> addresses, and URLs -> responses."""

    def __init__(self) -> None:
        self.hosts: dict[str, list[str]] = {
            "policy.example.test": [PUBLIC_IP],
            "github.com": ["140.82.112.3"],
            "raw.githubusercontent.com": ["185.199.108.133"],
        }
        self.pages: dict[str, httpx.Response] = {}
        self.requests: list[httpx.Request] = []
        self.error: type[httpx.TransportError] | None = None
        self.transport = httpx.MockTransport(self._handle)

    def resolver(self, host: str, _port: int) -> list[str]:
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            pass
        if host not in self.hosts:
            raise OSError("name not known")
        return self.hosts[host]

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error("boom", request=request)
        key = f"{request.url.scheme}://{request.headers['host']}{request.url.raw_path.decode()}"
        return self.pages.get(key, httpx.Response(404))

    def page(self, url: str, body: str = POLICY_HTML, **kwargs: Any) -> None:  # noqa: ANN401
        headers = {"content-type": "text/html; charset=utf-8", **kwargs.pop("headers", {})}
        self.pages[url] = httpx.Response(
            kwargs.pop("status", 200), content=body.encode(), headers=headers
        )

    def fetch(self, url: str) -> policy.PolicyResult:
        return policy.fetch_policy(url, transport=self.transport, resolver=self.resolver)


@pytest.fixture
def web() -> Web:
    return Web()


# --------------------------------------------------------------------------- fetching


def test_policy_fetched_and_chunked(web: Web) -> None:
    web.page("https://policy.example.test/privacy")

    result = web.fetch("https://policy.example.test/privacy")

    assert result.status == "fetched" and result.note is None
    assert result.url == result.final_url == "https://policy.example.test/privacy"
    assert result.format == "html" and result.title == "Privacy Policy"
    assert [(chunk.id, chunk.section_path, chunk.text) for chunk in result.chunks] == [
        ("pol_001", [], "We collect your email address when you create an account."),
        ("pol_002", [], "We use it to sign you in."),
        ("pol_003", ["2. Sharing"], "We do not sell your personal information to anyone!"),
        ("pol_004", ["2. Sharing"], "Contact us at any time."),
    ]
    texts = [chunk.text for chunk in result.chunks]
    assert "alert" not in " ".join(texts)


def test_the_request_is_pinned_to_the_checked_address_but_tls_uses_the_hostname(web: Web) -> None:
    web.page("https://policy.example.test/privacy")

    web.fetch("https://policy.example.test/privacy")

    (request,) = web.requests
    # The connection goes to the address that passed the guard...
    assert request.url.host == PUBLIC_IP
    # ...while HTTP and TLS still name the original host: SNI and the certificate check
    # use `sni_hostname`, not the IP address in the URL.
    assert request.headers["host"] == "policy.example.test"
    assert request.extensions["sni_hostname"] == "policy.example.test"
    assert "Mozilla/5.0" in request.headers["user-agent"]


def test_a_non_default_port_is_kept_in_the_host_header(web: Web) -> None:
    web.page("https://policy.example.test:8443/p")
    assert web.fetch("https://policy.example.test:8443/p").status == "fetched"
    assert web.requests[0].headers["host"] == "policy.example.test:8443"
    assert web.requests[0].url.port == 8443


@pytest.mark.parametrize("status", [404, 410])
def test_a_missing_policy_page_is_not_found(web: Web, status: int) -> None:
    web.page("https://policy.example.test/gone", status=status)
    result = web.fetch("https://policy.example.test/gone")
    assert result.status == "not_found" and str(status) in (result.note or "")


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        ({"status": 500}, "HTTP 500"),
        ({"headers": {"content-type": "application/pdf"}}, "not a web page"),
        ({"body": "<html><body><script>x()</script></body></html>"}, "No readable text"),
        ({"body": "x" * (policy.MAX_BYTES + 1)}, "larger than 2 MB"),
    ],
)
def test_policy_fetch_failures(web: Web, setup: dict[str, Any], expected: str) -> None:
    web.page("https://policy.example.test/privacy", **setup)

    result = web.fetch("https://policy.example.test/privacy")

    assert result.status == "fetch_failed" and result.chunks == []
    assert expected in (result.note or "")


@pytest.mark.parametrize("error", [httpx.ReadTimeout, httpx.ConnectError])
def test_network_errors_are_reported_not_raised(
    web: Web, error: type[httpx.TransportError]
) -> None:
    web.error = error
    assert web.fetch("https://policy.example.test/privacy").status == "fetch_failed"


def test_an_unresolvable_host_is_a_failed_fetch(web: Web) -> None:
    result = web.fetch("https://nowhere.example.test/privacy")
    assert result.status == "fetch_failed" and "could not be resolved" in (result.note or "")
    assert web.requests == []


def test_no_url_means_no_request(web: Web) -> None:
    assert web.fetch("").status == "no_url"
    assert policy.fetch_policy(None).status == "no_url"


def test_plain_text_policies_are_accepted(web: Web) -> None:
    web.page(
        "https://policy.example.test/p.txt",
        body="We keep your data for thirty days. Then we delete all of it.",
        headers={"content-type": "text/plain"},
    )
    result = web.fetch("https://policy.example.test/p.txt")
    assert result.format == "text"
    assert [chunk.text for chunk in result.chunks] == [
        "We keep your data for thirty days.",
        "Then we delete all of it.",
    ]


def test_beautifulsoup_is_used_when_trafilatura_finds_nothing(
    web: Web, monkeypatch: pytest.MonkeyPatch
) -> None:
    import trafilatura

    monkeypatch.setattr(trafilatura, "extract", lambda *_args, **_kwargs: None)
    web.page("https://policy.example.test/privacy")

    result = web.fetch("https://policy.example.test/privacy")

    assert result.status == "fetched"
    text = " ".join(chunk.text for chunk in result.chunks)
    assert "We do not sell your personal information" in text and "alert" not in text


# --------------------------------------------------------------------------- SSRF guard


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://127.0.0.1:8000/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://100.64.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fe80::1]/",
        "http://[fd00::1]/",
        "http://[64:ff9b::7f00:1]/",
        "http://224.0.0.1/",
        "http://240.0.0.1/",
        "http://localhost/",
        "http://internal.example.test/",
        "https://rebind.example.test/",
        "http://2130706433/",
    ],
)
def test_urls_that_reach_private_addresses_are_blocked(web: Web, url: str) -> None:
    web.hosts["localhost"] = ["127.0.0.1"]
    web.hosts["internal.example.test"] = ["10.1.2.3"]
    # One public and one private record: refused as a whole.
    web.hosts["rebind.example.test"] = [PUBLIC_IP, "127.0.0.1"]
    web.hosts["2130706433"] = ["127.0.0.1"]

    result = web.fetch(url)

    assert result.status == "fetch_failed"
    assert "private or reserved network address" in (result.note or "")
    assert web.requests == [], "no request may be sent to a blocked address"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("file:///etc/passwd", "Only http and https"),
        ("ftp://policy.example.test/p", "Only http and https"),
        ("gopher://policy.example.test/", "Only http and https"),
        ("https://user:pw@policy.example.test/", "credentials"),
        ("https:///nohost", "no host"),
        ("https://policy.example.test/" + "a" * 3000, "too long"),
    ],
)
def test_other_unsafe_urls_are_blocked(web: Web, url: str, expected: str) -> None:
    result = web.fetch(url)
    assert result.status == "fetch_failed" and expected in (result.note or "")
    assert web.requests == []


def test_a_redirect_is_followed_and_checked_again(web: Web) -> None:
    web.hosts["www.example.test"] = ["93.184.216.35"]
    web.page("https://policy.example.test/old", status=301, headers={"location": "/new"})
    web.page(
        "https://policy.example.test/new",
        status=302,
        headers={"location": "https://www.example.test/privacy"},
    )
    web.page("https://www.example.test/privacy")

    result = web.fetch("https://policy.example.test/old")

    assert result.status == "fetched"
    assert result.final_url == "https://www.example.test/privacy"
    assert [request.url.host for request in web.requests] == [PUBLIC_IP, PUBLIC_IP, "93.184.216.35"]
    assert web.requests[-1].extensions["sni_hostname"] == "www.example.test"


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://internal.example.test/",
        "file:///etc/passwd",
    ],
)
def test_a_redirect_to_a_private_address_is_blocked(web: Web, location: str) -> None:
    web.hosts["internal.example.test"] = ["10.1.2.3"]
    web.page("https://policy.example.test/privacy", status=302, headers={"location": location})

    result = web.fetch("https://policy.example.test/privacy")

    assert result.status == "fetch_failed"
    assert len(web.requests) == 1, "the redirect target must not be requested"


def test_at_most_three_redirects_are_followed(web: Web) -> None:
    for hop in range(5):
        web.page(
            f"https://policy.example.test/{hop}",
            status=302,
            headers={"location": f"/{hop + 1}"},
        )

    result = web.fetch("https://policy.example.test/0")

    assert result.status == "fetch_failed" and "redirected more than 3 times" in (result.note or "")
    assert len(web.requests) == 4


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("127.0.0.1", False),
        ("169.254.169.254", False),
        ("192.0.2.1", False),
        ("::", False),
        ("2002:7f00:1::", False),
        ("not-an-ip", False),
    ],
)
def test_is_public_ip(address: str, public: bool) -> None:
    assert policy.is_public_ip(address) is public


# --------------------------------------------------------------------------- GitHub, markdown


def test_a_github_page_is_fetched_as_the_raw_markdown_file(web: Web) -> None:
    web.page(RAW_URL, body=BINARY_EYE_POLICY, headers={"content-type": "text/plain; charset=utf-8"})

    result = web.fetch(BLOB_URL)

    assert result.status == "fetched" and result.format == "markdown"
    # Both URLs are recorded: the one the listing gives and the one that was fetched.
    assert (result.url, result.final_url) == (BLOB_URL, RAW_URL)
    assert result.title == "Privacy Policy" and len(result.chunks) == 17
    camera = next(chunk for chunk in result.chunks if chunk.section == "CAMERA")
    assert camera.section_path == ["Permissions", "CAMERA"]
    # Only the raw host was contacted, through the same pinned, guarded fetch.
    (request,) = web.requests
    assert request.headers["host"] == "raw.githubusercontent.com"
    assert request.url.host == "185.199.108.133"
    assert request.extensions["sni_hostname"] == "raw.githubusercontent.com"


def test_the_github_page_is_the_fallback_when_the_raw_file_is_missing(web: Web) -> None:
    web.page(
        BLOB_URL, body="<html><body><h2>Policy</h2><p>We collect nothing at all.</p></body></html>"
    )

    result = web.fetch(BLOB_URL)

    assert result.status == "fetched" and result.format == "html"
    assert (result.url, result.final_url) == (BLOB_URL, BLOB_URL)
    assert [request.headers["host"] for request in web.requests] == [
        "raw.githubusercontent.com",
        "github.com",
    ]


def test_the_ssrf_guard_applies_to_the_raw_host_too(web: Web) -> None:
    web.hosts["raw.githubusercontent.com"] = ["127.0.0.1"]
    web.hosts["github.com"] = ["10.0.0.7"]

    result = web.fetch(BLOB_URL)

    assert result.status == "fetch_failed"
    assert "private or reserved network address" in (result.note or "")
    assert web.requests == []


def test_the_size_limit_applies_to_raw_markdown(web: Web) -> None:
    big = "A sentence of policy text. " * 100_000
    web.page(RAW_URL, body=big, headers={"content-type": "text/plain"})
    web.page(BLOB_URL, body=big)

    result = web.fetch(BLOB_URL)

    assert result.status == "fetch_failed" and "larger than 2 MB" in (result.note or "")


@pytest.mark.parametrize(
    "content_type", ["text/markdown", "text/x-markdown; charset=utf-8", "text/plain"]
)
def test_markdown_content_types_are_accepted(web: Web, content_type: str) -> None:
    web.page(
        "https://policy.example.test/PRIVACY.md",
        body="# Policy\n\n## Camera\n\nUsed only to scan [codes](https://example.test).\n",
        headers={"content-type": content_type},
    )

    result = web.fetch("https://policy.example.test/PRIVACY.md")

    assert result.status == "fetched" and result.format == "markdown"
    assert [(chunk.section, chunk.text) for chunk in result.chunks] == [
        ("Camera", "Used only to scan codes.")
    ]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (BLOB_URL, RAW_URL),
        (
            "https://www.github.com/o/r/blob/main/docs/Privacy.MD",
            "https://raw.githubusercontent.com/o/r/main/docs/Privacy.MD",
        ),
        (
            "http://github.com/o/r/blob/v1.2/PRIVACY.markdown?plain=1",
            "https://raw.githubusercontent.com/o/r/v1.2/PRIVACY.markdown",
        ),
        (
            "https://github.com/o/r/raw/main/PRIVACY.md",
            "https://raw.githubusercontent.com/o/r/main/PRIVACY.md",
        ),
        ("https://github.com/o/r/blob/main/privacy.html", None),
        ("https://github.com/o/r", None),
        ("https://github.com/o/r/wiki/Privacy.md", None),
        ("https://gitlab.com/o/r/blob/main/PRIVACY.md", None),
        ("https://github.com.evil.test/o/r/blob/main/PRIVACY.md", None),
        ("https://evil.test/github.com/o/r/blob/main/PRIVACY.md", None),
        ("ftp://github.com/o/r/blob/main/PRIVACY.md", None),
        ("not a url", None),
    ],
)
def test_github_raw_url(url: str, expected: str | None) -> None:
    assert policy.github_raw_url(url) == expected
