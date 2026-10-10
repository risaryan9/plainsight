"""TLS must stay on (decisions D-030 and D-031).

Two things could silently weaken it:

- ``google_play_scraper`` turns off certificate verification for all of ``urllib`` when it
  is imported. ``pipeline.claim.play`` puts the default back.
- The policy fetch connects to a pinned IP address. The certificate must still be checked
  against the original hostname.

These tests talk to a throwaway HTTPS server on the loopback interface, never the internet.
"""

from __future__ import annotations

import datetime
import http.server
import ipaddress
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Importing the claim package imports google_play_scraper, which is the point.
import pipeline.claim.play  # noqa: F401
from pipeline.claim import policy

CERT_HOSTNAME = "policy.example.test"


@dataclass
class TlsServer:
    port: int
    ca_file: Path
    sni_seen: list[str | None] = field(default_factory=list)

    def trusting_context(self) -> ssl.SSLContext:
        """A normal verifying context that also trusts this server's certificate."""
        return ssl.create_default_context(cafile=str(self.ca_file))


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERT_HOSTNAME)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(CERT_HOSTNAME)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"<html><body><p>We collect nothing at all from this test page.</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[TlsServer]:
    """An HTTPS server on 127.0.0.1 whose certificate is valid only for CERT_HOSTNAME."""
    cert_file, key_file = _self_signed(tmp_path)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    state = TlsServer(port=server.server_address[1], ca_file=cert_file)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)

    def remember_sni(_socket: ssl.SSLObject, name: str | None, _context: ssl.SSLContext) -> None:
        state.sni_seen.append(name)

    context.sni_callback = remember_sni
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _deadline() -> float:
    return time.monotonic() + 5


# ------------------------------------------------- google_play_scraper's TLS change (D-030)


def test_the_urllib_default_context_is_the_verifying_one_after_the_scraper_import() -> None:
    import google_play_scraper  # noqa: F401

    assert ssl._create_default_https_context is ssl.create_default_context
    context = ssl._create_default_https_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_urllib_rejects_an_untrusted_certificate(tls_server: TlsServer) -> None:
    with pytest.raises(urllib.error.URLError) as excinfo:
        urllib.request.urlopen(f"https://127.0.0.1:{tls_server.port}/", timeout=5)
    assert isinstance(excinfo.value.reason, ssl.SSLCertVerificationError)


def test_httpx_rejects_an_untrusted_certificate(tls_server: TlsServer) -> None:
    with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
        httpx.get(f"https://127.0.0.1:{tls_server.port}/", timeout=5, trust_env=False)


# ------------------------------------------------- the pinned policy fetch (D-031)


def test_pinned_fetch_verifies_the_certificate_against_the_hostname(tls_server: TlsServer) -> None:
    url = httpx.URL(f"https://{CERT_HOSTNAME}:{tls_server.port}/privacy")

    response = policy.get_pinned(
        url, "127.0.0.1", deadline=_deadline(), verify=tls_server.trusting_context()
    )

    assert response.status == 200 and b"We collect nothing" in response.body
    # The original hostname was sent as SNI, although the socket went to the IP address.
    assert tls_server.sni_seen == [CERT_HOSTNAME]


def test_pinned_fetch_rejects_a_certificate_for_another_hostname(tls_server: TlsServer) -> None:
    """Same server, same trusted certificate, but the URL names a different host.

    If pinning made TLS check the IP address, or skip the check, this would succeed.
    """
    url = httpx.URL(f"https://other.example.test:{tls_server.port}/privacy")

    with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED") as excinfo:
        policy.get_pinned(
            url, "127.0.0.1", deadline=_deadline(), verify=tls_server.trusting_context()
        )
    assert "other.example.test" in str(excinfo.value)


def test_pinned_fetch_rejects_an_untrusted_certificate_by_default(tls_server: TlsServer) -> None:
    url = httpx.URL(f"https://{CERT_HOSTNAME}:{tls_server.port}/privacy")
    with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
        policy.get_pinned(url, "127.0.0.1", deadline=_deadline())


def test_a_bad_certificate_becomes_a_failed_fetch_not_a_crash(
    tls_server: TlsServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Let the loopback address through the SSRF guard for this one test, so that the full
    # fetch_policy path reaches the TLS handshake.
    monkeypatch.setattr(policy, "is_public_ip", lambda address: ipaddress.ip_address(address))

    result = policy.fetch_policy(
        f"https://{CERT_HOSTNAME}:{tls_server.port}/privacy",
        resolver=lambda _host, _port: ["127.0.0.1"],
    )

    assert result.status == "fetch_failed"
    assert result.note == "The policy site's TLS certificate is not valid."
