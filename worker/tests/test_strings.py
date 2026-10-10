from __future__ import annotations

from pipeline.extraction.strings import (
    Endpoint,
    extract_endpoints,
    extract_ipv4,
    extract_urls,
    find_secrets,
    mask_secret,
    redact_secrets,
)

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GOOGLE_KEY = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"


def test_urls_are_extracted_from_surrounding_text() -> None:
    text = 'POST to https://collect.example.net/v2?x=1, then "http://10.0.2.2:8080/ping".'
    assert extract_urls(text) == ["https://collect.example.net/v2?x=1", "http://10.0.2.2:8080/ping"]


def test_other_schemes_and_userinfo_are_handled() -> None:
    assert extract_urls("wss://user:pw@live.example.org/socket") == [
        "wss://user:pw@live.example.org/socket"
    ]


def test_schema_and_namespace_urls_are_skipped() -> None:
    for url in (
        "http://schemas.android.com/apk/res/android",
        "http://www.w3.org/2001/XMLSchema",
        "http://www.apache.org/licenses/LICENSE-2.0",
        "http://ns.adobe.com/xap/1.0/",
    ):
        assert extract_urls(url) == []


def test_template_fragments_are_not_urls() -> None:
    assert extract_urls("https://") == []
    assert extract_urls("https://%s/api") == []
    assert extract_urls("see http://localhost:3000/x") == ["http://localhost:3000/x"]


def test_ipv4_addresses_are_extracted() -> None:
    assert extract_ipv4("connect 185.199.108.153:443 or 8.8.8.8") == ["185.199.108.153", "8.8.8.8"]


def test_ipv4_rejects_invalid_and_embedded_quads() -> None:
    assert extract_ipv4("999.1.1.1") == []
    assert extract_ipv4("version 10.20.30.40.50") == []
    assert extract_ipv4("v10.20.30.40") == []


def test_ipv4_skips_oids_versions_and_loopback() -> None:
    for text in ("1.3.101.110", "2.5.29.15", "5.5.7.6", "127.0.0.1", "0.0.0.0", "255.255.255.0"):
        assert extract_ipv4(text) == []


def test_ip_inside_a_url_is_reported_once_as_a_url() -> None:
    assert extract_endpoints(["http://203.0.113.9/gate.php"]) == [
        Endpoint(value="http://203.0.113.9/gate.php", kind="url")
    ]


def test_endpoints_are_deduplicated_and_sorted() -> None:
    pool = ["https://b.example.com/", "x https://a.example.com/y", "https://b.example.com/", "nope"]
    assert [e.value for e in extract_endpoints(pool)] == [
        "https://a.example.com/y",
        "https://b.example.com/",
    ]


def test_mask_secret_keeps_four_characters_and_the_length() -> None:
    assert mask_secret(GOOGLE_KEY) == "AIza…(39)"
    assert mask_secret(AWS_KEY) == "AKIA…(20)"


def test_secrets_are_found_by_kind() -> None:
    hits = find_secrets(f'aws="{AWS_KEY}" google="{GOOGLE_KEY}"')
    assert {(h.kind, h.value) for h in hits} == {
        ("aws_access_key_id", AWS_KEY),
        ("google_api_key", GOOGLE_KEY),
    }


def test_near_misses_are_not_secrets() -> None:
    assert find_secrets("AKIA1234") == []
    assert find_secrets("XAKIA" + "IOSFODNN7EXAMPLE") == []
    assert find_secrets("AIzaTooShort") == []


def test_redaction_never_leaves_the_full_value() -> None:
    redacted = redact_secrets(f"https://maps.example.com/api?key={GOOGLE_KEY}&v=3")
    assert GOOGLE_KEY not in redacted
    assert redacted == "https://maps.example.com/api?key=AIza…(39)&v=3"


def test_secrets_inside_endpoint_urls_are_masked() -> None:
    endpoints = extract_endpoints([f"https://maps.example.com/api?key={GOOGLE_KEY}"])
    assert [e.value for e in endpoints] == ["https://maps.example.com/api?key=AIza…(39)"]
