from __future__ import annotations

import re
from pathlib import Path

import pytest

from pipeline.claim import chunking
from pipeline.claim.chunking import chunk_markdown, plain_text, split_sentences
from pipeline.claim.models import PolicyChunk
from pipeline.claim.policy import html_to_markdown

FIXTURES = Path(__file__).parent / "fixtures"
WIFI_SENTENCE = "Required to add a WiFi network from a barcode (usually a QR Code)."


@pytest.fixture(scope="module")
def binary_eye() -> list[PolicyChunk]:
    """The real Binary Eye policy (see fixtures/README.md)."""
    return chunk_markdown((FIXTURES / "binaryeye_PRIVACY.md").read_text(encoding="utf-8")).chunks


def _by_text(chunks: list[PolicyChunk], start: str) -> list[PolicyChunk]:
    return [chunk for chunk in chunks if chunk.text.startswith(start)]


# --------------------------------------------------------------------------- Binary Eye


def test_the_camera_chunk_has_the_section_camera(binary_eye: list[PolicyChunk]) -> None:
    (chunk,) = _by_text(binary_eye, "Required to read a barcode from the camera image.")
    assert chunk.section == "CAMERA"
    assert chunk.section_path == ["Permissions", "CAMERA"]
    assert chunk.search_text == (
        "Permissions > CAMERA: Required to read a barcode from the camera image."
    )


def test_the_internet_sentence_says_it_is_about_internet(binary_eye: list[PolicyChunk]) -> None:
    (chunk,) = _by_text(binary_eye, "Required to send a scanned code to a custom URL")
    assert chunk.section == "INTERNET" and "INTERNET" in chunk.search_text


def test_a_sentence_with_a_link_and_inline_code_is_one_chunk(
    binary_eye: list[PolicyChunk],
) -> None:
    texts = [chunk.text for chunk in binary_eye]
    assert (
        "Before Android Q, this feature requires using WifiManager.getConfiguredNetworks "
        "which requires ACCESS_FINE_LOCATION."
    ) in texts
    assert (
        "From Android R, ACCESS_WIFI_STATE is required for WifiManager.getNetworkSuggestions "
        "which is used to remove individual network suggestions."
    ) in texts
    # Each dotted name appears only inside a full sentence.
    for chunk in binary_eye:
        if "WifiManager." in chunk.text:
            assert chunk.text.endswith(".") and len(chunk.text.split()) > 8


def test_no_chunk_is_just_a_bare_identifier(binary_eye: list[PolicyChunk]) -> None:
    for chunk in binary_eye:
        assert len(chunk.text.split()) >= 3, chunk.text
        assert not re.fullmatch(r"[\w.]+", chunk.text), chunk.text


def test_the_same_sentence_under_three_headings_gives_three_sections(
    binary_eye: list[PolicyChunk],
) -> None:
    chunks = [chunk for chunk in binary_eye if chunk.text == WIFI_SENTENCE]
    assert [chunk.section for chunk in chunks] == [
        "ACCESS_FINE_LOCATION",
        "CHANGE_WIFI_STATE",
        "ACCESS_WIFI_STATE",
    ]


def test_a_heading_keeps_the_link_text_never_the_reference_label(
    binary_eye: list[PolicyChunk],
) -> None:
    # The file says "### [ACCESS_WIFI_STATE][ACCESS_FINE_LOCATION]" (a typo in the label).
    assert "### [ACCESS_WIFI_STATE][ACCESS_FINE_LOCATION]" in (
        FIXTURES / "binaryeye_PRIVACY.md"
    ).read_text(encoding="utf-8")
    (chunk,) = _by_text(binary_eye, "From Android R, ACCESS_WIFI_STATE is required")
    assert chunk.section == "ACCESS_WIFI_STATE"
    assert chunk.section_path == ["Permissions", "ACCESS_WIFI_STATE"]
    sections = [chunk.section for chunk in binary_eye]
    assert sections.count("ACCESS_FINE_LOCATION") == 3  # only its own three sentences


def test_binary_eye_as_a_whole(binary_eye: list[PolicyChunk]) -> None:
    result = chunk_markdown((FIXTURES / "binaryeye_PRIVACY.md").read_text(encoding="utf-8"))
    assert result.title == "Privacy Policy" and result.truncated is False
    assert [chunk.id for chunk in binary_eye] == [f"pol_{n:03d}" for n in range(1, 18)]
    # The page title is not a section: the two opening sentences have no heading path.
    assert [chunk.section_path for chunk in binary_eye[:2]] == [[], []]
    assert binary_eye[0].search_text == "Binary Eye does not collect any personal information."
    assert {chunk.section for chunk in binary_eye[2:]} == {
        "ACCESS_FINE_LOCATION",
        "BLUETOOTH, BLUETOOTH_ADMIN and BLUETOOTH_CONNECT",
        "CAMERA",
        "INTERNET",
        "VIBRATE",
        "WRITE_EXTERNAL_STORAGE",
        "CHANGE_WIFI_STATE",
        "ACCESS_WIFI_STATE",
    }
    # "Android S." ends a sentence although S is a single letter.
    assert "BLUETOOTH_CONNECT from Android S on." in [chunk.text for chunk in binary_eye]
    # Link-reference definitions and URLs are not policy text.
    assert not any("developer.android.com" in chunk.text for chunk in binary_eye)


# --------------------------------------------------------------------------- paths, tables


@pytest.fixture(scope="module")
def table_policy() -> list[PolicyChunk]:
    return chunk_markdown((FIXTURES / "policy_table.md").read_text(encoding="utf-8")).chunks


def test_section_path_tells_collect_from_share(table_policy: list[PolicyChunk]) -> None:
    same = [c for c in table_policy if c.text == "We use your location to show nearby places."]
    # Same nearest heading and same text, but different paths: both are kept.
    assert [chunk.section for chunk in same] == ["Location", "Location"]
    assert [chunk.section_path for chunk in same] == [
        ["Data we collect", "Location"],
        ["Data we share", "Location"],
    ]
    assert same[0].search_text.startswith("Data we collect > Location: ")
    assert same[1].search_text.startswith("Data we share > Location: ")
    # The page title is skipped.
    assert not any("Example App Privacy Policy" in chunk.search_text for chunk in table_policy)


def test_a_table_gives_one_chunk_per_row(table_policy: list[PolicyChunk]) -> None:
    rows = [chunk for chunk in table_policy if chunk.text.startswith("Data type: ")]
    assert [(chunk.section_path, chunk.text) for chunk in rows] == [
        (
            ["Data we collect", "Location"],
            "Data type: Email address; Purpose: Account sign-in; Shared with: Nobody",
        ),
        (
            ["Data we collect", "Location"],
            "Data type: Device ID; Purpose: Advertising; Shared with: Ad networks",
        ),
        # An empty cell is left out; a link in a cell keeps its text.
        (["Data we collect", "Location"], "Data type: Precise location; Purpose: Maps"),
        # A table without outer pipes, under another section.
        (["Data we share", "Location"], "Data type: Crash logs; Kept for: 90 days"),
    ]
    # Rows are not merged into a paragraph, and the header row is not a chunk.
    assert not any("Purpose | Shared" in chunk.text for chunk in table_policy)
    assert not any("---" in chunk.text for chunk in table_policy)


def test_a_new_heading_replaces_deeper_and_equal_levels() -> None:
    text = (
        "## A\n\n### A1\n\nFirst sentence here.\n\n#### deep\n\nSecond sentence here.\n\n"
        "### A2\n\nThird sentence here.\n\n## B\n\nFourth sentence here."
    )
    assert [(c.section_path, c.text) for c in chunk_markdown(text).chunks] == [
        (["A", "A1"], "First sentence here."),
        (["A", "A1", "deep"], "Second sentence here."),
        (["A", "A2"], "Third sentence here."),
        (["B"], "Fourth sentence here."),
    ]


def test_several_level_one_headings_are_sections_not_a_title() -> None:
    result = chunk_markdown("# Collection\n\nWe collect email.\n\n# Sharing\n\nWe share nothing.")
    assert result.title is None
    assert [chunk.section_path for chunk in result.chunks] == [["Collection"], ["Sharing"]]


def test_setext_headings_and_lists() -> None:
    text = (
        "Policy\n======\n\nWhat we collect\n---------------\n\n"
        "- Your email address\n- Contacts, if you\n  allow it\n\n1. First numbered item here\n"
    )
    result = chunk_markdown(text)
    assert result.title == "Policy"
    assert [(c.section, c.text) for c in result.chunks] == [
        ("What we collect", "Your email address"),
        ("What we collect", "Contacts, if you allow it"),
        ("What we collect", "First numbered item here"),
    ]


# --------------------------------------------------------------------------- duplicates


def test_a_duplicate_needs_the_same_section_and_the_same_text() -> None:
    sentence = "We keep logs for a week."
    text = f"## A\n\n{sentence}\n\n{sentence}\n\n## B\n\n{sentence}"
    chunks = chunk_markdown(text).chunks
    assert [(chunk.id, chunk.section, chunk.text) for chunk in chunks] == [
        ("pol_001", "A", "We keep logs for a week."),
        ("pol_002", "B", "We keep logs for a week."),
    ]


# --------------------------------------------------------------------------- sentences


def test_lines_of_a_paragraph_are_joined_before_splitting() -> None:
    text = (
        "We collect your email\naddress when you sign up. We use\nit to sign you in.\n\n"
        "New paragraph here."
    )
    assert [chunk.text for chunk in chunk_markdown(text).chunks] == [
        "We collect your email address when you sign up.",
        "We use it to sign you in.",
        "New paragraph here.",
    ]


@pytest.mark.parametrize(
    ("paragraph", "expected"),
    [
        ("We call WifiManager.getConfiguredNetworks. It needs location.", 2),
        ("See example.com/privacy.html for details about android.permission.CAMERA use.", 1),
        ("We share data with partners, e.g. Google and Meta, for ads. We never sell it.", 2),
        (
            "This applies to Example Inc. and its affiliates, i.e. Example Ltd. in the U.K. only.",
            1,
        ),
        ("Version 2.5 was released in 2024. It changed section 3.1 only.", 2),
        ("Is my data sold? No! We never sell it.", 2),
        ("2. Sharing of your data with others.", 1),
    ],
)
def test_sentences_end_only_at_real_sentence_ends(paragraph: str, expected: int) -> None:
    sentences = split_sentences(paragraph)
    assert len(sentences) == expected, sentences
    assert " ".join(sentences) == paragraph


def test_a_one_word_fragment_joins_the_sentence_before_it() -> None:
    assert split_sentences("Is my data sold? No! We never sell it.") == [
        "Is my data sold? No!",
        "We never sell it.",
    ]


def test_very_long_sentences_are_split_and_control_characters_dropped() -> None:
    chunks = chunk_markdown("word " * 400 + "\x00\x1b[31m").chunks
    assert len(chunks) > 1
    assert all(len(chunk.text) <= chunking.MAX_CHUNK_CHARS for chunk in chunks)
    assert all("\x00" not in chunk.text and "\x1b" not in chunk.text for chunk in chunks)


def test_chunks_are_capped_and_the_cut_is_flagged() -> None:
    text = "\n\n".join(f"Sentence number {n} is long enough to stand alone." for n in range(500))
    result = chunk_markdown(text)
    assert len(result.chunks) == chunking.MAX_CHUNKS and result.truncated is True
    assert result.chunks[0].id == "pol_001" and result.chunks[-1].id == "pol_400"
    assert chunk_markdown("One sentence only.").truncated is False


def test_chunk_ids_are_stable_and_empty_text_gives_nothing() -> None:
    text = (FIXTURES / "policy_table.md").read_text(encoding="utf-8")
    assert chunk_markdown(text) == chunk_markdown(text)
    assert chunk_markdown(" \n\t\n").chunks == []


# --------------------------------------------------------------------------- inline text


@pytest.mark.parametrize(
    ("markdown", "expected"),
    [
        ("[ACCESS_WIFI_STATE][ACCESS_FINE_LOCATION]", "ACCESS_WIFI_STATE"),
        ("[CAMERA][CAMERA]", "CAMERA"),
        ("[our site](https://example.test/a_b)", "our site"),
        ("[shortcut] reference", "shortcut reference"),
        ("requires `ACCESS_FINE_LOCATION` now", "requires ACCESS_FINE_LOCATION now"),
        ("**bold** and *italic* and _emphasis_", "bold and italic and emphasis"),
        (
            "ACCESS_FINE_LOCATION and READ_SMS_MESSAGES",
            "ACCESS_FINE_LOCATION and READ_SMS_MESSAGES",
        ),
        ("![logo](https://example.test/l.png) text", "logo text"),
        ("<https://example.test/p>", "https://example.test/p"),
        ('a <span class="x">b</span> c &amp; d', "a b c & d"),
        ("escaped \\*star\\* and 5 \\* 3", "escaped *star* and 5 * 3"),
    ],
)
def test_plain_text(markdown: str, expected: str) -> None:
    assert plain_text(markdown) == expected


def test_code_blocks_and_rules_are_not_policy_text() -> None:
    text = "Intro sentence here.\n\n```\nrm -rf / # never run\n```\n\n---\n\nClosing sentence here."
    assert [chunk.text for chunk in chunk_markdown(text).chunks] == [
        "Intro sentence here.",
        "Closing sentence here.",
    ]


# --------------------------------------------------------------------------- HTML policies

HTML_POLICY = """<!doctype html><html><head><title>Privacy</title>
<script>alert("never run")</script></head><body><main><article>
<h1>Privacy Policy</h1>
<p>We respect your privacy. This policy explains what we do with <a href="/x">your data</a> and
why, e.g. when you call <code>WifiManager.getConfiguredNetworks</code> it needs location.</p>
<h2>Data we collect</h2>
<h3>Location</h3>
<p>We collect your precise location while the app is open.</p>
<p><strong>How long we keep it</strong></p>
<p>We keep location data for thirty days and then delete it from our servers.</p>
<h2>Data we share</h2>
<h3>Location</h3>
<p>We share coarse location with our advertising partners.</p>
<table><thead><tr><th>Data type</th><th>Purpose</th><th>Shared with</th></tr></thead>
<tbody><tr><td>Email address</td><td>Account sign-in</td><td>Nobody</td></tr>
<tr><td>Device ID</td><td>Advertising</td><td><b>Ad networks</b></td></tr></tbody></table>
</article></main></body></html>"""

HTML_EXPECTED = [
    ([], "We respect your privacy."),
    (
        [],
        "This policy explains what we do with your data and why, e.g. when you call "
        "WifiManager.getConfiguredNetworks it needs location.",
    ),
    (["Data we collect", "Location"], "We collect your precise location while the app is open."),
    (
        ["Data we collect", "Location", "How long we keep it"],
        "We keep location data for thirty days and then delete it from our servers.",
    ),
    (["Data we share", "Location"], "We share coarse location with our advertising partners."),
    (
        ["Data we share", "Location"],
        "Data type: Email address; Purpose: Account sign-in; Shared with: Nobody",
    ),
    (
        ["Data we share", "Location"],
        "Data type: Device ID; Purpose: Advertising; Shared with: Ad networks",
    ),
]


def test_an_html_policy_keeps_headings_tables_and_whole_sentences() -> None:
    result = chunk_markdown(html_to_markdown(HTML_POLICY), bold_headings=True)
    assert result.title == "Privacy Policy"
    assert [(chunk.section_path, chunk.text) for chunk in result.chunks] == HTML_EXPECTED
    assert not any("alert" in chunk.text for chunk in result.chunks)


def test_a_short_bold_only_paragraph_is_a_heading_only_when_asked() -> None:
    text = (
        "## Data\n\n**How long we keep it**\n\nThirty days at most.\n\n"
        "**This bold paragraph is far too long to be a heading of any kind.**\n\n"
        "## Next\n\nAnother sentence here."
    )
    with_bold = chunk_markdown(text, bold_headings=True).chunks
    assert [(c.section_path, c.text) for c in with_bold] == [
        (["Data", "How long we keep it"], "Thirty days at most."),
        (
            ["Data", "How long we keep it"],
            "This bold paragraph is far too long to be a heading of any kind.",
        ),
        # A real heading ends the bold one.
        (["Next"], "Another sentence here."),
    ]
    without = chunk_markdown(text).chunks
    assert (["Data"], "How long we keep it") in [(c.section_path, c.text) for c in without]


def test_the_fallback_html_parser_keeps_headings_and_whole_sentences(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import trafilatura

    monkeypatch.setattr(trafilatura, "extract", lambda *_args, **_kwargs: None)

    chunks = chunk_markdown(html_to_markdown(HTML_POLICY), bold_headings=True).chunks

    by_text = {chunk.text: chunk.section_path for chunk in chunks}
    assert by_text["We collect your precise location while the app is open."] == [
        "Data we collect",
        "Location",
    ]
    assert by_text["We share coarse location with our advertising partners."] == [
        "Data we share",
        "Location",
    ]
    assert any("WifiManager.getConfiguredNetworks it needs location." in text for text in by_text)
    assert not any("alert" in text for text in by_text)
