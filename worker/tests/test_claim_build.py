from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from pipeline.claim import build_claim, cache, claim_evidence
from pipeline.claim import claim as claim_module
from pipeline.claim.models import (
    CachedClaim,
    Claim,
    PlayListing,
    PlayLookup,
    PolicyChunk,
    PolicyResult,
)

LISTING = PlayListing(
    title="Super Flashlight - Bright LED Torch",
    description="The brightest flashlight.",
    category="Tools",
    developer="Example Apps",
    developer_website="https://example-apps.test/",
    privacy_policy_url="https://example-apps.test/privacy",
    installs="1,000,000+",
    updated_on=date(2026, 9, 1),
    url="https://play.google.com/store/apps/details?id=com.example.flashlight",
)
POLICY = PolicyResult(
    status="fetched",
    url="https://example-apps.test/privacy",
    final_url="https://example-apps.test/privacy/",
    format="html",
    title="Privacy Policy",
    chunks=[
        PolicyChunk(id="pol_001", text="We collect your email address."),
        PolicyChunk(
            id="pol_002",
            section="Microphone",
            section_path=["Data we collect", "Microphone"],
            text="We never record audio.",
        ),
    ],
)


class Sources:
    """Stands in for the Play lookup and the policy fetch, and counts the calls."""

    def __init__(self) -> None:
        self.play: PlayLookup | Exception = PlayLookup(status="found", listing=LISTING)
        self.policy: PolicyResult = POLICY
        self.play_calls: list[str] = []
        self.policy_calls: list[str | None] = []

    def fetch_listing(self, package_name: str) -> PlayLookup:
        self.play_calls.append(package_name)
        if isinstance(self.play, Exception):
            raise self.play
        return self.play

    def fetch_policy(self, url: str | None) -> PolicyResult:
        self.policy_calls.append(url)
        return self.policy


@pytest.fixture
def sources(monkeypatch: pytest.MonkeyPatch) -> Sources:
    fake = Sources()
    monkeypatch.setattr(claim_module, "fetch_listing", fake.fetch_listing)
    monkeypatch.setattr(claim_module, "fetch_policy", fake.fetch_policy)
    return fake


NOT_FOUND = PlayLookup(status="not_found", note="No Play Store listing for this package name.")

# --------------------------------------------------------------------------- sources


def test_claim_from_a_play_listing_with_a_policy(sources: Sources) -> None:
    claim = build_claim("com.example.flashlight", "Super Flashlight", "from my cousin")

    assert claim.source == "play_store" and claim.play_lookup == "found"
    assert claim.title == "Super Flashlight - Bright LED Torch"
    assert claim.description_excerpt == "The brightest flashlight."
    assert (claim.category, claim.category_source) == ("Tools", "play_store")
    assert claim.developer == "Example Apps" and claim.installs == "1,000,000+"
    assert claim.updated_on == date(2026, 9, 1)
    assert claim.privacy_policy_url == "https://example-apps.test/privacy"
    assert claim.policy_status == "fetched"
    assert claim.schema_version == "claim.v2"
    assert claim.policy_final_url == "https://example-apps.test/privacy/"
    assert (claim.policy_format, claim.policy_title) == ("html", "Privacy Policy")
    assert claim.policy_chunks[1].section_path == ["Data we collect", "Microphone"]
    assert [(chunk.id, chunk.text) for chunk in claim.listing_chunks] == [
        ("lst_001", "The brightest flashlight."),
        ("lst_002", "from my cousin"),
    ]
    assert claim.flag_chunks == []
    assert [chunk.id for chunk in claim.policy_chunks] == ["pol_001", "pol_002"]
    assert claim.caption == "from my cousin"
    assert claim.flags == [] and claim.notes == []
    assert claim.evidence == ["lst_001", "lst_002", "pol_001", "pol_002"]
    assert sources.policy_calls == ["https://example-apps.test/privacy"]


def test_not_on_play_falls_back_to_the_caption(sources: Sources) -> None:
    sources.play = NOT_FOUND

    claim = build_claim("com.scam.invite", "Wedding Invitation", "  my cousin sent this  ")

    assert claim.source == "caption" and claim.play_lookup == "not_found"
    assert claim.caption == "my cousin sent this"
    assert claim.title == "Wedding Invitation"
    assert claim.category is None and claim.category_source is None
    assert claim.policy_status == "no_url" and claim.policy_chunks == []
    assert claim.flags == ["claim_not_on_play", "claim_no_policy"]
    assert claim.evidence == ["lst_002", "claim_not_on_play", "claim_no_policy"]
    assert sources.policy_calls == [], "there is no policy URL to fetch"


@pytest.mark.parametrize("caption", [None, "", "   "])
def test_not_on_play_without_a_caption_falls_back_to_the_label(
    sources: Sources, caption: str | None
) -> None:
    sources.play = NOT_FOUND

    claim = build_claim("com.scam.invite", "Wedding Invitation", caption)

    assert claim.source == "app_label" and claim.caption is None
    assert claim.evidence == ["claim_not_on_play", "claim_no_policy"]


def test_a_failed_play_lookup_is_not_reported_as_not_on_play(sources: Sources) -> None:
    sources.play = PlayLookup(status="error", note="Play Store lookup timed out (10 s).")

    claim = build_claim("com.example.app", "Example", "a note")

    assert claim.source == "caption" and claim.play_lookup == "error"
    # Nothing is known about the listing or the policy, so no flag claims otherwise.
    assert claim.flags == []
    assert "Play Store lookup timed out (10 s)." in claim.notes


def test_the_claim_never_raises(sources: Sources) -> None:
    sources.play = RuntimeError("the scraper exploded")

    claim = build_claim("com.example.app", "Example", "a note")

    assert claim.source == "caption" and claim.play_lookup == "error"
    assert claim.title == "Example" and claim.evidence == ["lst_002"]
    assert claim.notes == ["The claim could not be built; only the app name and caption are used."]


# --------------------------------------------------------------------------- policy


@pytest.mark.parametrize(
    ("status", "flags"),
    [
        ("fetch_failed", ["claim_policy_fetch_failed"]),
        ("not_found", ["claim_no_policy"]),
        ("no_url", ["claim_no_policy"]),
    ],
)
def test_policy_problems_are_flagged(sources: Sources, status: str, flags: list[str]) -> None:
    sources.policy = PolicyResult(status=status, note="why")  # type: ignore[arg-type]

    claim = build_claim("com.example.flashlight", "Super Flashlight")

    assert claim.source == "play_store"
    assert claim.policy_status == status and claim.policy_chunks == []
    assert claim.flags == flags and "why" in claim.notes


# --------------------------------------------------------------------------- impersonation


@pytest.mark.parametrize(
    "label",
    ["Super Flashlight", "super flashlight - bright led torch", "SuperFlashlight", "Flashlight"],
)
def test_a_matching_label_is_not_flagged(sources: Sources, label: str) -> None:
    claim = build_claim("com.example.flashlight", label)
    assert claim.label_title_similarity is not None
    assert claim.label_title_similarity >= claim_module.IMPERSONATION_THRESHOLD
    assert "claim_possible_impersonation" not in claim.flags


@pytest.mark.parametrize("label", ["Wedding Invitation", "SBI Rewards", "PM Kisan Yojana"])
def test_a_mismatching_label_is_flagged_as_possible_impersonation(
    sources: Sources, label: str
) -> None:
    claim = build_claim("com.example.flashlight", label)
    assert claim.label_title_similarity is not None
    assert claim.label_title_similarity < claim_module.IMPERSONATION_THRESHOLD
    assert claim.flags == ["claim_possible_impersonation"]
    assert "claim_possible_impersonation" in claim.evidence


def test_no_label_or_no_listing_means_no_impersonation_check(sources: Sources) -> None:
    assert build_claim("com.example.flashlight", None).label_title_similarity is None
    assert build_claim("com.example.flashlight", "!!!").label_title_similarity is None
    sources.play = NOT_FOUND
    claim = build_claim("com.example.flashlight", "Wedding Invitation")
    assert claim.label_title_similarity is None
    assert "claim_possible_impersonation" not in claim.flags


@pytest.mark.parametrize(
    ("label", "title", "expected"),
    [
        ("WhatsApp", "WhatsApp Messenger", 1.0),
        ("WhatsApp", "whatsapp", 1.0),
        ("Telegram", "Telegram", 1.0),
        ("Wedding Invite", "WhatsApp Messenger", 0.25),
        ("", "WhatsApp", None),
    ],
)
def test_name_similarity(label: str, title: str, expected: float | None) -> None:
    score = claim_module.name_similarity(label, title)
    if expected is None or expected == 1.0:
        assert score == expected
    else:
        assert score is not None and score < claim_module.IMPERSONATION_THRESHOLD


# --------------------------------------------------------------------------- cache


def test_listing_and_policy_are_cached_per_package_but_the_caption_is_not(
    sources: Sources, tmp_path: Path
) -> None:
    first = build_claim(
        "com.example.flashlight", "Super Flashlight", "secret note", cache_dir=tmp_path
    )
    second = build_claim(
        "com.example.flashlight", "Super Flashlight", "other note", cache_dir=tmp_path
    )

    assert (first.from_cache, second.from_cache) == (False, True)
    assert len(sources.play_calls) == 1 and len(sources.policy_calls) == 1
    assert second.caption == "other note"
    per_request = {"caption", "from_cache", "listing_chunks"}
    assert second.model_dump(exclude=per_request) == first.model_dump(exclude=per_request)
    assert second.listing_chunks[1].text == "other note"
    (cache_file,) = tmp_path.iterdir()
    assert cache_file.name == "com.example.flashlight.json"
    stored = cache_file.read_text()
    assert "secret note" not in stored and "other note" not in stored
    assert json.loads(stored)["play"]["listing"]["title"] == LISTING.title


def test_not_on_play_is_cached_too(sources: Sources, tmp_path: Path) -> None:
    sources.play = NOT_FOUND
    build_claim("com.scam.invite", "Invite", cache_dir=tmp_path)
    claim = build_claim("com.scam.invite", "Invite", cache_dir=tmp_path)
    assert claim.from_cache and claim.flags == ["claim_not_on_play", "claim_no_policy"]
    assert len(sources.play_calls) == 1


def test_errors_are_not_cached(sources: Sources, tmp_path: Path) -> None:
    sources.play = PlayLookup(status="error", note="timed out")
    build_claim("com.example.flashlight", "Super Flashlight", cache_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []

    # A failed policy fetch keeps the listing but is retried on the next scan.
    sources.play = PlayLookup(status="found", listing=LISTING)
    sources.policy = PolicyResult(status="fetch_failed", note="timed out")
    build_claim("com.example.flashlight", "Super Flashlight", cache_dir=tmp_path)
    sources.policy = POLICY
    claim = build_claim("com.example.flashlight", "Super Flashlight", cache_dir=tmp_path)

    assert claim.policy_status == "fetched" and claim.from_cache
    assert len(sources.play_calls) == 2 and len(sources.policy_calls) == 2


def test_cache_entries_expire_after_three_days(sources: Sources, tmp_path: Path) -> None:
    build_claim("com.example.flashlight", "Super Flashlight", cache_dir=tmp_path)
    now = datetime.now(UTC)

    assert cache.load(tmp_path, "com.example.flashlight", now=now + timedelta(days=2, hours=23))
    assert (
        cache.load(tmp_path, "com.example.flashlight", now=now + timedelta(days=3, minutes=1))
        is None
    )


def test_a_corrupt_cache_entry_is_ignored(sources: Sources, tmp_path: Path) -> None:
    (tmp_path / "com.example.flashlight.json").write_text("{not json")
    claim = build_claim("com.example.flashlight", "Super Flashlight", cache_dir=tmp_path)
    assert claim.source == "play_store" and not claim.from_cache


@pytest.mark.parametrize("package", ["../../etc/passwd", "com.example/../../x", "..", "a/b.c"])
def test_an_unsafe_package_name_never_becomes_a_file_name(
    sources: Sources, tmp_path: Path, package: str
) -> None:
    cache_dir = tmp_path / "claims"
    assert cache.cache_path(cache_dir, package) is None
    sources.play = NOT_FOUND

    build_claim(package, "App", cache_dir=cache_dir)

    assert not cache_dir.exists()
    assert [path.name for path in tmp_path.iterdir()] == []


# --------------------------------------------------------------------------- evidence, model


def test_every_cited_evidence_id_exists(sources: Sources) -> None:
    claim = build_claim("com.example.flashlight", "Wedding Invitation", "a note")
    items = claim_evidence(claim)

    assert set(items) == set(claim.evidence)
    assert items["lst_001"].kind == "listing" and LISTING.url in items["lst_001"].location
    assert items["lst_002"].kind == "caption" and items["lst_002"].snippet == "a note"
    assert items["pol_002"].kind == "policy"
    assert items["pol_002"].location == (
        'chunk #2 (section "Data we collect > Microphone") of the policy at '
        "https://example-apps.test/privacy/"
    )
    assert (
        items["pol_001"].location == "chunk #1 of the policy at https://example-apps.test/privacy/"
    )
    assert items["claim_possible_impersonation"].kind == "claim"


@pytest.mark.parametrize(
    ("on_play", "label", "caption"),
    [
        (True, "Wedding Invitation", "a note"),
        (True, "Super Flashlight", None),
        (False, "App", "x"),
        (False, "App", None),
    ],
)
def test_every_evidence_id_resolves_to_text_inside_the_claim(
    sources: Sources, on_play: bool, label: str, caption: str | None
) -> None:
    if not on_play:
        sources.play = NOT_FOUND

    claim = build_claim("com.example.flashlight", label, caption)

    text_by_id = {
        chunk.id: chunk.text
        for chunk in [*claim.listing_chunks, *claim.flag_chunks, *claim.policy_chunks]
    }
    assert set(text_by_id) == set(claim.evidence) and claim.evidence
    assert all(text_by_id.values())
    assert [chunk.id for chunk in claim.flag_chunks] == claim.flags


def test_listing_and_flag_chunks(sources: Sources) -> None:
    sources.play = NOT_FOUND
    claim = build_claim("com.scam.invite", "Wedding Invitation", "my cousin sent this")

    assert [(chunk.id, chunk.text) for chunk in claim.listing_chunks] == [
        ("lst_002", "my cousin sent this")
    ]
    assert [chunk.id for chunk in claim.flag_chunks] == ["claim_not_on_play", "claim_no_policy"]
    assert "outside the Play Store" in claim.flag_chunks[0].text


def test_cache_entries_from_the_old_version_are_not_reused(
    sources: Sources, tmp_path: Path
) -> None:
    build_claim("com.example.flashlight", "Super Flashlight", cache_dir=tmp_path)
    cache_file = tmp_path / "com.example.flashlight.json"
    current = json.loads(cache_file.read_text())
    assert current["schema_version"] == CachedClaim.model_fields["schema_version"].default
    assert current["schema_version"] == "claim-cache.v2"

    # What a claim-cache.v1 entry looked like: chunks without sections.
    old = {**current, "schema_version": "claim-cache.v1"}
    old["policy"] = {
        "status": "fetched",
        "url": "https://example-apps.test/privacy",
        "final_url": "https://example-apps.test/privacy",
        "chunks": [{"id": "pol_001", "text": "WifiManager.getConfiguredNetworks"}],
        "truncated": False,
        "note": None,
    }
    cache_file.write_text(json.dumps(old))

    claim = build_claim("com.example.flashlight", "Super Flashlight", cache_dir=tmp_path)

    assert not claim.from_cache and len(sources.play_calls) == 2
    assert [chunk.id for chunk in claim.policy_chunks] == ["pol_001", "pol_002"]
    assert json.loads(cache_file.read_text())["schema_version"] == "claim-cache.v2"


def test_untrusted_text_is_stored_as_plain_clipped_text(sources: Sources) -> None:
    claim = build_claim(
        "com.example.flashlight", "<b>App</b>\x00" + "x" * 500, "c\x1b[31m" + "y" * 9000
    )
    assert claim.app_label is not None and "\x00" not in claim.app_label
    assert len(claim.app_label) == claim_module.MAX_LABEL_CHARS
    assert claim.caption is not None and "\x1b" not in claim.caption
    assert len(claim.caption) == claim_module.MAX_CAPTION_CHARS
    assert len(claim_evidence(claim)["lst_002"].snippet) <= claim_module.MAX_SNIPPET_CHARS


def test_category_source_accepts_inferred_for_the_purpose_agent() -> None:
    claim = Claim(
        source="caption",
        package_name="com.scam.invite",
        play_lookup="not_found",
        policy_status="no_url",
        category="Events",
        category_source="inferred",
    )
    assert claim.category_source == "inferred"
    with pytest.raises(ValueError):
        Claim.model_validate({**claim.model_dump(), "category_source": "guessed"})
