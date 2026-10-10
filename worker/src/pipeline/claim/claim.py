"""Build the claim: what the app says it is (spec §7.8).

    build_claim(package_name, app_label, caption) -> Claim

The claim is best effort and must never fail a scan: every failure falls back to a
weaker source and is recorded in ``notes``.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path

from ..extraction.models import EvidenceItem
from . import cache
from .models import (
    CAPTION_EVIDENCE_ID,
    FLAG_NO_POLICY,
    FLAG_NOT_ON_PLAY,
    FLAG_POLICY_FETCH_FAILED,
    FLAG_POSSIBLE_IMPERSONATION,
    LISTING_EVIDENCE_ID,
    Chunk,
    Claim,
    ClaimSource,
    PlayLookup,
    PolicyResult,
)
from .play import fetch_listing
from .policy import fetch_policy

logger = logging.getLogger("plainsight.worker.claim")

# Below this label-vs-title score the listing may describe a different app (D-032).
IMPERSONATION_THRESHOLD = 0.5
# Telegram's caption limit; anything longer is clipped.
MAX_CAPTION_CHARS = 4096
MAX_LABEL_CHARS = 200
MAX_SNIPPET_CHARS = 200
MAX_LOCATION_CHARS = 400

_FLAG_TEXT: dict[str, tuple[str, str]] = {
    FLAG_NOT_ON_PLAY: (
        "Play Store lookup by package name",
        "No Play Store listing exists for this package name: the app is distributed "
        "outside the Play Store.",
    ),
    FLAG_NO_POLICY: (
        "privacy policy",
        "No privacy policy is available for this app.",
    ),
    FLAG_POLICY_FETCH_FAILED: (
        "privacy policy",
        "The listing links a privacy policy, but it could not be fetched.",
    ),
    FLAG_POSSIBLE_IMPERSONATION: (
        "APK label compared with the Play Store title",
        "The APK's name does not match the Play Store listing for its package name, so "
        "the listing may describe a different app.",
    ),
}


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _clean(value: str | None, limit: int) -> str | None:
    """Plain, clipped text or None. Control characters are dropped."""
    if not value:
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable() or ch in "\n\t").strip()
    return _clip(cleaned, limit) if cleaned else None


# --------------------------------------------------------------------------- similarity


def _words(text: str) -> list[str]:
    return re.findall(r"[^\W_]+", unicodedata.normalize("NFKC", text).casefold())


def name_similarity(app_label: str, play_title: str) -> float | None:
    """How well the APK's label matches the Play title, 0..1 (D-032).

    Both names are lower-cased and reduced to letters and digits. The score is the higher of

    - the character similarity ratio of the two names, and
    - the share of the label's words that appear in the title, so that the label
      "WhatsApp" matches the title "WhatsApp Messenger".

    None when either name has no letters or digits to compare.
    """
    label_words, title_words = _words(app_label), _words(play_title)
    if not label_words or not title_words:
        return None
    ratio = SequenceMatcher(None, "".join(label_words), "".join(title_words)).ratio()
    overlap = len(set(label_words) & set(title_words)) / len(set(label_words))
    return round(max(ratio, overlap), 3)


# --------------------------------------------------------------------------- building


def _lookup(package_name: str, cache_dir: Path | None) -> tuple[PlayLookup, PolicyResult, bool]:
    """Listing and policy for a package, from the cache when it is fresh."""
    entry = cache.load(cache_dir, package_name) if cache_dir is not None else None
    play = entry.play if entry else fetch_listing(package_name)
    policy = entry.policy if entry else None

    if policy is None:
        if play.listing is not None:
            policy = fetch_policy(play.listing.privacy_policy_url)
        else:
            policy = PolicyResult(
                status="no_url", note="There is no listing to take a policy from."
            )
        # Errors are not cached, so the next scan tries again.
        if cache_dir is not None and play.status in ("found", "not_found"):
            cache.save(
                cache_dir,
                package_name,
                play,
                policy if policy.status != "fetch_failed" else None,
                fetched_at=entry.fetched_at if entry else None,
            )
    return play, policy, entry is not None


def _build(
    package_name: str, app_label: str | None, caption: str | None, cache_dir: Path | None
) -> Claim:
    play, policy, from_cache = _lookup(package_name, cache_dir)
    listing = play.listing

    source: ClaimSource = "play_store" if listing else ("caption" if caption else "app_label")
    flags: list[str] = []
    notes = [note for note in (play.note, policy.note) if note]
    evidence: list[str] = []

    if listing is not None:
        evidence.append(LISTING_EVIDENCE_ID)
    if caption:
        evidence.append(CAPTION_EVIDENCE_ID)

    if play.status == "not_found":
        flags.append(FLAG_NOT_ON_PLAY)
    # After a failed lookup nothing is known about the policy, so no flag is raised.
    if play.status != "error":
        if policy.status in ("no_url", "not_found"):
            flags.append(FLAG_NO_POLICY)
        elif policy.status == "fetch_failed":
            flags.append(FLAG_POLICY_FETCH_FAILED)

    similarity = None
    if listing is not None and app_label:
        similarity = name_similarity(app_label, listing.title)
        if similarity is not None and similarity < IMPERSONATION_THRESHOLD:
            flags.append(FLAG_POSSIBLE_IMPERSONATION)

    evidence += flags
    evidence += [chunk.id for chunk in policy.chunks]

    listing_chunks = []
    if listing is not None:
        listing_chunks.append(
            Chunk(id=LISTING_EVIDENCE_ID, text=listing.description or listing.title)
        )
    if caption:
        listing_chunks.append(Chunk(id=CAPTION_EVIDENCE_ID, text=caption))

    return Claim(
        source=source,
        package_name=package_name,
        app_label=app_label,
        caption=caption,
        play_lookup=play.status,
        title=listing.title if listing else app_label,
        description_excerpt=listing.description if listing else None,
        category=listing.category if listing else None,
        category_source="play_store" if listing and listing.category else None,
        developer=listing.developer if listing else None,
        developer_website=listing.developer_website if listing else None,
        installs=listing.installs if listing else None,
        updated_on=listing.updated_on if listing else None,
        play_url=listing.url if listing else None,
        privacy_policy_url=listing.privacy_policy_url if listing else None,
        policy_status=policy.status,
        policy_final_url=policy.final_url,
        policy_format=policy.format,
        policy_title=policy.title,
        policy_chunks=policy.chunks,
        policy_truncated=policy.truncated,
        listing_chunks=listing_chunks,
        flag_chunks=[Chunk(id=flag, text=_FLAG_TEXT[flag][1]) for flag in flags],
        label_title_similarity=similarity,
        flags=flags,
        notes=notes,
        from_cache=from_cache,
        evidence=evidence,
    )


def build_claim(
    package_name: str,
    app_label: str | None,
    caption: str | None = None,
    *,
    cache_dir: Path | None = None,
) -> Claim:
    """Describe what the app says it is. Never raises.

    ``package_name`` and ``app_label`` come from the APK's manifest (never from the file
    name), ``caption`` from the person who sent it. ``cache_dir`` enables the per-package
    cache of the listing and policy; the caption is not cached.
    """
    package_name = _clean(package_name, 300) or "unknown"
    app_label = _clean(app_label, MAX_LABEL_CHARS)
    caption = _clean(caption, MAX_CAPTION_CHARS)
    try:
        return _build(package_name, app_label, caption, cache_dir)
    except Exception:
        logger.exception("building the claim failed; falling back to the label and caption")
        return Claim(
            source="caption" if caption else "app_label",
            package_name=package_name,
            app_label=app_label,
            caption=caption,
            play_lookup="error",
            title=app_label,
            policy_status="no_url",
            notes=["The claim could not be built; only the app name and caption are used."],
            listing_chunks=[Chunk(id=CAPTION_EVIDENCE_ID, text=caption)] if caption else [],
            evidence=[CAPTION_EVIDENCE_ID] if caption else [],
        )


# --------------------------------------------------------------------------- evidence


def claim_evidence(claim: Claim) -> dict[str, EvidenceItem]:
    """The evidence items behind ``claim.evidence`` (spec §8.1), keyed by id."""
    items: dict[str, EvidenceItem] = {}
    if LISTING_EVIDENCE_ID in claim.evidence:
        text = ": ".join(part for part in (claim.title, claim.description_excerpt) if part)
        items[LISTING_EVIDENCE_ID] = EvidenceItem(
            kind="listing",
            location=_clip(f"Play Store listing {claim.play_url}", MAX_LOCATION_CHARS),
            snippet=_clip(text, MAX_SNIPPET_CHARS),
        )
    if CAPTION_EVIDENCE_ID in claim.evidence and claim.caption:
        items[CAPTION_EVIDENCE_ID] = EvidenceItem(
            kind="caption",
            location="caption sent with the APK",
            snippet=_clip(claim.caption, MAX_SNIPPET_CHARS),
        )
    for flag in claim.flags:
        location, snippet = _FLAG_TEXT[flag]
        items[flag] = EvidenceItem(kind="claim", location=location, snippet=snippet)
    policy_url = claim.policy_final_url or claim.privacy_policy_url
    for number, chunk in enumerate(claim.policy_chunks, start=1):
        where = f' (section "{" > ".join(chunk.section_path)}")' if chunk.section_path else ""
        items[chunk.id] = EvidenceItem(
            kind="policy",
            location=_clip(
                f"chunk #{number}{where} of the policy at {policy_url}", MAX_LOCATION_CHARS
            ),
            snippet=_clip(chunk.text, MAX_SNIPPET_CHARS),
        )
    return items
