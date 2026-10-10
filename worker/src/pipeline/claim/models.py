"""Pydantic models for the claim (``claim.v2``, decisions D-033 and D-037).

Field names follow the ``claim`` block of report.v1 (spec §8.4) where one exists. Like the
extraction models, these move to ``packages/shared`` when report.v1 is frozen (D-015).
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "claim.v2"

ClaimSource = Literal["play_store", "caption", "app_label"]
PlayLookupStatus = Literal["found", "not_found", "error", "skipped"]
PolicyStatus = Literal["fetched", "not_found", "fetch_failed", "no_url"]
PolicyFormat = Literal["markdown", "html", "text"]

# Named evidence ids for special claim facts (spec §8.1).
FLAG_NOT_ON_PLAY = "claim_not_on_play"
FLAG_NO_POLICY = "claim_no_policy"
FLAG_POLICY_FETCH_FAILED = "claim_policy_fetch_failed"
FLAG_POSSIBLE_IMPERSONATION = "claim_possible_impersonation"

LISTING_EVIDENCE_ID = "lst_001"
CAPTION_EVIDENCE_ID = "lst_002"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PlayListing(_Model):
    """The parts of a Play Store listing the claim uses."""

    title: str
    description: str | None = None
    category: str | None = None
    developer: str | None = None
    developer_website: str | None = None
    privacy_policy_url: str | None = None
    installs: str | None = None
    updated_on: date | None = None
    url: str


class PlayLookup(_Model):
    """Outcome of a Play Store lookup. ``note`` says why when there is no listing."""

    status: PlayLookupStatus
    listing: PlayListing | None = None
    note: str | None = None


class Chunk(_Model):
    """An evidence id and the text it stands for."""

    id: str
    text: str


class PolicyChunk(_Model):
    """One sentence (or one table row) of the privacy policy, with its headings."""

    id: str
    # The nearest heading above the sentence, e.g. "CAMERA". Same as section_path[-1].
    section: str | None = None
    # Every heading above it, outermost first, e.g. ["Permissions", "CAMERA"]. The page
    # title is not part of the path (see Claim.policy_title).
    section_path: list[str] = Field(default_factory=list)
    text: str

    @property
    def search_text(self) -> str:
        """What policy retrieval (BM25, spec §7.11) must index: the heading path and the text.

        The text alone is not enough: "Required to send a scanned code to a custom URL"
        only says it is about INTERNET through its heading, and "Location" under "Data we
        collect" means something else than under "Data we share".
        """
        if not self.section_path:
            return self.text
        return f"{' > '.join(self.section_path)}: {self.text}"


class PolicyResult(_Model):
    """Outcome of a privacy-policy fetch. ``note`` says why when it was not fetched."""

    status: PolicyStatus
    # The URL the listing gives, and the URL the text was really fetched from. They differ
    # after a redirect and for GitHub pages, which are fetched as raw files.
    url: str | None = None
    final_url: str | None = None
    format: PolicyFormat | None = None
    title: str | None = None
    chunks: list[PolicyChunk] = Field(default_factory=list)
    truncated: bool = False
    note: str | None = None


class CachedClaim(_Model):
    """What is cached per package (D-029). The caption is never part of it.

    The version is bumped whenever the cached shape or the chunking changes. An entry
    with another version fails validation and is ignored, so stale claims are never
    reused. It is separate from ``PIPELINE_VERSION``, which keys the extraction cache.
    """

    schema_version: Literal["claim-cache.v2"] = "claim-cache.v2"
    package_name: str
    fetched_at: datetime
    play: PlayLookup
    # None means the policy still has to be fetched (the last attempt failed).
    policy: PolicyResult | None = None


class Claim(_Model):
    schema_version: Literal["claim.v2"] = "claim.v2"
    source: ClaimSource
    package_name: str
    app_label: str | None = None
    # The sender's own words. Private to the scan: never cached per APK or per package.
    caption: str | None = None

    play_lookup: PlayLookupStatus
    title: str | None = None
    description_excerpt: str | None = None
    category: str | None = None
    # "inferred" is reserved for the Purpose agent (sideloaded apps, spec §7.10).
    category_source: Literal["play_store", "inferred"] | None = None
    developer: str | None = None
    developer_website: str | None = None
    installs: str | None = None
    updated_on: date | None = None
    play_url: str | None = None

    privacy_policy_url: str | None = None
    policy_status: PolicyStatus
    # The URL the policy text was fetched from (after redirects; the raw file for GitHub).
    policy_final_url: str | None = None
    policy_format: PolicyFormat | None = None
    policy_title: str | None = None
    policy_chunks: list[PolicyChunk] = Field(default_factory=list)
    policy_truncated: bool = False
    # Text behind the other evidence ids, so that every id in ``evidence`` resolves to
    # text inside the claim: lst_001 = Play description, lst_002 = caption, claim_* = flag.
    listing_chunks: list[Chunk] = Field(default_factory=list)
    flag_chunks: list[Chunk] = Field(default_factory=list)

    # 0..1, APK label against the Play title. None when there is nothing to compare.
    label_title_similarity: float | None = None
    flags: list[str] = Field(default_factory=list)
    # Why the claim fell back, e.g. "Play Store lookup timed out".
    notes: list[str] = Field(default_factory=list)
    from_cache: bool = False
    evidence: list[str] = Field(default_factory=list)
