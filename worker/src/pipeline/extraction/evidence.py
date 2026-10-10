"""Evidence ids (spec §8.1).

Ids are ``<prefix>_<nnn>``, numbered per prefix in the order facts are recorded. Callers
record facts in sorted order, so the ids are stable for the same APK.
"""

from __future__ import annotations

from .models import EvidenceItem, EvidenceKind
from .strings import redact_secrets

MAX_SNIPPET_CHARS = 200
MAX_LOCATION_CHARS = 400

_KIND_BY_PREFIX: dict[str, EvidenceKind] = {
    "man": "manifest",
    "api": "api_call",
    "sdk": "sdk",
    "str": "string",
    "file": "file",
}


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class EvidenceStore:
    """Collects evidence items and hands out ids. The same location is stored once."""

    def __init__(self) -> None:
        self._items: dict[str, EvidenceItem] = {}
        self._ids_by_key: dict[tuple[str, str], str] = {}
        self._next: dict[str, int] = {}

    def add(self, prefix: str, location: str, snippet: str) -> str:
        """Record one piece of evidence and return its id.

        Text taken from the APK is untrusted: secrets are masked and long values clipped.
        """
        kind = _KIND_BY_PREFIX[prefix]
        location = _clip(redact_secrets(location), MAX_LOCATION_CHARS)
        key = (prefix, location)
        existing = self._ids_by_key.get(key)
        if existing is not None:
            return existing
        number = self._next.get(prefix, 0) + 1
        self._next[prefix] = number
        evidence_id = f"{prefix}_{number:03d}"
        self._ids_by_key[key] = evidence_id
        self._items[evidence_id] = EvidenceItem(
            kind=kind,
            location=location,
            snippet=_clip(redact_secrets(snippet), MAX_SNIPPET_CHARS),
        )
        return evidence_id

    def items(self) -> dict[str, EvidenceItem]:
        return dict(self._items)
