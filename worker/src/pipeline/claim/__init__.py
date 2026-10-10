"""The claim side (spec §7.8): what the app says it is.

    from pipeline.claim import build_claim

    claim = build_claim("com.example.app", "Example", caption="sent by my bank")

Everything fetched here (Play listing, privacy policy) and the caption is untrusted text.
It is stored as plain text and never executed or rendered.
"""

from __future__ import annotations

from .claim import build_claim, claim_evidence
from .models import SCHEMA_VERSION, Chunk, Claim, PolicyChunk

__all__ = ["SCHEMA_VERSION", "Chunk", "Claim", "PolicyChunk", "build_claim", "claim_evidence"]
