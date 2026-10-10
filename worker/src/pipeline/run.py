"""The pipeline: extraction → claim (more stages follow, spec §7.6).

    from pipeline.run import run_pipeline

    report = run_pipeline("/path/to/app.apk", caption="sent by my bank")

No Lambda-specific logic belongs here (spec §20.1 rule 9).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from .claim import build_claim, claim_evidence
from .extraction import analyze_apk

SCHEMA_VERSION = "pipeline.v1"


def run_pipeline(
    apk_path: str | Path,
    caption: str | None = None,
    *,
    extraction: dict[str, Any] | None = None,
    claims_dir: Path | None = None,
) -> dict[str, Any]:
    """Analyse an APK and build its claim. Returns a JSON-serialisable dict:

    ``{schema_version, apk, facts, claim, evidence, meta}``

    ``extraction`` is an earlier ``analyze_apk`` result for this APK. Pass it to skip the
    expensive extraction stage: extraction depends only on the APK, the claim also depends
    on the caption, so only extraction is cached per APK (decision D-028).

    Raises :class:`~pipeline.extraction.InvalidApkError` if the APK cannot be analysed.
    The claim stage never raises.
    """
    if extraction is None:
        extraction = analyze_apk(str(apk_path))
    apk = extraction["apk"]

    started = time.perf_counter()
    claim = build_claim(apk["package_name"], apk.get("app_label"), caption, cache_dir=claims_dir)
    claim_ms = round((time.perf_counter() - started) * 1000)

    meta = dict(extraction.get("meta", {}))
    meta["stage_ms"] = {**meta.get("stage_ms", {}), "claim": claim_ms}
    meta["duration_ms"] = meta.get("duration_ms", 0) + claim_ms

    return {
        "schema_version": SCHEMA_VERSION,
        "apk": apk,
        "facts": extraction["facts"],
        "claim": claim.model_dump(mode="json"),
        "evidence": {
            **extraction.get("evidence", {}),
            **{key: item.model_dump(mode="json") for key, item in claim_evidence(claim).items()},
        },
        "meta": meta,
    }
