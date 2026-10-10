from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from pipeline import run as run_module
from pipeline.claim import Claim, build_claim
from pipeline.run import run_pipeline

EXTRACTION: dict[str, Any] = {
    "schema_version": "extraction.v1",
    "apk": {"sha256": "ab" * 32, "package_name": "com.example.app", "app_label": "Example"},
    "facts": {"permissions": [], "capabilities": []},
    "evidence": {"man_001": {"kind": "manifest", "location": "manifest", "snippet": "x"}},
    "meta": {"androguard_version": "4.1.4", "duration_ms": 7000, "stage_ms": {"analyse": 6500}},
}


@pytest.fixture
def claims(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    def fake_build_claim(
        package_name: str, app_label: str | None, caption: str | None, *, cache_dir: Path | None
    ) -> Claim:
        calls.append((package_name, app_label, caption, cache_dir))
        return Claim(
            source="caption" if caption else "app_label",
            package_name=package_name,
            app_label=app_label,
            caption=caption,
            play_lookup="not_found",
            policy_status="no_url",
            flags=["claim_not_on_play"],
            evidence=(["lst_002"] if caption else []) + ["claim_not_on_play"],
        )

    monkeypatch.setattr(run_module, "build_claim", fake_build_claim)
    return calls


def test_run_pipeline_combines_extraction_and_claim(
    claims: list[tuple[Any, ...]], tmp_path: Path
) -> None:
    report = run_pipeline(
        "unused.apk", "from my cousin", extraction=EXTRACTION, claims_dir=tmp_path
    )

    assert list(report) == ["schema_version", "apk", "facts", "claim", "evidence", "meta"]
    assert report["schema_version"] == "pipeline.v1"
    assert report["apk"] == EXTRACTION["apk"] and report["facts"] == EXTRACTION["facts"]
    assert report["claim"]["source"] == "caption"
    assert report["claim"]["caption"] == "from my cousin"
    # The package name and label come from the manifest, not from the file name.
    assert claims == [("com.example.app", "Example", "from my cousin", tmp_path)]
    # Extraction and claim evidence share one map, and every cited id is in it.
    assert set(report["evidence"]) == {"man_001", "lst_002", "claim_not_on_play"}
    assert set(report["claim"]["evidence"]) <= set(report["evidence"])
    assert report["meta"]["stage_ms"]["analyse"] == 6500
    assert report["meta"]["stage_ms"]["claim"] >= 0
    assert report["meta"]["duration_ms"] == 7000 + report["meta"]["stage_ms"]["claim"]
    # The cached extraction that was passed in is not modified.
    assert "claim" not in EXTRACTION["meta"]["stage_ms"] and "lst_002" not in EXTRACTION["evidence"]


def test_run_pipeline_runs_the_extraction_when_none_is_given(
    claims: list[tuple[Any, ...]], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def fake_analyze(path: str) -> dict[str, Any]:
        seen.append(path)
        return EXTRACTION

    monkeypatch.setattr(run_module, "analyze_apk", fake_analyze)

    report = run_pipeline(Path("/tmp/some.apk"))

    assert seen == ["/tmp/some.apk"]
    assert report["claim"]["source"] == "app_label" and report["claim"]["caption"] is None


@pytest.mark.skipif(os.environ.get("RUN_LIVE_TESTS") != "1", reason="set RUN_LIVE_TESTS=1")
def test_live_lookup_of_a_well_known_package(tmp_path: Path) -> None:
    """Talks to the real Play Store and the real policy site."""
    claim = build_claim("com.whatsapp", "WhatsApp", cache_dir=tmp_path)

    assert claim.source == "play_store", claim.notes
    assert claim.title and "whatsapp" in claim.title.lower()
    assert claim.category == "Communication"
    assert claim.policy_status == "fetched", claim.notes
    assert len(claim.policy_chunks) > 20
    assert "claim_possible_impersonation" not in claim.flags
    assert (tmp_path / "com.whatsapp.json").is_file()
