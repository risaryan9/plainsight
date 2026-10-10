"""Runs the real pipeline on a real APK. Set TEST_APK_PATH to enable it:

TEST_APK_PATH=~/apks/some-app.apk uv run pytest worker/tests/test_integration.py
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

import pytest

from pipeline.extraction import ExtractionResult, analyze_apk

APK_PATH = os.environ.get("TEST_APK_PATH")

pytestmark = pytest.mark.skipif(not APK_PATH, reason="TEST_APK_PATH is not set")


@pytest.fixture(scope="module")
def output() -> dict[str, Any]:
    assert APK_PATH
    return analyze_apk(os.path.expanduser(APK_PATH))


def test_output_validates_against_the_model(output: dict[str, Any]) -> None:
    result = ExtractionResult.model_validate(output)
    assert result.schema_version == "extraction.v1"
    assert re.fullmatch(r"[a-zA-Z_][\w]*(\.[a-zA-Z_][\w]*)+", result.apk.package_name)
    assert re.fullmatch(r"[0-9a-f]{64}", result.apk.sha256)
    assert result.apk.size_bytes > 0


def test_output_is_json_serialisable(output: dict[str, Any]) -> None:
    assert json.loads(json.dumps(output)) == output


def test_every_referenced_evidence_id_exists(output: dict[str, Any]) -> None:
    result = ExtractionResult.model_validate(output)
    facts = result.facts
    referenced = {
        evidence_id
        for group in (
            facts.permissions,
            facts.capabilities,
            facts.sdks,
            facts.endpoints,
            facts.high_risk_features,
            facts.exported_components,
            facts.secrets,
        )
        for fact in group
        for evidence_id in fact.evidence
    }
    referenced |= {site.evidence for cap in facts.capabilities for site in cap.call_sites}
    assert referenced
    assert referenced <= set(result.evidence)
    assert all(re.fullmatch(r"(man|api|sdk|str|file)_\d{3,}", key) for key in result.evidence)


def test_facts_and_timings_are_present(output: dict[str, Any]) -> None:
    result = ExtractionResult.model_validate(output)
    assert result.facts.permissions
    assert {"MICROPHONE", "CAMERA", "CONTACTS"} <= {c.capability for c in result.facts.capabilities}
    assert len(result.facts.endpoints) <= 50
    assert {"validate", "load", "analyse", "permissions", "api_usage", "strings", "sdks"} <= set(
        result.meta.stage_ms
    )
    assert result.meta.androguard_version


def test_ids_are_stable_across_runs(output: dict[str, Any]) -> None:
    assert APK_PATH
    again = analyze_apk(os.path.expanduser(APK_PATH))
    assert again["evidence"] == output["evidence"]
    assert again["facts"] == output["facts"]
