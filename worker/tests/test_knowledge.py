from __future__ import annotations

from pipeline.extraction.evidence import EvidenceStore
from pipeline.extraction.knowledge import load_knowledge
from pipeline.extraction.sdks import SdkMatcher, descriptor_to_dotted


def test_data_files_load_and_validate() -> None:
    knowledge = load_knowledge()
    assert knowledge.permission_map["android.permission.RECORD_AUDIO"] == "MICROPHONE"
    assert knowledge.permission_map["android.permission.ACCESS_FINE_LOCATION"] == "PRECISE_LOCATION"
    assert {"MICROPHONE", "CAMERA", "PRECISE_LOCATION", "CONTACTS", "SMS_SEND"} <= set(
        knowledge.sensitive_apis
    )
    assert "dynamic_code_loading" in knowledge.high_risk_features
    assert len(knowledge.sdk_signatures) >= 10


def test_every_api_capability_has_a_permission() -> None:
    knowledge = load_knowledge()
    assert set(knowledge.sensitive_apis) <= set(knowledge.permission_map.values())


def test_descriptor_to_dotted() -> None:
    assert descriptor_to_dotted("Lcom/foo/Bar$Baz;") == "com.foo.Bar$Baz"


def test_sdk_matcher_matches_whole_package_segments() -> None:
    matcher = SdkMatcher(load_knowledge().sdk_signatures)
    ads = matcher.match("Lcom/google/android/gms/ads/AdView;")
    assert ads is not None and ads.name == "Google Mobile Ads"
    assert matcher.match("Lcom/appsflyerx/Thing;") is None
    assert matcher.match("Lcom/example/app/MainActivity;") is None


def test_sdk_detection_groups_and_counts_classes() -> None:
    matcher = SdkMatcher(load_knowledge().sdk_signatures)
    detections = matcher.detect(
        ["Lcom/adjust/sdk/Adjust;", "Lcom/adjust/sdk/a/B;", "Lcom/example/Main;"]
    )
    assert [(d.signature.name, d.class_count) for d in detections] == [("Adjust", 2)]
    assert detections[0].example_class == "com.adjust.sdk.Adjust"


def test_evidence_ids_are_sequential_per_prefix_and_deduplicated() -> None:
    store = EvidenceStore()
    first = store.add("man", "manifest/uses-permission[@name='a']", "<uses-permission/>")
    second = store.add("api", "La;->b()V calls Lc;->d()V", "Lc;->d()V")
    again = store.add("man", "manifest/uses-permission[@name='a']", "<uses-permission/>")
    third = store.add("man", "manifest/uses-permission[@name='b']", "<uses-permission/>")
    assert (first, second, again, third) == ("man_001", "api_001", "man_001", "man_002")
    assert store.items()["api_001"].kind == "api_call"


def test_evidence_masks_secrets_and_clips_long_text() -> None:
    key = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
    store = EvidenceStore()
    evidence_id = store.add("str", f'string "{key}" in La;->b()V', key + "x" * 500)
    item = store.items()[evidence_id]
    assert key not in item.location and key not in item.snippet
    assert len(item.snippet) <= 200
