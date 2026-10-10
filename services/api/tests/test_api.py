from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from api.settings import Settings, get_settings
from pipeline.claim import claim as claim_module
from pipeline.claim.models import PlayListing, PlayLookup, PolicyChunk, PolicyResult
from pipeline.extraction import InvalidApkError


def make_apk(extra: bytes = b"") -> bytes:
    """A ZIP that passes validation (the analysis itself is stubbed in these tests)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"manifest" + extra)
        zf.writestr("classes.dex", b"dex")
    return buffer.getvalue()


def fake_report(package: str = "com.example.app") -> dict[str, Any]:
    return {
        "schema_version": "extraction.v1",
        "apk": {"package_name": package, "app_label": "Example"},
        "evidence": {"man_001": {"kind": "manifest", "location": "manifest", "snippet": "x"}},
        "meta": {"duration_ms": 10, "stage_ms": {"analyse": 9}},
        "facts": {
            "permissions": [
                {"name": "android.permission.CAMERA", "protection": "dangerous"},
                {"name": "android.permission.INTERNET", "protection": "normal"},
            ],
            "capabilities": [
                {"capability": "CAMERA", "requested": True, "used": False},
                {"capability": "STORAGE", "requested": False, "used": None},
            ],
        },
    }


class Analyzer:
    """Stands in for analyze_apk and records how it was called."""

    def __init__(self) -> None:
        self.paths: list[Path] = []
        self.error: Exception | None = None

    def __call__(self, path: str) -> dict[str, Any]:
        self.paths.append(Path(path))
        assert Path(path).is_file()
        if self.error:
            raise self.error
        return fake_report()


class Play:
    """Stands in for the Play Store lookup and the policy fetch (no network in tests)."""

    def __init__(self) -> None:
        self.on_play = False
        self.lookups: list[str] = []

    def fetch_listing(self, package_name: str) -> PlayLookup:
        self.lookups.append(package_name)
        if not self.on_play:
            return PlayLookup(status="not_found", note="No Play Store listing.")
        return PlayLookup(
            status="found",
            listing=PlayListing(
                title="Example",
                category="Tools",
                privacy_policy_url="https://example.test/privacy",
                url=f"https://play.google.com/store/apps/details?id={package_name}",
            ),
        )

    def fetch_policy(self, url: str | None) -> PolicyResult:
        return PolicyResult(
            status="fetched",
            url=url,
            final_url=url,
            chunks=[PolicyChunk(id="pol_001", text="We collect your email address.")],
        )


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        reports_dir=tmp_path / "reports",
        claims_dir=tmp_path / "claims",
        scan_lock_timeout_s=0.05,
    )


@pytest.fixture(autouse=True)
def play(monkeypatch: pytest.MonkeyPatch) -> Play:
    fake = Play()
    monkeypatch.setattr(claim_module, "fetch_listing", fake.fetch_listing)
    monkeypatch.setattr(claim_module, "fetch_policy", fake.fetch_policy)
    return fake


@pytest.fixture
def analyzer(monkeypatch: pytest.MonkeyPatch) -> Analyzer:
    stub = Analyzer()
    monkeypatch.setattr(api_main, "analyze_apk", stub)
    return stub


@pytest.fixture
def client(settings: Settings, analyzer: Analyzer) -> Iterator[TestClient]:
    api_main.app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(api_main.app) as test_client:
        yield test_client
    api_main.app.dependency_overrides.clear()


def upload(client: TestClient, data: bytes, caption: str | None = None) -> Any:  # noqa: ANN401
    return client.post(
        "/scan",
        files={"file": ("app.apk", data, "application/octet-stream")},
        data={"caption": caption} if caption is not None else None,
    )


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"ok": True}


def test_scan_runs_the_analysis_and_saves_the_report(
    client: TestClient, analyzer: Analyzer, settings: Settings
) -> None:
    data = make_apk()
    sha256 = hashlib.sha256(data).hexdigest()

    response = upload(client, data)

    assert response.status_code == 200
    body = response.json()
    report_path = settings.reports_dir / f"{sha256}__dev-0.json"
    assert body["sha256"] == sha256
    assert body["cached"] is False
    assert body["pipeline_version"] == "dev-0"
    assert body["report_path"] == str(report_path)
    assert body["summary"] == {
        "package": "com.example.app",
        "label": "Example",
        "permission_count": 2,
        "dangerous_permissions": ["android.permission.CAMERA"],
        "capabilities": [
            {"capability": "CAMERA", "requested": True, "used": False},
            {"capability": "STORAGE", "requested": False, "used": None},
        ],
    }
    assert body["claim"]["source"] == "app_label"
    assert body["claim"]["flags"] == ["claim_not_on_play", "claim_no_policy"]
    assert json.loads(report_path.read_text()) == fake_report()


def test_second_scan_of_the_same_file_is_served_from_the_cache(
    client: TestClient, analyzer: Analyzer
) -> None:
    data = make_apk()
    first = upload(client, data).json()
    second = upload(client, data).json()

    assert len(analyzer.paths) == 1
    assert second["cached"] is True
    assert second["claim"]["from_cache"] is True
    for body in (first, second):
        del body["cached"], body["claim"]["from_cache"]
    assert second == first


def test_the_caption_goes_into_the_claim_but_never_into_the_shared_caches(
    client: TestClient, analyzer: Analyzer, settings: Settings
) -> None:
    data = make_apk()
    sha256 = hashlib.sha256(data).hexdigest()

    first = upload(client, data, caption="  my cousin sent this as a wedding invite ").json()
    cached_other = upload(client, data, caption="from a different user").json()
    cached_none = upload(client, data, caption="   ").json()

    assert first["claim"]["source"] == "caption"
    assert first["claim"]["caption"] == "my cousin sent this as a wedding invite"
    assert "lst_002" in first["claim"]["evidence"]
    # The extraction is cached per APK; the claim is rebuilt for each request's caption.
    assert len(analyzer.paths) == 1
    assert cached_other["cached"] is True
    assert cached_other["claim"]["caption"] == "from a different user"
    assert cached_none["claim"]["caption"] is None
    assert cached_none["claim"]["source"] == "app_label"

    # Neither cache that is shared between senders holds a caption.
    extraction_file = settings.reports_dir / f"{sha256}__dev-0.json"
    (claim_file,) = settings.claims_dir.glob("*.json")
    assert claim_file.name == "com.example.app.json"
    for shared in (extraction_file, claim_file):
        assert "wedding" not in shared.read_text() and "different user" not in shared.read_text()
    # ...and the report served by hash is the extraction only.
    assert client.get(f"/reports/{sha256}").json() == fake_report()


def test_the_combined_report_is_saved_but_not_served(
    client: TestClient, play: Play, settings: Settings
) -> None:
    play.on_play = True
    data = make_apk()
    sha256 = hashlib.sha256(data).hexdigest()

    body = upload(client, data, caption="a note").json()

    assert body["claim"]["source"] == "play_store"
    assert body["claim"]["category"] == "Tools"
    assert body["claim"]["policy_status"] == "fetched"
    assert [chunk["id"] for chunk in body["claim"]["policy_chunks"]] == ["pol_001"]
    assert play.lookups == ["com.example.app"], "looked up by the manifest's package name"

    combined = json.loads((settings.reports_dir / f"{sha256}__dev-0.combined.json").read_text())
    assert list(combined) == ["schema_version", "apk", "facts", "claim", "evidence", "meta"]
    assert combined["schema_version"] == "pipeline.v1"
    assert combined["claim"] == body["claim"]
    assert set(combined["evidence"]) == {"man_001", "lst_001", "lst_002", "pol_001"}
    assert "claim" in combined["meta"]["stage_ms"]
    # It holds the sender's caption, so no URL reaches it.
    for name in (f"{sha256}.combined", f"{sha256}__dev-0.combined.json", f"{sha256}.combined.json"):
        assert client.get(f"/reports/{name}").status_code == 404


def test_an_overlong_caption_is_rejected(client: TestClient, analyzer: Analyzer) -> None:
    assert upload(client, make_apk(), caption="x" * 5000).status_code == 422
    assert analyzer.paths == []


def test_a_new_pipeline_version_rescans(
    client: TestClient, analyzer: Analyzer, settings: Settings
) -> None:
    data = make_apk()
    upload(client, data)
    newer = settings.model_copy(update={"pipeline_version": "dev-1"})
    api_main.app.dependency_overrides[get_settings] = lambda: newer

    body = upload(client, data).json()

    assert len(analyzer.paths) == 2
    assert body["cached"] is False
    assert body["pipeline_version"] == "dev-1"
    assert body["report_path"].endswith("__dev-1.json")


def test_the_temp_apk_is_deleted_after_a_scan(client: TestClient, analyzer: Analyzer) -> None:
    upload(client, make_apk())
    assert analyzer.paths and not analyzer.paths[0].exists()


def test_the_temp_apk_is_deleted_when_the_analysis_fails(
    client: TestClient, analyzer: Analyzer, settings: Settings
) -> None:
    analyzer.error = InvalidApkError("The APK's code could not be parsed.")

    response = upload(client, make_apk())

    assert response.status_code == 400
    assert response.json()["detail"] == "The APK's code could not be parsed."
    assert not analyzer.paths[0].exists()
    assert not list(settings.reports_dir.glob("*")) if settings.reports_dir.exists() else True


def test_a_file_that_is_not_an_apk_is_rejected(client: TestClient, analyzer: Analyzer) -> None:
    response = upload(client, b"this is not a zip file")

    assert response.status_code == 400
    assert "ZIP signature" in response.json()["detail"]
    assert analyzer.paths == []


def test_an_oversized_upload_is_rejected(
    client: TestClient, analyzer: Analyzer, settings: Settings
) -> None:
    tiny = settings.model_copy(update={"max_upload_mb": 1})
    api_main.app.dependency_overrides[get_settings] = lambda: tiny

    response = upload(client, make_apk(extra=b"\x00") + b"\x00" * (2 * 1024 * 1024))

    assert response.status_code == 413
    assert analyzer.paths == []


def test_scan_returns_503_while_another_scan_holds_the_lock(
    client: TestClient, analyzer: Analyzer
) -> None:
    assert api_main._scan_lock.acquire(blocking=False)
    try:
        response = upload(client, make_apk())
    finally:
        api_main._scan_lock.release()

    assert response.status_code == 503
    assert response.json()["detail"] == "Another scan is running, please try again in a minute"
    assert response.headers["retry-after"] == "60"
    assert analyzer.paths == []
    # The lock is free again afterwards.
    assert upload(client, make_apk()).status_code == 200


def test_cached_reports_are_served_even_while_a_scan_is_running(client: TestClient) -> None:
    data = make_apk()
    upload(client, data)
    assert api_main._scan_lock.acquire(blocking=False)
    try:
        response = upload(client, data)
    finally:
        api_main._scan_lock.release()
    assert response.status_code == 200 and response.json()["cached"] is True


def test_get_report_returns_the_stored_json(client: TestClient) -> None:
    sha256 = upload(client, make_apk()).json()["sha256"]

    response = client.get(f"/reports/{sha256}")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == fake_report()


@pytest.mark.parametrize("sha256", ["0" * 64, "not-a-hash", "..%2F..%2Fetc%2Fpasswd"])
def test_get_report_404s_for_unknown_or_malformed_hashes(client: TestClient, sha256: str) -> None:
    assert client.get(f"/reports/{sha256}").status_code == 404


def test_pipeline_version_cannot_contain_path_characters() -> None:
    with pytest.raises(ValueError):
        Settings(_env_file=None, pipeline_version="../evil")
