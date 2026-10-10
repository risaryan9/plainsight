"""Response models of the API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class CapabilitySummary(BaseModel):
    capability: str
    requested: bool
    # None when the extractor has no API rules for the capability (usage unknown).
    used: bool | None


class ScanSummary(BaseModel):
    package: str
    label: str | None
    permission_count: int
    dangerous_permissions: list[str]
    capabilities: list[CapabilitySummary]
    # The uploader's own note, echoed back. It is per request and never stored in the report.
    caption: str | None = None


class ScanResponse(BaseModel):
    sha256: str
    cached: bool
    pipeline_version: str
    report_path: str
    summary: ScanSummary


def summarise(report: dict[str, Any], caption: str | None = None) -> ScanSummary:
    """Build the short summary from a stored extraction report, plus this request's caption."""
    apk = report["apk"]
    facts = report["facts"]
    permissions = facts["permissions"]
    return ScanSummary(
        package=apk["package_name"],
        label=apk.get("app_label"),
        permission_count=len(permissions),
        dangerous_permissions=[
            p["name"] for p in permissions if p.get("protection") == "dangerous"
        ],
        capabilities=[
            CapabilitySummary(
                capability=c["capability"], requested=c["requested"], used=c.get("used")
            )
            for c in facts["capabilities"]
        ],
        caption=caption,
    )
