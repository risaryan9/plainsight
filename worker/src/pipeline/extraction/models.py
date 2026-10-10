"""Pydantic models for the extraction output (``extraction.v1``).

The ``apk``, ``facts`` and ``evidence`` parts follow report.v1 (spec §8.4). ``facts`` is a
superset: capabilities carry call sites and the requested/used flags, and high-risk
features carry evidence.

# DEV-ONLY (D-015): these models move to ``packages/shared`` with the rest of the contracts
# when report.v1 is frozen.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "extraction.v1"

EvidenceKind = Literal[
    # Extraction (this package).
    "manifest",
    "api_call",
    "sdk",
    "string",
    "file",
    # Claim side (pipeline.claim).
    "listing",
    "caption",
    "policy",
    "claim",
]
ComponentType = Literal["activity", "service", "receiver", "provider"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ApkIdentity(_Model):
    sha256: str
    size_bytes: int
    package_name: str
    app_label: str | None = None
    version_name: str | None = None
    version_code: int | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    signing_cert_sha256: str | None = None
    # None when the APK carries no readable signing certificate.
    debug_signed: bool | None = None


class PermissionFact(_Model):
    name: str
    # Base protection level (normal / dangerous / signature / ...). None when Androguard
    # does not know the permission (non-AOSP permissions that the app does not define).
    protection: str | None = None
    protection_flags: list[str] = Field(default_factory=list)
    capability: str | None = None
    # None when no API rules exist for the capability, so usage is unknown.
    used: bool | None = None
    max_sdk: int | None = None
    evidence: list[str] = Field(default_factory=list)


class CallSite(_Model):
    caller: str
    target: str
    kind: Literal["method_call", "field_read", "string"]
    in_sdk: bool
    sdk_name: str | None = None
    evidence: str


class CapabilityFact(_Model):
    capability: str
    description: str | None = None
    requested: bool
    # None when no API rules exist for the capability, so usage is unknown.
    used: bool | None = None
    requested_unused: bool = False
    used_unrequested: bool = False
    # Set when every call site is inside one bundled SDK.
    via_sdk: str | None = None
    call_site_count: int = 0
    call_sites: list[CallSite] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class SdkFact(_Model):
    name: str
    category: str
    class_count: int
    evidence: list[str] = Field(default_factory=list)


class EndpointFact(_Model):
    value: str
    kind: Literal["url", "ip"]
    evidence: list[str] = Field(default_factory=list)


class HighRiskFeature(_Model):
    feature: str
    description: str | None = None
    evidence: list[str] = Field(default_factory=list)


class ExportedComponent(_Model):
    type: ComponentType
    name: str
    intent_filters: list[str] = Field(default_factory=list)
    permission: str | None = None
    evidence: list[str] = Field(default_factory=list)


class SecretFact(_Model):
    kind: str
    # Never the real value: first 4 characters + "…" + "(length)".
    masked: str
    evidence: list[str] = Field(default_factory=list)


class Facts(_Model):
    permissions: list[PermissionFact] = Field(default_factory=list)
    capabilities: list[CapabilityFact] = Field(default_factory=list)
    sdks: list[SdkFact] = Field(default_factory=list)
    endpoints: list[EndpointFact] = Field(default_factory=list)
    high_risk_features: list[HighRiskFeature] = Field(default_factory=list)
    exported_components: list[ExportedComponent] = Field(default_factory=list)
    secrets: list[SecretFact] = Field(default_factory=list)


class EvidenceItem(_Model):
    kind: EvidenceKind
    location: str
    snippet: str


class Meta(_Model):
    androguard_version: str
    duration_ms: int
    stage_ms: dict[str, int] = Field(default_factory=dict)
    # Totals before any cap was applied (e.g. endpoints_total vs the 50 that are listed).
    counts: dict[str, int] = Field(default_factory=dict)


class ExtractionResult(_Model):
    schema_version: Literal["extraction.v1"] = "extraction.v1"
    apk: ApkIdentity
    facts: Facts
    evidence: dict[str, EvidenceItem] = Field(default_factory=dict)
    meta: Meta
