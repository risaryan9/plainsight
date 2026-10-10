"""Public entry point of the extraction layer: ``analyze_apk(path) -> dict``.

Static analysis only. The APK is validated, then parsed in memory; it is never installed,
executed or loaded, nothing is written to disk and no network calls are made.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import Counter
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from . import androguard_adapter as adapter
from .api_usage import NO_CODE_REFERENCE, UsageSite, find_capability_usage, find_class_init_sites
from .evidence import EvidenceStore
from .knowledge import Knowledge, load_knowledge
from .models import (
    ApkIdentity,
    CallSite,
    CapabilityFact,
    EndpointFact,
    ExportedComponent,
    ExtractionResult,
    Facts,
    HighRiskFeature,
    Meta,
    PermissionFact,
    SdkFact,
    SecretFact,
)
from .sdks import SdkMatcher
from .strings import MAX_ENDPOINTS, find_endpoints, find_secrets, mask_secret
from .validate import validate_apk

MAX_CALL_SITES = 5
MAX_EVIDENCE_FILES = 5
_HASH_CHUNK_BYTES = 1024 * 1024


class _StageTimer:
    def __init__(self) -> None:
        self.stage_ms: dict[str, int] = {}
        self._start = time.perf_counter()

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = round((time.perf_counter() - start) * 1000)
            self.stage_ms[name] = self.stage_ms.get(name, 0) + elapsed

    def total_ms(self) -> int:
        return round((time.perf_counter() - self._start) * 1000)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


# ------------------------------------------------------------------------------ manifest


def _identity(handle: adapter.ApkHandle, sha256: str, size_bytes: int) -> ApkIdentity:
    manifest = adapter.read_manifest(handle)
    certs = adapter.read_signing_certs(handle)
    return ApkIdentity(
        sha256=sha256,
        size_bytes=size_bytes,
        package_name=manifest.package_name,
        app_label=manifest.app_label,
        version_name=manifest.version_name,
        version_code=manifest.version_code,
        min_sdk=manifest.min_sdk,
        target_sdk=manifest.target_sdk,
        signing_cert_sha256=certs[0].sha256 if certs else None,
        debug_signed=any(cert.is_debug for cert in certs) if certs else None,
    )


def _permission_evidence(store: EvidenceStore, permission: adapter.DeclaredPermission) -> str:
    max_sdk = (
        f' android:maxSdkVersion="{permission.max_sdk}"' if permission.max_sdk is not None else ""
    )
    return store.add(
        "man",
        f"manifest/{permission.tag}[@name='{permission.name}']",
        f'<{permission.tag} android:name="{permission.name}"{max_sdk}/>',
    )


def _component_evidence(store: EvidenceStore, component: adapter.Component) -> str:
    attrs = f'android:name="{component.name}" android:exported="{str(component.exported).lower()}"'
    if component.permission:
        attrs += f' android:permission="{component.permission}"'
    actions = f" actions: {', '.join(component.actions)}" if component.actions else ""
    return store.add(
        "man",
        f"manifest/application/{component.tag}[@name='{component.name}']",
        f"<{component.tag} {attrs}>{actions}",
    )


def _split_protection(raw: str | None) -> tuple[str | None, list[str]]:
    """``"signature|privileged"`` -> ``("signature", ["privileged"])``."""
    if not raw:
        return None, []
    base, *flags = (part.strip() for part in raw.split("|"))
    return base or None, [flag for flag in flags if flag]


# ----------------------------------------------------------------------------- api usage


def _site_evidence(store: EvidenceStore, site: UsageSite) -> str:
    if site.kind == "string":
        where = site.caller if site.caller_class else "the string pool"
        return store.add("str", f'string "{site.target}" in {where}', site.target)
    verb = "calls" if site.kind == "method_call" else "reads"
    return store.add("api", f"{site.caller} {verb} {site.target}", site.target)


def _call_sites(store: EvidenceStore, sites: Sequence[UsageSite]) -> list[CallSite]:
    return [
        CallSite(
            caller=site.caller,
            target=site.target,
            kind=site.kind,
            in_sdk=site.sdk is not None,
            sdk_name=site.sdk.name if site.sdk else None,
            evidence=_site_evidence(store, site),
        )
        for site in sites[:MAX_CALL_SITES]
    ]


def _via_sdk(sites: Sequence[UsageSite]) -> str | None:
    """The SDK's name when every call site sits inside one bundled SDK."""
    code_sites = [site for site in sites if site.caller != NO_CODE_REFERENCE]
    names = {site.sdk.name if site.sdk else None for site in code_sites}
    if len(names) == 1 and None not in names:
        return next(iter(names))
    return None


def _capabilities(
    store: EvidenceStore,
    knowledge: Knowledge,
    permission_ids_by_capability: dict[str, list[str]],
    usage: dict[str, list[UsageSite]],
) -> list[CapabilityFact]:
    requested = set(permission_ids_by_capability)
    facts = []
    for capability in sorted(requested | set(knowledge.sensitive_apis)):
        rule = knowledge.sensitive_apis.get(capability)
        is_requested = capability in requested
        sites = usage.get(capability)
        used = bool(sites) if sites is not None else None
        call_sites = _call_sites(store, sites or [])
        covered = is_requested or (
            rule is not None and any(other in requested for other in rule.satisfied_by)
        )
        facts.append(
            CapabilityFact(
                capability=capability,
                description=rule.description if rule else None,
                requested=is_requested,
                used=used,
                requested_unused=is_requested and used is False,
                used_unrequested=bool(used) and not covered,
                via_sdk=_via_sdk(sites or []) if used else None,
                call_site_count=len(sites or []),
                call_sites=call_sites,
                evidence=[
                    *permission_ids_by_capability.get(capability, []),
                    *(site.evidence for site in call_sites),
                ],
            )
        )
    return facts


# --------------------------------------------------------------------- high-risk features


def _high_risk_features(
    store: EvidenceStore,
    knowledge: Knowledge,
    handle: adapter.ApkHandle,
    matcher: SdkMatcher,
    permissions: Sequence[adapter.DeclaredPermission],
    components: Sequence[adapter.Component],
) -> list[HighRiskFeature]:
    permissions_by_name = {p.name: p for p in permissions}
    files = adapter.list_files(handle)
    features = []
    for name, rule in knowledge.high_risk_features.items():
        evidence: list[str] = []
        for permission_name in rule.permissions:
            if permission_name in permissions_by_name:
                evidence.append(_permission_evidence(store, permissions_by_name[permission_name]))
        if rule.component is not None:
            for component in components:
                if component.type != rule.component.type:
                    continue
                if (
                    set(component.actions) & set(rule.component.actions)
                    or component.permission in rule.component.permissions
                ):
                    evidence.append(_component_evidence(store, component))
        if rule.class_init:
            sites = find_class_init_sites(handle, rule.class_init, matcher)
            evidence.extend(_site_evidence(store, site) for site in sites[:MAX_CALL_SITES])
        if rule.file_pattern:
            pattern = re.compile(rule.file_pattern)
            matches = [file_name for file_name in files if pattern.search(file_name)]
            for file_name in matches[:MAX_EVIDENCE_FILES]:
                more = len(matches) - MAX_EVIDENCE_FILES
                suffix = f" (+{more} more)" if more > 0 and file_name == matches[0] else ""
                evidence.append(store.add("file", f"apk file {file_name}", file_name + suffix))
        if evidence:
            features.append(
                HighRiskFeature(
                    feature=name,
                    description=rule.description,
                    evidence=list(dict.fromkeys(evidence)),
                )
            )
    return sorted(features, key=lambda f: f.feature)


# -------------------------------------------------------------------------------- strings


def _string_location(handle: adapter.ApkHandle, source: str, shown: str) -> str:
    callers = adapter.string_callers(handle, source)
    where = callers[0].signature if callers else "the string pool"
    more = f" (+{len(callers) - 1} more)" if len(callers) > 1 else ""
    return f'string "{shown}" in {where}{more}'


def _endpoints(
    store: EvidenceStore, handle: adapter.ApkHandle, pool: Sequence[str]
) -> tuple[list[EndpointFact], int]:
    sources = find_endpoints(pool)
    ordered = sorted(sources, key=lambda e: (e.kind, e.value))
    facts = [
        EndpointFact(
            value=endpoint.value,
            kind=endpoint.kind,
            evidence=[
                store.add(
                    "str",
                    _string_location(handle, sources[endpoint], endpoint.value),
                    sources[endpoint],
                )
            ],
        )
        for endpoint in ordered[:MAX_ENDPOINTS]
    ]
    return facts, len(ordered)


def _secrets(
    store: EvidenceStore, handle: adapter.ApkHandle, pool: Sequence[str]
) -> list[SecretFact]:
    seen: set[tuple[str, str]] = set()
    facts = []
    for source in pool:
        for hit in find_secrets(source):
            if (hit.kind, hit.value) in seen:
                continue
            seen.add((hit.kind, hit.value))
            masked = mask_secret(hit.value)
            # The evidence store masks secrets again, so the raw source is safe to pass.
            evidence_id = store.add("str", _string_location(handle, source, masked), source)
            facts.append(SecretFact(kind=hit.kind, masked=masked, evidence=[evidence_id]))
    return facts


# ----------------------------------------------------------------------------- pipeline


def extract(path: str) -> ExtractionResult:
    """Run the extraction pipeline and return the typed result.

    Raises :class:`~pipeline.extraction.errors.InvalidApkError` if the file fails
    validation or cannot be parsed.
    """
    timer = _StageTimer()
    knowledge = load_knowledge()
    store = EvidenceStore()
    matcher = SdkMatcher(knowledge.sdk_signatures)

    with timer.stage("validate"):
        validated = validate_apk(path)
    with timer.stage("hash"):
        sha256 = _sha256_file(path)
    with timer.stage("load"):
        handle = adapter.open_apk(path)
    with timer.stage("analyse"):
        adapter.analyse_code(handle)

    with timer.stage("permissions"):
        identity = _identity(handle, sha256, validated.size_bytes)
        declared = adapter.read_permissions(handle)
        components = adapter.read_components(handle)
        permission_ids = {p.name: _permission_evidence(store, p) for p in declared}
        ids_by_capability: dict[str, list[str]] = {}
        for permission in declared:
            capability = knowledge.permission_map.get(permission.name)
            if capability:
                ids_by_capability.setdefault(capability, []).append(permission_ids[permission.name])
        exported = [
            ExportedComponent(
                type=component.type,
                name=component.name,
                intent_filters=list(component.actions),
                permission=component.permission,
                evidence=[_component_evidence(store, component)],
            )
            for component in components
            if component.exported
        ]

    with timer.stage("sdks"):
        class_names = adapter.internal_class_names(handle)
        sdks = [
            SdkFact(
                name=detection.signature.name,
                category=detection.signature.category,
                class_count=detection.class_count,
                evidence=[
                    store.add(
                        "sdk",
                        f"package prefix {detection.signature.prefix}",
                        f"{detection.class_count} classes, e.g. {detection.example_class}",
                    )
                ],
            )
            for detection in matcher.detect(class_names)
        ]

    with timer.stage("strings"):
        pool = adapter.pool_strings(handle)

    with timer.stage("api_usage"):
        usage = find_capability_usage(handle, knowledge.sensitive_apis, matcher, pool)
        capabilities = _capabilities(store, knowledge, ids_by_capability, usage)
        capability_by_name = {fact.capability: fact for fact in capabilities}
        high_risk = _high_risk_features(store, knowledge, handle, matcher, declared, components)

    permissions = []
    for permission in declared:
        protection, flags = _split_protection(permission.protection)
        capability = knowledge.permission_map.get(permission.name)
        capability_fact = capability_by_name.get(capability) if capability else None
        permissions.append(
            PermissionFact(
                name=permission.name,
                protection=protection,
                protection_flags=flags,
                capability=capability,
                used=capability_fact.used if capability_fact else None,
                max_sdk=permission.max_sdk,
                evidence=[
                    permission_ids[permission.name],
                    *(
                        site.evidence
                        for site in (capability_fact.call_sites if capability_fact else [])
                    ),
                ],
            )
        )

    with timer.stage("strings"):
        endpoints, endpoints_total = _endpoints(store, handle, pool)
        secrets = _secrets(store, handle, pool)

    protections = Counter(p.protection for p in permissions)
    return ExtractionResult(
        apk=identity,
        facts=Facts(
            permissions=permissions,
            capabilities=capabilities,
            sdks=sdks,
            endpoints=endpoints,
            high_risk_features=high_risk,
            exported_components=exported,
            secrets=secrets,
        ),
        evidence=store.items(),
        meta=Meta(
            androguard_version=adapter.androguard_version(),
            duration_ms=timer.total_ms(),
            stage_ms=timer.stage_ms,
            counts={
                "permissions": len(permissions),
                "dangerous_permissions": protections.get("dangerous", 0),
                "components": len(components),
                "exported_components": len(exported),
                "classes": len(class_names),
                "strings": len(pool),
                "endpoints_total": endpoints_total,
                "zip_entries": validated.entry_count,
            },
        ),
    )


def analyze_apk(path: str) -> dict[str, Any]:
    """Statically analyse the APK at ``path`` and return a JSON-serialisable dict.

    The dict validates against :class:`~pipeline.extraction.models.ExtractionResult`.
    Raises :class:`~pipeline.extraction.errors.InvalidApkError` for anything that is not
    a sane APK.
    """
    return extract(path).model_dump(mode="json")
