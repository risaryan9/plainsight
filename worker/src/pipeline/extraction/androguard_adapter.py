"""The only module that imports Androguard (spec §7.7, §20.1 rule 8).

Everything here is a thin wrapper that turns Androguard objects into plain Python data,
so an Androguard upgrade only touches this file. Written against Androguard 4.1.4.

Androguard parses bytes in memory. Nothing from the APK is installed, executed, loaded
or written to disk, and no network calls are made.

The :class:`ApkHandle` keeps the parsed DEX files and the cross-reference index. A later
``get_method_source(handle, method_signature)`` (Androguard's DAD decompiler) can be
added here by attaching ``DecompilerDAD(dex, analysis)`` lazily to the DEX objects the
handle already holds; ``analyze_apk`` does not need to change for that.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any, Literal

import androguard
from androguard.core.analysis.analysis import Analysis
from androguard.core.apk import APK
from androguard.core.dex import DEX
from loguru import logger

from .errors import InvalidApkError

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS: dict[str, str] = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}
PERMISSION_TAGS = ("uses-permission", "uses-permission-sdk-23")
_DEBUG_CERT_MARKER = "Android Debug"
# Dalvik opcodes that read a field: iget* (0x52-0x58) and sget* (0x60-0x66).
_FIELD_READ_OPS = frozenset(range(0x52, 0x59)) | frozenset(range(0x60, 0x67))

_log_state: dict[str, int | None] = {"sink_id": None}


# --------------------------------------------------------------------------- data types


@dataclass(frozen=True, order=True)
class MethodRef:
    """A method, identified the way DEX does: class descriptor, name, descriptor."""

    class_name: str
    name: str
    descriptor: str

    @property
    def signature(self) -> str:
        """``Lcom/foo/Bar;->baz(I)V``: the id a future ``get_method_source`` will take."""
        return f"{self.class_name}->{self.name}{self.descriptor}"


@dataclass(frozen=True, order=True)
class CodeRef:
    """One place in the code (``caller``) that touches ``target``."""

    caller: MethodRef
    target: str
    kind: Literal["method_call", "field_read"]


@dataclass(frozen=True)
class ManifestInfo:
    package_name: str
    app_label: str | None
    version_name: str | None
    version_code: int | None
    min_sdk: int | None
    target_sdk: int | None


@dataclass(frozen=True)
class SigningCert:
    sha256: str
    subject: str
    is_debug: bool


@dataclass(frozen=True)
class DeclaredPermission:
    name: str
    tag: str
    protection: str | None
    max_sdk: int | None


@dataclass(frozen=True)
class Component:
    type: Literal["activity", "service", "receiver", "provider"]
    tag: str
    name: str
    exported: bool
    permission: str | None
    actions: tuple[str, ...]


@dataclass
class ApkHandle:
    """An opened APK. Treat it as opaque outside this module."""

    path: str
    _apk: Any
    _dexes: list[Any] = field(default_factory=list)
    _analysis: Any = None


# ------------------------------------------------------------------------------ logging


def configure_logging(min_level: str = "WARNING") -> None:
    """Drop Androguard log records below ``min_level``.

    Androguard 4 logs through loguru, whose default handler prints everything from DEBUG
    up to stderr. If that default handler is still installed we swap it for one that
    filters Androguard's records. If the host application has already configured loguru
    itself, we leave its handlers alone and switch Androguard's records off instead.
    """
    logging.getLogger("apkInspector").setLevel(min_level)
    threshold = logger.level(min_level).no

    def _keep(record: Any) -> bool:  # noqa: ANN401 - loguru's record type is not importable
        name = record["name"] or ""
        return not name.startswith("androguard") or record["level"].no >= threshold

    previous = _log_state["sink_id"]
    if previous is None:
        try:
            logger.remove(0)
        except ValueError:
            logger.disable("androguard")
            return
    else:
        with suppress(ValueError):
            logger.remove(previous)
    _log_state["sink_id"] = logger.add(sys.stderr, filter=_keep)


def androguard_version() -> str:
    return str(androguard.__version__)


# ------------------------------------------------------------------------------ loading


def open_apk(path: str) -> ApkHandle:
    """Parse the APK container and its manifest. Does not touch the DEX code yet."""
    try:
        apk = APK(path)
    except Exception as exc:
        raise InvalidApkError(
            f"The APK could not be parsed ({type(exc).__name__}: {exc})."
        ) from exc
    if not apk.is_valid_APK() or not apk.get_package():
        raise InvalidApkError("The APK's AndroidManifest.xml could not be parsed.")
    return ApkHandle(path=path, _apk=apk)


def analyse_code(handle: ApkHandle) -> None:
    """Parse every DEX file and build the cross-reference index (the slow step)."""
    if handle._analysis is not None:
        return
    apk = handle._apk
    analysis = Analysis()
    dexes = []
    try:
        for dex_bytes in apk.get_all_dex():
            dex = DEX(dex_bytes, using_api=apk.get_target_sdk_version())
            analysis.add(dex)
            dexes.append(dex)
        analysis.create_xref()
    except Exception as exc:
        raise InvalidApkError(
            f"The APK's code could not be parsed ({type(exc).__name__}: {exc})."
        ) from exc
    handle._dexes = dexes
    handle._analysis = analysis


def _analysis(handle: ApkHandle) -> Any:  # noqa: ANN401 - Androguard is untyped
    if handle._analysis is None:
        raise RuntimeError("analyse_code(handle) must be called first")
    return handle._analysis


# ----------------------------------------------------------------------------- manifest


def _to_int(value: object) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def read_manifest(handle: ApkHandle) -> ManifestInfo:
    apk = handle._apk
    try:
        label: str | None = apk.get_app_name()
    except Exception:
        label = None
    return ManifestInfo(
        package_name=apk.get_package(),
        app_label=label or None,
        version_name=apk.get_androidversion_name() or None,
        version_code=_to_int(apk.get_androidversion_code()),
        min_sdk=_to_int(apk.get_min_sdk_version()),
        target_sdk=_to_int(apk.get_target_sdk_version()),
    )


def read_signing_certs(handle: ApkHandle) -> list[SigningCert]:
    """Unique signing certificates across the v1, v2 and v3 schemes. Empty if unsigned."""
    try:
        certs = handle._apk.get_certificates()
    except Exception:
        return []
    result = []
    for cert in certs:
        subject = cert.subject.human_friendly
        result.append(
            SigningCert(
                sha256=cert.sha256.hex(),
                subject=subject,
                is_debug=_DEBUG_CERT_MARKER in subject,
            )
        )
    return result


def _format_name(package: str, name: str) -> str:
    """Resolve a manifest class name against the package, as Android does."""
    if name.startswith("."):
        return package + name
    if "." not in name:
        return f"{package}.{name}"
    return name


def read_permissions(handle: ApkHandle) -> list[DeclaredPermission]:
    """Every ``<uses-permission>`` (and ``-sdk-23``) entry, sorted and deduplicated."""
    apk = handle._apk
    try:
        details: dict[str, list[str]] = apk.get_details_permissions()
    except Exception:
        details = {}
    root = apk.get_android_manifest_xml()
    seen: dict[str, DeclaredPermission] = {}
    for tag in PERMISSION_TAGS:
        for element in root.iter(tag):
            name = element.get(ANDROID_NS + "name")
            if not name or name in seen:
                continue
            level = details.get(name, [None])[0]
            seen[name] = DeclaredPermission(
                name=name,
                tag=tag,
                protection=level or None,
                max_sdk=_to_int(element.get(ANDROID_NS + "maxSdkVersion")),
            )
    return [seen[name] for name in sorted(seen)]


def read_components(handle: ApkHandle) -> list[Component]:
    """Activities, services, receivers and providers with their effective exported flag."""
    apk = handle._apk
    package = apk.get_package()
    target_sdk = _to_int(apk.get_target_sdk_version()) or 1
    application = apk.get_android_manifest_xml().find("application")
    if application is None:
        return []
    components = []
    for element in application:
        if element.tag not in COMPONENT_TAGS:
            continue
        name = element.get(ANDROID_NS + "name")
        if not name:
            continue
        component_type = COMPONENT_TAGS[element.tag]
        actions = sorted(
            {
                action.get(ANDROID_NS + "name")
                for action in element.iterfind("intent-filter/action")
                if action.get(ANDROID_NS + "name")
            }
        )
        exported_attr = element.get(ANDROID_NS + "exported")
        if exported_attr is not None:
            exported = str(exported_attr).lower() == "true"
        elif component_type == "provider":
            # Providers were exported by default before API 17.
            exported = target_sdk < 17
        else:
            # Without the attribute, a component with an intent filter is exported.
            exported = bool(actions)
        components.append(
            Component(
                type=component_type,  # type: ignore[arg-type]
                tag=element.tag,
                name=_format_name(package, name),
                exported=exported,
                permission=element.get(ANDROID_NS + "permission") or None,
                actions=tuple(actions),
            )
        )
    return sorted(components, key=lambda c: (c.type, c.name, c.tag))


def list_files(handle: ApkHandle) -> list[str]:
    """Names of the files inside the APK (from the ZIP directory; nothing is extracted)."""
    return sorted(handle._apk.get_files())


# --------------------------------------------------------------------------------- code


def _method_ref(method: Any) -> MethodRef:  # noqa: ANN401 - Androguard is untyped
    return MethodRef(
        class_name=str(method.class_name),
        name=str(method.name),
        descriptor=str(method.descriptor).replace(" ", ""),
    )


def internal_class_names(handle: ApkHandle) -> list[str]:
    """Descriptors of the classes defined in the APK's own DEX files."""
    return sorted(str(c.name) for c in _analysis(handle).get_internal_classes())


def _calls_to_class(class_analysis: Any, names: frozenset[str] | None) -> set[CodeRef]:  # noqa: ANN401
    refs: set[CodeRef] = set()
    for method in class_analysis.get_methods():
        if names is not None and method.name not in names:
            continue
        target = _method_ref(method).signature
        for _caller_class, caller, _offset in method.get_xref_from():
            refs.add(CodeRef(caller=_method_ref(caller), target=target, kind="method_call"))
    return refs


def find_method_calls(handle: ApkHandle, class_name: str, names: Iterable[str]) -> list[CodeRef]:
    """Call sites of the named methods of one exact class (framework or bundled)."""
    class_analysis = _analysis(handle).get_class_analysis(class_name)
    if class_analysis is None:
        return []
    return sorted(_calls_to_class(class_analysis, frozenset(names)))


def find_calls_by_class_prefix(handle: ApkHandle, prefix: str) -> list[CodeRef]:
    """Call sites of any method on a class whose descriptor starts with ``prefix``."""
    refs: set[CodeRef] = set()
    for class_analysis in _analysis(handle).get_classes():
        if str(class_analysis.name).startswith(prefix):
            refs |= _calls_to_class(class_analysis, None)
    return sorted(refs)


def find_field_reads(handle: ApkHandle, class_prefixes: Sequence[str]) -> list[CodeRef]:
    """Methods that read a field of a class whose descriptor starts with any prefix.

    Androguard only cross-references fields of classes defined inside the APK, so reads
    of framework constants (``ContactsContract.Contacts.CONTENT_URI``) are not in its
    index. This looks them up in each DEX file's field table and, only if one is present,
    scans the bytecode for the instructions that read it.
    """
    _analysis(handle)
    prefixes = tuple(class_prefixes)
    if not prefixes:
        return []
    refs: set[CodeRef] = set()
    for dex in handle._dexes:
        wanted: dict[int, str] = {}
        for index in range(dex.get_len_fields()):
            class_name, field_type, field_name = dex.get_cm_field(index)
            if str(class_name).startswith(prefixes):
                wanted[index] = f"{class_name}->{field_name}:{field_type}"
        if not wanted:
            continue
        for class_def in dex.get_classes():
            for method in class_def.get_methods():
                for _offset, instruction in method.get_instructions_idx():
                    if instruction.get_op_value() not in _FIELD_READ_OPS:
                        continue
                    target = wanted.get(instruction.get_ref_kind())
                    if target is None:
                        continue
                    caller = MethodRef(
                        class_name=str(method.get_class_name()),
                        name=str(method.get_name()),
                        descriptor=str(method.get_descriptor()).replace(" ", ""),
                    )
                    refs.add(CodeRef(caller=caller, target=target, kind="field_read"))
    return sorted(refs)


def pool_strings(handle: ApkHandle) -> list[str]:
    """Every distinct string in the DEX string pools (includes strings no code loads)."""
    _analysis(handle)
    values: set[str] = set()
    for dex in handle._dexes:
        values.update(str(value) for value in dex.get_strings())
    return sorted(values)


def string_callers(handle: ApkHandle, value: str) -> list[MethodRef]:
    """Methods that load the exact string ``value`` with a const-string instruction."""
    string_analysis = _analysis(handle).get_strings_analysis().get(value)
    if string_analysis is None:
        return []
    return sorted({_method_ref(method) for _class, method in string_analysis.get_xref_from()})


configure_logging()
