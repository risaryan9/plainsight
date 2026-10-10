"""Command line entry point.

uv run python -m pipeline.extraction.cli path/to/app.apk [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .errors import InvalidApkError
from .models import CapabilityFact, ExtractionResult

MAX_URLS_SHOWN = 10
# Rows of the requested/used table: label -> capabilities folded into the row.
USAGE_TABLE: dict[str, tuple[str, ...]] = {
    "MICROPHONE": ("MICROPHONE",),
    "CAMERA": ("CAMERA",),
    "LOCATION": ("PRECISE_LOCATION", "APPROX_LOCATION", "BACKGROUND_LOCATION"),
    "CONTACTS": ("CONTACTS",),
    "SMS": ("SMS_READ", "SMS_SEND"),
}


def _yes_no(value: bool | None) -> str:
    return "?" if value is None else ("yes" if value else "no")


def _usage_row(label: str, facts: Sequence[CapabilityFact]) -> str:
    requested = any(fact.requested for fact in facts)
    known = [fact.used for fact in facts if fact.used is not None]
    used = any(known) if known else None
    sites = [site for fact in facts for site in fact.call_sites]
    notes = []
    if any(fact.requested_unused for fact in facts) and not used:
        notes.append("requested but unused")
    if any(fact.used_unrequested for fact in facts):
        notes.append("USED BUT NOT REQUESTED")
    via = sorted({fact.via_sdk for fact in facts if fact.via_sdk})
    if via:
        notes.append("only via " + ", ".join(via))
    if sites:
        notes.append(f"e.g. {sites[0].caller}")
    row = f"  {label:<11}{_yes_no(requested):<11}{_yes_no(used):<6}"
    row += f"{sum(fact.call_site_count for fact in facts):<7}"
    return row + "; ".join(notes)


def format_summary(result: ExtractionResult) -> str:
    """Short human-readable summary of an extraction result."""
    apk, facts, meta = result.apk, result.facts, result.meta
    lines = [
        f"{apk.package_name}  ({apk.app_label or 'no label'})",
        f"  version {apk.version_name} ({apk.version_code})  "
        f"minSdk {apk.min_sdk}  targetSdk {apk.target_sdk}  {apk.size_bytes / 1_048_576:.1f} MB",
        f"  sha256  {apk.sha256}",
        f"  signer  {apk.signing_cert_sha256 or 'none found'}"
        + ("  [DEBUG-SIGNED]" if apk.debug_signed else ""),
        "",
    ]

    dangerous = [p for p in facts.permissions if p.protection == "dangerous"]
    lines.append(f"Permissions: {len(facts.permissions)} declared, {len(dangerous)} dangerous")
    for permission in dangerous:
        capability = f"  -> {permission.capability}" if permission.capability else ""
        lines.append(f"  {permission.name}{capability}")

    lines += ["", "Requested vs used:", "  capability requested  used  sites  notes"]
    by_name = {fact.capability: fact for fact in facts.capabilities}
    for label, names in USAGE_TABLE.items():
        lines.append(_usage_row(label, [by_name[name] for name in names if name in by_name]))

    trackers = [sdk for sdk in facts.sdks if sdk.category != "library"]
    libraries = [sdk for sdk in facts.sdks if sdk.category == "library"]
    lines += ["", f"SDKs / trackers: {len(trackers) or 'none detected'}"]
    lines += [f"  {sdk.name} [{sdk.category}] ({sdk.class_count} classes)" for sdk in trackers]
    if libraries:
        lines.append("Known libraries: " + ", ".join(sdk.name for sdk in libraries))

    total = meta.counts.get("endpoints_total", len(facts.endpoints))
    lines += ["", f"Endpoints: {total} found, showing {min(total, MAX_URLS_SHOWN)}"]
    lines += [f"  {endpoint.value}" for endpoint in facts.endpoints[:MAX_URLS_SHOWN]]

    lines += ["", f"High-risk features: {len(facts.high_risk_features) or 'none'}"]
    lines += [f"  {f.feature}: {f.description}" for f in facts.high_risk_features]

    lines.append("")
    lines.append(f"Exported components: {len(facts.exported_components)}")
    if facts.secrets:
        lines.append(f"Secrets: {len(facts.secrets)}")
        lines += [f"  {secret.kind}: {secret.masked}" for secret in facts.secrets]

    stages = "  ".join(f"{name} {ms}" for name, ms in meta.stage_ms.items())
    lines += [
        "",
        f"Timing: {meta.duration_ms} ms total  (androguard {meta.androguard_version})",
        f"  ms per stage: {stages}",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline.extraction.cli",
        description="Statically analyse an Android APK. The APK is never installed or run.",
    )
    parser.add_argument("apk", help="path to the .apk file")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument(
        "--verbose", action="store_true", help="also show Androguard's parser warnings"
    )
    args = parser.parse_args(argv)

    from . import androguard_adapter
    from .analyze import extract

    # Androguard warns about harmless quirks in most real APKs; keep stdout/stderr clean.
    androguard_adapter.configure_logging("WARNING" if args.verbose else "ERROR")

    try:
        result = extract(args.apk)
    except InvalidApkError as exc:
        print(f"Invalid APK: {exc.reason}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False))
    else:
        print(format_summary(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
