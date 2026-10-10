"""Requested vs used: find the code that exercises each capability (spec §7.7)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from . import androguard_adapter as adapter
from .knowledge import CapabilityRule, SdkSignature
from .sdks import SdkMatcher

NO_CODE_REFERENCE = "(no code reference)"


@dataclass(frozen=True)
class UsageSite:
    """One place where a capability's API is touched."""

    caller: str
    caller_class: str | None
    target: str
    kind: Literal["method_call", "field_read", "string"]
    sdk: SdkSignature | None

    @property
    def sort_key(self) -> tuple[bool, str, str]:
        # The app's own code first, then bundled SDKs.
        return (self.sdk is not None, self.caller, self.target)


def _site_from_ref(ref: adapter.CodeRef, matcher: SdkMatcher) -> UsageSite:
    return UsageSite(
        caller=ref.caller.signature,
        caller_class=ref.caller.class_name,
        target=ref.target,
        kind=ref.kind,
        sdk=matcher.match(ref.caller.class_name),
    )


def find_class_init_sites(
    handle: adapter.ApkHandle, class_names: Sequence[str], matcher: SdkMatcher
) -> list[UsageSite]:
    """Constructor calls on the given classes (used for dynamic code loading)."""
    sites = {
        _site_from_ref(ref, matcher)
        for class_name in class_names
        for ref in adapter.find_method_calls(handle, class_name, ["<init>"])
    }
    return sorted(sites, key=lambda s: s.sort_key)


def find_capability_usage(
    handle: adapter.ApkHandle,
    rules: Mapping[str, CapabilityRule],
    matcher: SdkMatcher,
    pool: Sequence[str],
) -> dict[str, list[UsageSite]]:
    """For each capability with API rules, every call site found, app code first."""
    all_prefixes = sorted({prefix for rule in rules.values() for prefix in rule.class_prefixes})
    field_reads = adapter.find_field_reads(handle, all_prefixes)

    usage: dict[str, list[UsageSite]] = {}
    for capability, rule in rules.items():
        sites: set[UsageSite] = set()
        for method_rule in rule.methods:
            for ref in adapter.find_method_calls(handle, method_rule.class_name, method_rule.names):
                sites.add(_site_from_ref(ref, matcher))
        for prefix in rule.class_prefixes:
            for ref in adapter.find_calls_by_class_prefix(handle, prefix):
                sites.add(_site_from_ref(ref, matcher))
        for ref in field_reads:
            if ref.target.startswith(rule.class_prefixes):
                sites.add(_site_from_ref(ref, matcher))
        for needle in rule.strings:
            for value in pool:
                if needle not in value:
                    continue
                callers = adapter.string_callers(handle, value)
                if not callers:
                    sites.add(UsageSite(NO_CODE_REFERENCE, None, value, "string", None))
                for caller in callers:
                    sites.add(
                        UsageSite(
                            caller=caller.signature,
                            caller_class=caller.class_name,
                            target=value,
                            kind="string",
                            sdk=matcher.match(caller.class_name),
                        )
                    )
        usage[capability] = sorted(sites, key=lambda s: s.sort_key)
    return usage
