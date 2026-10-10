"""Plain-text messages. No parse mode is used, so text from an APK cannot inject markup."""

from __future__ import annotations

from typing import Any

MAX_SUMMARY_CHARS = 1000
MAX_APK_BYTES = 20 * 1024 * 1024
_MAX_NAME_CHARS = 80
_MAX_DANGEROUS_SHOWN = 6
_MAX_CAPABILITIES_SHOWN = 8

START_TEXT = (
    "Hi! I'm Plainsight. Send me an Android app file (.apk) and I'll tell you what it "
    "is able to do: which permissions it asks for, and which of them its code really uses.\n\n"
    "I only read the file. I never install or run it."
)
HELP_TEXT = (
    "How to use me:\n"
    "1. Send or forward an .apk file to this chat (up to 20 MB).\n"
    "2. Wait a little; a scan can take up to a minute.\n"
    "3. I reply with a short summary and the full report as a JSON file.\n\n"
    "Commands: /start, /help, /about"
)
ABOUT_TEXT = (
    "Plainsight checks whether an Android app does what it claims, or takes more than it "
    "needs. This early version does static analysis only: it reads the app's manifest and "
    "code without running it. It is a student project, not a guarantee that an app is safe."
)
FALLBACK_TEXT = "Send me an APK file to scan."
SCANNING_TEXT = "Scanning…"
NOT_APK_TEXT = (
    "I can only scan Android app files, and that file's name doesn't end in .apk. "
    "Please send the .apk file itself."
)
TOO_LARGE_TEXT = (
    "Sorry, that file is {size_mb:.1f} MB. Telegram only lets bots download files up to "
    "20 MB, so I can't scan it here."
)
REPORT_UNAVAILABLE_TEXT = "I couldn't attach the full report this time."
UNEXPECTED_ERROR_TEXT = "Something went wrong on my side. Please try again."


def check_document(file_name: str | None, file_size: int | None) -> str | None:
    """Return a polite refusal if the document cannot be scanned, else None."""
    if not file_name or not file_name.lower().endswith(".apk"):
        return NOT_APK_TEXT
    if file_size is not None and file_size > MAX_APK_BYTES:
        return TOO_LARGE_TEXT.format(size_mb=file_size / 1_048_576)
    return None


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _short_permission(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _pretty(capability: str) -> str:
    return capability.replace("_", " ").capitalize()


def _usage_line(capability: dict[str, Any]) -> str | None:
    requested, used = capability.get("requested"), capability.get("used")
    name = _pretty(str(capability.get("capability", "?")))
    if requested and used:
        return f"• {name}: asks for it and uses it"
    if requested and used is False:
        return f"• {name}: asks for it, but no code uses it"
    if requested:
        return f"• {name}: asks for it"
    if used:
        return f"• {name}: code can use it, but it is not asked for"
    return None


def format_summary(summary: dict[str, Any], *, cached: bool) -> str:
    """The chat reply for a finished scan. Always under ``MAX_SUMMARY_CHARS`` characters."""
    package = _clip(str(summary.get("package") or "unknown package"), _MAX_NAME_CHARS)
    label = summary.get("label")
    title = f"{_clip(str(label), _MAX_NAME_CHARS)} ({package})" if label else package

    dangerous = [str(name) for name in summary.get("dangerous_permissions") or []]
    lines = [
        title,
        "",
        f"Permissions: {summary.get('permission_count', 0)} declared, {len(dangerous)} dangerous",
    ]
    if dangerous:
        shown = [_clip(_short_permission(name), 40) for name in dangerous[:_MAX_DANGEROUS_SHOWN]]
        more = len(dangerous) - len(shown)
        lines.append("Dangerous: " + ", ".join(shown) + (f" (+{more} more)" if more > 0 else ""))

    usage = [
        line
        for capability in summary.get("capabilities") or []
        if (line := _usage_line(capability)) is not None
    ]
    lines.append("")
    if usage:
        lines.append("What it asks for vs what its code uses:")
        lines += [_clip(line, 90) for line in usage[:_MAX_CAPABILITIES_SHOWN]]
        if len(usage) > _MAX_CAPABILITIES_SHOWN:
            lines.append(f"(+{len(usage) - _MAX_CAPABILITIES_SHOWN} more in the report)")
    else:
        lines.append("It asks for no sensitive capabilities, and none were found in its code.")

    lines += ["", "Saved result from an earlier scan." if cached else "Fresh scan."]
    return _clip("\n".join(lines), MAX_SUMMARY_CHARS - 1)
