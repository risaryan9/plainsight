"""Telegram handlers. Thin by design: Telegram in, API call out (spec §7.1)."""

from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path

from telegram import Message, Update
from telegram.ext import ContextTypes

from . import formatting
from .api_client import ApiClient, ApiError, ScanResult

logger = logging.getLogger("plainsight.bot")

API_CLIENT_KEY = "api_client"
DEV_SEND_JSON_KEY = "dev_send_json"
# Telegram refuses bot uploads over 50 MB; stay clear of the limit.
MAX_DEV_FILE_BYTES = 45 * 1024 * 1024


async def start(update: Update, _context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_message:
        await update.effective_message.reply_text(formatting.START_TEXT)


async def help_command(update: Update, _context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_message:
        await update.effective_message.reply_text(formatting.HELP_TEXT)


async def about(update: Update, _context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_message:
        await update.effective_message.reply_text(formatting.ABOUT_TEXT)


async def fallback(update: Update, _context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_message:
        await update.effective_message.reply_text(formatting.FALLBACK_TEXT)


def dev_file_name(kind: str, package: object) -> str:
    """``<kind>_<package>.json``. The package name comes from the APK, so it is made safe."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(package or "unknown"))[:80]
    return f"{kind}_{safe}.json"


def _pretty_json(data: bytes) -> bytes:
    try:
        return json.dumps(json.loads(data), indent=2, ensure_ascii=False).encode("utf-8")
    except ValueError:
        return data


async def send_dev_json(message: Message, api: ApiClient, result: ScanResult) -> None:
    """Send the raw extraction and claim JSON to the chat.

    # DEV-ONLY (D-035): behind DEV_SEND_JSON. End users should never receive raw JSON.
    """
    package = result.summary.get("package")
    files: list[tuple[str, bytes]] = []
    try:
        extraction = await api.fetch_report(result.sha256)
    except ApiError:
        await message.reply_text(formatting.REPORT_UNAVAILABLE_TEXT)
    else:
        files.append((dev_file_name("extraction", package), _pretty_json(extraction)))
    claim = json.dumps(result.claim, indent=2, ensure_ascii=False).encode("utf-8")
    files.append((dev_file_name("claim", package), claim))

    for file_name, data in files:
        if len(data) > MAX_DEV_FILE_BYTES:
            await message.reply_text(
                formatting.DEV_FILE_TOO_LARGE_TEXT.format(
                    file_name=file_name, size_mb=len(data) / 1_048_576
                )
            )
            continue
        await message.reply_document(document=data, filename=file_name)


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if message is None or message.document is None:
        return
    document = message.document

    refusal = formatting.check_document(document.file_name, document.file_size)
    if refusal is not None:
        await message.reply_text(refusal)
        return

    api: ApiClient = context.application.bot_data[API_CLIENT_KEY]
    await message.reply_text(formatting.SCANNING_TEXT)
    # The caption text itself is never logged, only whether there is one.
    logger.info(
        "scan requested chat=%s file=%r size=%s caption=%s",
        message.chat_id,
        document.file_name,
        document.file_size,
        bool(message.caption),
    )

    with tempfile.TemporaryDirectory(prefix="plainsight-bot-") as tmp_dir:
        apk_path = Path(tmp_dir) / "upload.apk"
        try:
            telegram_file = await document.get_file()
            await telegram_file.download_to_drive(custom_path=apk_path)
        except Exception:
            logger.exception("could not download the document from Telegram")
            await message.reply_text(
                "I couldn't download that file from Telegram. Please try sending it again."
            )
            return
        try:
            # A forwarded document keeps its caption; it becomes part of the claim.
            result = await api.scan(apk_path, "upload.apk", caption=message.caption)
        except ApiError as exc:
            await message.reply_text(exc.user_message)
            return

    await message.reply_text(
        formatting.format_summary(result.summary, cached=result.cached, claim=result.claim)
    )
    logger.info(
        "scan done chat=%s sha256=%s cached=%s", message.chat_id, result.sha256, result.cached
    )

    if context.application.bot_data.get(DEV_SEND_JSON_KEY):
        await send_dev_json(message, api, result)


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("unhandled error while processing an update", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(formatting.UNEXPECTED_ERROR_TEXT)
