"""Telegram handlers. Thin by design: Telegram in, API call out (spec §7.1)."""

from __future__ import annotations

import logging
import re
import tempfile
from pathlib import Path

from telegram import Update
from telegram.ext import ContextTypes

from . import formatting
from .api_client import ApiClient, ApiError

logger = logging.getLogger("plainsight.bot")

API_CLIENT_KEY = "api_client"


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


def _report_file_name(package: object, sha256: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", str(package or "report"))[:80]
    return f"{safe}-{sha256[:12]}.json"


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
    logger.info(
        "scan requested chat=%s file=%r size=%s",
        message.chat_id,
        document.file_name,
        document.file_size,
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
            result = await api.scan(apk_path, "upload.apk")
        except ApiError as exc:
            await message.reply_text(exc.user_message)
            return

    await message.reply_text(formatting.format_summary(result.summary, cached=result.cached))
    logger.info(
        "scan done chat=%s sha256=%s cached=%s", message.chat_id, result.sha256, result.cached
    )

    try:
        report = await api.fetch_report(result.sha256)
    except ApiError:
        await message.reply_text(formatting.REPORT_UNAVAILABLE_TEXT)
        return
    await message.reply_document(
        document=report,
        filename=_report_file_name(result.summary.get("package"), result.sha256),
        caption="Full report (JSON)",
    )


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("unhandled error while processing an update", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(formatting.UNEXPECTED_ERROR_TEXT)
