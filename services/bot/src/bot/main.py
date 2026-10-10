"""Plainsight Telegram bot (long polling).

uv run python -m bot.main
"""

from __future__ import annotations

import logging
import sys

from pydantic import ValidationError
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters

from . import handlers
from .api_client import ApiClient
from .settings import Settings, get_settings

logger = logging.getLogger("plainsight.bot")


def build_application(settings: Settings) -> Application:  # type: ignore[type-arg]
    # Scans take a while, so let several chats be served at once.
    application = (
        Application.builder()
        .token(settings.telegram_bot_token.get_secret_value())
        .concurrent_updates(True)
        .build()
    )
    application.bot_data[handlers.API_CLIENT_KEY] = ApiClient(
        settings.api_url, timeout_s=settings.scan_timeout_s
    )
    application.add_handler(CommandHandler("start", handlers.start))
    application.add_handler(CommandHandler("help", handlers.help_command))
    application.add_handler(CommandHandler("about", handlers.about))
    application.add_handler(MessageHandler(filters.Document.ALL, handlers.handle_document))
    application.add_handler(MessageHandler(filters.ALL, handlers.fallback))
    application.add_error_handler(handlers.on_error)
    return application


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    # httpx logs every request URL at INFO, and Telegram URLs contain the bot token.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    try:
        settings = get_settings()
    except ValidationError:
        print(
            "TELEGRAM_BOT_TOKEN is not set. Put it in .env (TELEGRAM_BOT_TOKEN=...) and run "
            "this from the folder that contains .env.",
            file=sys.stderr,
        )
        return 1

    logger.info("starting; API at %s", settings.api_url)
    build_application(settings).run_polling(allowed_updates=Update.ALL_TYPES)
    return 0


if __name__ == "__main__":
    sys.exit(main())
