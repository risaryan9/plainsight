# plainsight

Forward an Android app (APK) to a Telegram bot and get an honest answer back: does this app do what it claims, or is it taking more than it needs?

Plainsight analyses APKs statically (they are never installed or executed) and compares what the app does with what it says it does.

See [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md) for the full specification.

## Extraction layer

The first piece that exists is the static extractor in `worker/`. It needs [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run python -m pipeline.extraction.cli path/to/app.apk          # short summary
uv run python -m pipeline.extraction.cli path/to/app.apk --json   # full JSON
```

From Python: `from pipeline.extraction import analyze_apk`.

Tests: `uv run pytest`. The integration test needs a real APK, kept outside the repo:

```bash
TEST_APK_PATH=~/apks/some-app.apk uv run pytest
```

## Running the bot locally

Copy `.env.example` to `.env` and set `TELEGRAM_BOT_TOKEN` (from @BotFather). Then, from the repo root, in two terminals:

```bash
# terminal 1: the API
uv run uvicorn api.main:app --port 8000

# terminal 2: the Telegram bot
uv run python -m bot.main
```

Send the bot an `.apk` file (up to 20 MB). Reports are saved in `data/reports/`. Stop either program with Ctrl+C.
