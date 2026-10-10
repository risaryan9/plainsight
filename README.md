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

Tests never use the network, except one that is skipped unless you ask for it:

```bash
RUN_LIVE_TESTS=1 uv run pytest -k live   # looks up com.whatsapp on the real Play Store
```

## Running the bot locally

Copy `.env.example` to `.env` and set `TELEGRAM_BOT_TOKEN` (from @BotFather). Then, from the repo root, in two terminals:

```bash
# terminal 1: the API
uv run uvicorn api.main:app --port 8000

# terminal 2: the Telegram bot
uv run python -m bot.main
```

Send the bot an `.apk` file (up to 20 MB), with a caption if you like: the caption becomes part of the app's "claim". The bot replies with a summary and a claim line such as `Claim: Play Store · Tools · policy fetched (42 sentences)`. Reports are saved in `data/reports/`, and Play listings and privacy policies are cached in `data/claims/`. Stop either program with Ctrl+C.

While `DEV_SEND_JSON=true` (the default for now), the bot also sends `extraction_<package>.json` and `claim_<package>.json` to the chat.

## Decisions and dev shortcuts

[docs/DECISIONS.md](docs/DECISIONS.md) logs every design decision. Entries marked `TEMPORARY-DEV` are development shortcuts that must change before production; `grep -rn "DEV-ONLY" .` finds the code they cover.
