# Decision log

A running log of design decisions and development shortcuts, for the people and AI agents
who work on this repository. Read it before changing code.

**Status**

- `PERMANENT`: the intended design. Change it only by adding a new entry that supersedes it.
- `TEMPORARY-DEV`: a development shortcut that must change before production. The code it
  covers is marked `# DEV-ONLY (D-0xx)`, so `grep -rn "DEV-ONLY" .` lists every shortcut.
- `SUPERSEDED`: no longer true; the entry says what replaced it.

**Adding an entry:** take the next free id, never reuse or renumber one, and fill in every
field. "Undo / revisit" is required for `TEMPORARY-DEV`. D-001 to D-025 were moved here from
`docs/PROJECT_SPEC.md` §21 with their numbers kept (D14 there is D-014 here), so older
references still resolve. `§` references point into the spec.

## Open shortcuts (TEMPORARY-DEV)

| ID | Shortcut |
|---|---|
| D-015 | Extraction models live in the worker, not `packages/shared` |
| D-021 | `POST /scan` is synchronous, with no auth and no rate limit |
| D-022 | Reports are addressed by APK hash |
| D-023 | One scan at a time, enforced by an in-process lock |
| D-026 | Reports are cached as files in `data/reports/` |
| D-029 | Claim cache is local files, kept for 3 days |
| D-034 | Combined report saved per hash; claim returned inline by `/scan` |
| D-035 | `DEV_SEND_JSON` sends raw JSON files to the Telegram chat |

---

## Architecture (from the original spec)

### D-001 · 2026-10-09 · Static analysis only
- **Decision:** APKs are parsed, never installed, run, emulated or dynamically loaded.
- **Status:** PERMANENT
- **Why:** safe to build and demo; no malware ever runs; fits Lambda. Alternative considered: dynamic analysis in emulators or sandboxes.
- **Affects:** the whole worker; `CLAUDE.md` safety rules; §9.2.
- **Undo / revisit:** not planned. It is a firm safety rule.

### D-002 · 2026-10-09 · Telegram as the front door
- **Decision:** users forward APKs to a Telegram bot; a web dashboard shows the full report.
- **Status:** PERMANENT
- **Why:** matches how scam APKs arrive; five-minute bot setup; free. Alternatives: a native Android app, WhatsApp first, web only.
- **Affects:** `services/bot`; §4.
- **Undo / revisit:** WhatsApp is future work (§19).

### D-003 · 2026-10-09 · Hybrid hosting: laptop + one Lambda
- **Decision:** the bot, API, database and dashboard run on the laptop; the heavy analysis runs in one AWS Lambda.
- **Status:** PERMANENT (the Lambda half is not built yet, see D-021)
- **Why:** fully serverless was too much AWS and harder to debug; one big VM loses isolation for hostile APKs.
- **Affects:** §5; `services/`, `worker/`, `infra/`.
- **Undo / revisit:** when the project outgrows a demo.

### D-004 · 2026-10-09 · No queue
- **Decision:** the API starts the worker with an asynchronous Lambda invoke instead of a queue.
- **Status:** PERMANENT (not built yet)
- **Why:** async invoke already gives fire-and-forget plus retries; hash-keyed results make retries safe; a Lambda cannot read a queue on a laptop behind NAT. Alternatives: Redis/Celery, SQS.
- **Affects:** §6, §7.2, §7.6.
- **Undo / revisit:** if scans need ordering or back-pressure.

### D-005 · 2026-10-09 · Androguard only
- **Decision:** Androguard is the only APK analysis tool.
- **Status:** PERMANENT
- **Why:** apktool and jadx need a JVM, more memory and time; Androguard is a Python library that also decompiles and covers all v1 facts.
- **Affects:** `worker/src/pipeline/extraction/`.
- **Undo / revisit:** if obfuscated apps need a stronger decompiler.

### D-006 · 2026-10-09 · Claude via the Anthropic API, orchestrated by LangGraph
- **Decision:** the agent layer calls Claude directly and is built with LangGraph.
- **Status:** PERMANENT (not built yet)
- **Why:** the project's own agent design (tools, loop, verifier) is the core contribution; avoids a black-box managed agent; keeps the AWS footprint small. Alternatives: Amazon Bedrock, Bedrock Agents.
- **Affects:** §7.11.
- **Undo / revisit:** not planned.

### D-007 · 2026-10-09 · Models baked into the Lambda image
- **Decision:** the ML models ship inside the worker container image.
- **Status:** PERMANENT (not built yet)
- **Why:** small tree models load in milliseconds; no extra service or cost. Alternatives: a SageMaker endpoint, a separate model server.
- **Affects:** §7.10, `worker/Dockerfile`.
- **Undo / revisit:** if the models grow large.

### D-008 · 2026-10-09 · PostgreSQL on the laptop
- **Decision:** PostgreSQL is the system of record for scans and reports.
- **Status:** PERMANENT (not built yet; see D-026 for what exists today)
- **Why:** JSONB reports, SQL for stats and rate limits, easy local development. Alternative: DynamoDB.
- **Affects:** §7.3.
- **Undo / revisit:** not planned.

### D-009 · 2026-10-09 · Cloudflare Tunnel
- **Decision:** one Cloudflare Tunnel gives the laptop a public HTTPS URL.
- **Status:** PERMANENT (not built yet)
- **Why:** one URL for the callback and the dashboard with no router changes; a named tunnel is stable. Alternatives: ngrok, port forwarding, API Gateway.
- **Affects:** §7.4.
- **Undo / revisit:** not planned.

### D-010 · 2026-10-09 · AWS SAM for infrastructure
- **Decision:** all AWS resources are defined in one SAM template.
- **Status:** PERMANENT (not built yet)
- **Why:** one repeatable template for the bucket, function, image repository, roles and log retention. Alternatives: Terraform, console clicks.
- **Affects:** §10, `infra/`.
- **Undo / revisit:** not planned.

### D-011 · 2026-10-09 · Deterministic scoring + verifier
- **Decision:** risk scores, concern levels and severities are computed in code; a verifier drops findings without evidence.
- **Status:** PERMANENT (not built yet)
- **Why:** reproducible, explainable and robust to prompt injection. Alternative: let the LLM score the app.
- **Affects:** §7.12, §9.3.
- **Undo / revisit:** not planned.

### D-012 · 2026-10-09 · Cache key = sha256 + pipeline version
- **Decision:** analysis results are cached by `(sha256, pipeline_version)`.
- **Status:** PERMANENT
- **Why:** "scan once, protect everyone"; changing the pipeline correctly invalidates old results. Alternatives: no cache, hash only.
- **Affects:** `services/api/src/api/main.py` (`report_path_for`), `PIPELINE_VERSION` in `services/api/src/api/settings.py`.
- **Undo / revisit:** bump `PIPELINE_VERSION` whenever analysis results change. See D-028 for what is and is not cached.

### D-013 · 2026-10-09 · BM25 policy retrieval in v1
- **Decision:** policy sentences are searched with BM25, not embeddings.
- **Status:** PERMANENT (not built yet)
- **Why:** keeps torch out of the Lambda image (size, cold start). Alternative: sentence-transformers embeddings.
- **Affects:** §7.11.
- **Undo / revisit:** embeddings remain an upgrade.

## Extraction layer

### D-014 · 2026-10-09 · The SDK list is `sdk_signatures.json`
- **Decision:** the SDK list is `worker/data/sdk_signatures.json` (the spec called it `trackers.json`), and it has a `library` category.
- **Status:** PERMANENT
- **Why:** the same list attributes call sites to bundled code, so it also needs non-tracker libraries (AppCompat, CameraX, OkHttp). Alternative: trackers only.
- **Affects:** `worker/data/sdk_signatures.json`, `worker/src/pipeline/extraction/sdks.py`, `knowledge.py`.
- **Undo / revisit:** merge in a tracker-signature snapshot (e.g. Exodus Privacy's list; check its licence) later.

### D-015 · 2026-10-09 · Extraction models live in the worker
- **Decision:** extraction emits its own `extraction.v1` shape, a superset of the `apk` + `facts` + `evidence` parts of `report.v1`, defined in `worker/src/pipeline/extraction/models.py` instead of `packages/shared`.
- **Status:** TEMPORARY-DEV
- **Why:** capabilities need call sites, `requested_unused` / `used_unrequested` and `call_site_count`; high-risk features need evidence; `report.v1` is not frozen yet.
- **Affects:** `worker/src/pipeline/extraction/models.py`, `worker/src/pipeline/claim/models.py` (D-033), every consumer of the report dict.
- **Undo / revisit:** when `report.v1` is frozen (roadmap P1), fold the extra fields in and move the models to `packages/shared`.

### D-016 · 2026-10-09 · Evidence prefix `file_`
- **Decision:** files inside the APK archive (native libraries) get evidence ids with the `file_` prefix.
- **Status:** PERMANENT
- **Why:** neither `man_` nor `str_` describes an archive entry.
- **Affects:** `worker/src/pipeline/extraction/evidence.py`, §8.1.
- **Undo / revisit:** not planned.

### D-017 · 2026-10-09 · High-risk feature rules are data
- **Decision:** high-risk feature rules live in `worker/data/high_risk_features.yaml`.
- **Status:** PERMANENT
- **Why:** the same "data, not if-chains" rule as the other curated lists. Alternative: hard-coded checks.
- **Affects:** `worker/data/high_risk_features.yaml`, `worker/src/pipeline/extraction/knowledge.py`, `analyze.py`.
- **Undo / revisit:** not planned.

### D-018 · 2026-10-09 · Androguard pinned to 4.1.4, no decompiler attached
- **Decision:** Androguard is pinned to 4.1.4 and the DEX files are loaded without the DAD decompiler.
- **Status:** PERMANENT
- **Why:** load and analyse can be timed separately; the adapter keeps the DEX objects so a decompiler can be attached lazily later. Alternative: `AnalyzeAPK()`.
- **Affects:** `worker/pyproject.toml`, `worker/src/pipeline/extraction/androguard_adapter.py`.
- **Undo / revisit:** when the code index (`get_method_source`) is built.

### D-019 · 2026-10-09 · Androguard log thresholds
- **Decision:** Androguard logs at WARNING in the library and ERROR in the CLI and the API (`--verbose` / `PARSER_LOG_LEVEL` restore WARNING).
- **Status:** PERMANENT
- **Why:** normal APKs produce about 20 harmless warnings each, which bury the output.
- **Affects:** `androguard_adapter.configure_logging`, `extraction/cli.py`, `services/api/src/api/settings.py`.
- **Undo / revisit:** not planned.

### D-020 · 2026-10-09 · IPv4 extraction drops unlikely addresses
- **Decision:** dotted quads that start with 0/1/2 or use only single digits are dropped (small allow-list for public DNS).
- **Status:** PERMANENT
- **Why:** almost all such strings in real APKs are ASN.1 object identifiers or version numbers.
- **Affects:** `worker/src/pipeline/extraction/strings.py`.
- **Undo / revisit:** it is a heuristic; treat `ip` endpoints as low-confidence.

## API and bot

### D-021 · 2026-10-09 · `POST /scan` is synchronous
- **Decision:** `POST /scan` runs the whole pipeline inside the request (a plain `def` route) and answers `200` with the result, instead of the spec's `202` + Lambda + callback flow. There is no auth and no rate limit.
- **Status:** TEMPORARY-DEV
- **Why:** gets Telegram → API → pipeline working end to end first.
- **Affects:** `services/api/src/api/main.py` (`scan`), `services/bot/src/bot/api_client.py`, `SCAN_TIMEOUT_S`.
- **Undo / revisit:** replace with the §7.2 flow (202 + callback, internal token, rate limits) in roadmap P2/P3. **Local use only until then.**

### D-022 · 2026-10-09 · The bot fetches reports over HTTP, by hash
- **Decision:** `GET /reports/{sha256}` serves the extraction report; the bot downloads it over HTTP and never reads the API's disk.
- **Status:** the HTTP fetch is PERMANENT; addressing reports by hash is TEMPORARY-DEV
- **Why:** keeps the bot a thin adapter that can run on another machine. A hash is guessable by anyone who has the same APK, which is acceptable only locally.
- **Affects:** `services/api/src/api/main.py` (`get_report`), `services/bot/src/bot/api_client.py` (`fetch_report`).
- **Undo / revisit:** switch public URLs to unguessable `scan_id`s (§7.2) with D-021.

### D-023 · 2026-10-09 · One scan at a time
- **Decision:** a process-wide lock surrounds the extraction; a request waits up to `SCAN_LOCK_TIMEOUT_S` (20 s), then gets `503` + `Retry-After: 60`. Cache hits never wait. Each scan logs its duration and peak memory.
- **Status:** TEMPORARY-DEV
- **Why:** one scan peaks at 0.4–1.3 GB (§7.7), so parallel scans can exhaust a laptop.
- **Affects:** `services/api/src/api/main.py` (`_scan_lock`), `metrics.py`, `services/bot/src/bot/api_client.py` (`MSG_BUSY`).
- **Undo / revisit:** the lock is in-process only, so run one uvicorn worker. It goes away when the analysis moves to Lambda (D-021).

### D-024 · 2026-10-09 · Bot uses `API_URL` and plain text
- **Decision:** the bot's config variable is `API_URL` (the spec said `API_INTERNAL_URL`), and its messages are plain text with no parse mode.
- **Status:** PERMANENT
- **Why:** plain text means APK-derived names cannot inject markup (§9.3).
- **Affects:** `services/bot/src/bot/settings.py`, `formatting.py`.
- **Undo / revisit:** the §8.5 verdict format arrives with the agent layer and must escape its input.

### D-025 · 2026-10-10 · Caption echoed in the summary
- **Decision:** the bot sent the Telegram caption to `POST /scan` and the API echoed it in `summary.caption`.
- **Status:** SUPERSEDED by the claim layer (2026-10-10). The bot still sends the `caption` form field, but it now feeds the claim (D-028) and the echo is gone.
- **Why:** a test hook until something consumed the caption.
- **Affects:** nothing any more.
- **Undo / revisit:** done.

### D-026 · 2026-10-10 · Reports are cached as files
- **Decision:** extraction reports are stored as `data/reports/<sha256>__<pipeline_version>.json` on the API's disk, instead of PostgreSQL (D-008) and S3.
- **Status:** TEMPORARY-DEV
- **Why:** no database to run while the pipeline is still changing shape. Split out of D-021.
- **Affects:** `services/api/src/api/main.py` (`report_path_for`, `_load_report`, `_write_report`), `REPORTS_DIR`, `.gitignore` (`/data/`).
- **Undo / revisit:** move to PostgreSQL + S3 with D-021. Files never expire and are not shared between machines.

### D-027 · 2026-10-10 · One decision log
- **Decision:** `docs/DECISIONS.md` is the only decision log. It replaces the table in spec §21 and the planned `docs/adr/` folder.
- **Status:** PERMANENT
- **Why:** two logs drift apart; agents need one place that also flags dev shortcuts.
- **Affects:** `docs/PROJECT_SPEC.md` §21, `CLAUDE.md`.
- **Undo / revisit:** not planned.

## Claim layer

### D-028 · 2026-10-10 · Only extraction is cached per APK; the claim is rebuilt per request
- **Decision:** the extraction result stays cached by `<sha256>__<pipeline_version>` (D-012). The claim is rebuilt on every `/scan`, from the package-level claim cache (D-029) plus that request's caption.
- **Status:** PERMANENT
- **Why:** the same APK arrives with different captions, and the caption is private to the sender. The claim is cheap to rebuild.
- **Affects:** `worker/src/pipeline/run.py` (`run_pipeline`), `services/api/src/api/main.py` (`scan`).
- **Undo / revisit:** if claim building becomes expensive, cache the caption-free part harder (it already is, D-029) rather than the caption.

### D-029 · 2026-10-10 · Claim cache is local files, 3 days
- **Decision:** the Play listing and privacy policy are cached per package in `data/claims/<package>.json` for 3 days. The caption is never cached. Lookup errors and failed policy fetches are not cached, so they are retried.
- **Status:** TEMPORARY-DEV
- **Why:** avoids re-scraping Play during repeated tests. The spec (§7.8) puts this cache in S3 for 7 days.
- **Affects:** `worker/src/pipeline/claim/cache.py`, `CLAIMS_DIR` in `services/api/src/api/settings.py`.
- **Undo / revisit:** move to S3 (`claims/{package}.json`) in roadmap P3 and settle the lifetime then. "Not on Play" is also cached for 3 days, so a newly published app can look unlisted for that long. Entries carry their own version (`claim-cache.v2`, D-037); an entry with another version is ignored.

### D-030 · 2026-10-10 · Play pages are fetched by our own HTTP client
- **Decision:** `google-play-scraper` is pinned to 1.2.7 and used only to parse the listing page (`parse_dom`). The page is fetched with httpx (10 s, verified TLS). The library's import-time change that turns off TLS verification for all of `urllib` is undone straight after import.
- **Status:** PERMANENT
- **Why:** the library's own `app()` has no timeout, and importing it sets `ssl._create_default_https_context` to the unverified context for the whole process.
- **Affects:** `worker/src/pipeline/claim/play.py`, `worker/pyproject.toml`, `worker/tests/test_claim_tls.py` (guards the TLS reset).
- **Undo / revisit:** re-check both points before upgrading the pin. `parse_dom` and `Formats.Detail` are library internals, so an upgrade can break them; the claim then degrades to "lookup failed", it does not fail the scan.

### D-031 · 2026-10-10 · SSRF guard on the policy fetch
- **Decision:** the privacy-policy URL must be http/https with no credentials, and every address its host resolves to must be public. This is checked again on each redirect (at most 3). The connection goes to the address that was checked, while TLS still uses the original hostname for SNI and certificate verification. Proxy settings from the environment are ignored.
- **Status:** PERMANENT
- **Why:** the URL comes from a Play listing, which an attacker controls, and the fetch runs on the laptop and later inside AWS (cloud metadata at 169.254.169.254). Connecting to the checked address closes the gap where DNS changes between the check and the fetch.
- **Affects:** `worker/src/pipeline/claim/policy.py`, `worker/tests/test_claim_policy.py`, `worker/tests/test_claim_tls.py`.
- **Undo / revisit:** never weaken it. If a proxy is ever required, the proxy must enforce the same rule.

### D-032 · 2026-10-10 · Impersonation check by name similarity
- **Decision:** when a Play listing is found, the APK's label is compared with the Play title. Both are lower-cased and reduced to letters and digits; the score is the higher of a character similarity ratio and the share of label words that appear in the title. A score below **0.5** sets `claim_possible_impersonation`.
- **Status:** PERMANENT (the threshold is a first guess)
- **Why:** a malicious APK can reuse a real app's package name, so the listing may describe a different app. The word-overlap half lets "WhatsApp" match "WhatsApp Messenger".
- **Affects:** `worker/src/pipeline/claim/claim.py` (`IMPERSONATION_THRESHOLD`, `name_similarity`).
- **Undo / revisit:** tune the threshold on real samples. Known weakness: a label in another language than the English Play title scores low. A missing label is not flagged. Comparing signing certificates would be stronger, but Play does not publish them.

### D-033 · 2026-10-10 · Claim model and fixed claim evidence ids
- **Decision:** the claim is a pydantic model (`claim.v1` at first, `claim.v2` since D-037) in `worker/src/pipeline/claim/models.py`, using `report.v1`'s field names where they exist. `category_source` already allows `"inferred"` for the future Purpose agent. Evidence ids are fixed: `lst_001` is the Play listing, `lst_002` is the caption, policy sentences are `pol_001`…, and flags are named `claim_*` ids (`claim_not_on_play`, `claim_no_policy`, `claim_policy_fetch_failed`, `claim_possible_impersonation`).
- **Status:** PERMANENT (its location follows D-015)
- **Why:** fixed ids mean the caption is always `lst_002` whether or not a listing exists, so later stages can cite it without looking it up.
- **Affects:** `worker/src/pipeline/claim/models.py`, `claim.py`, `worker/src/pipeline/extraction/models.py` (`EvidenceKind`), §8.1.
- **Undo / revisit:** move to `packages/shared` with D-015.

### D-034 · 2026-10-10 · Combined report saved per hash; claim returned inline
- **Decision:** `run_pipeline` returns a `pipeline.v1` dict (`schema_version, apk, facts, claim, evidence, meta`). The API saves it as `data/reports/<sha256>__<pipeline_version>.combined.json` (the latest request overwrites it) and returns the claim inside the `/scan` response. The combined file is not served over HTTP.
- **Status:** TEMPORARY-DEV
- **Why:** the combined report contains the sender's caption, and reports are addressed by hash (D-022), so serving it would show one user's caption to another. Saving it is only for inspection during development.
- **Affects:** `worker/src/pipeline/run.py`, `services/api/src/api/main.py` (`combined_report_path_for`), `services/api/src/api/schemas.py` (`ScanResponse.claim`).
- **Undo / revisit:** with D-021 and D-026: store the report per `scan_id` in PostgreSQL and serve it by `scan_id`, with captions kept private (§9.1). `pipeline.v1` becomes `report.v1` when that contract is frozen.

### D-035 · 2026-10-10 · `DEV_SEND_JSON` sends raw JSON to the chat
- **Decision:** with `DEV_SEND_JSON=true` (the default for now) the bot sends `extraction_<package>.json` and `claim_<package>.json` to the chat after the summary. A file over 45 MB is skipped with a message. With the flag off, the bot sends only the summary.
- **Status:** TEMPORARY-DEV
- **Why:** lets the developer inspect both halves of the pipeline from Telegram while there is no dashboard.
- **Affects:** `services/bot/src/bot/settings.py`, `handlers.py`, `.env.example`.
- **Undo / revisit:** default it to false, then remove it, when the dashboard and the §8.5 verdict message exist. End users should never receive raw JSON.

### D-036 · 2026-10-10 · Four new worker dependencies
- **Decision:** the worker now depends on `google-play-scraper` (pinned, D-030), `httpx`, `trafilatura` and `beautifulsoup4`.
- **Status:** PERMANENT
- **Why:** Play listing parsing, HTTP with timeouts and size caps, main-text extraction from policy pages, and a plain-text fallback when `trafilatura` finds nothing.
- **Affects:** `worker/pyproject.toml`, `uv.lock`, and later the Lambda image.
- **Undo / revisit:** **review the Lambda image size and cold start in roadmap P3.** `trafilatura` brings about 15 transitive packages (`lxml`, `babel`, `dateparser`, `regex`, `justext`, `courlan`, `htmldate` and others); if that is too heavy, replace it with the BeautifulSoup path alone or a slimmer extractor.

### D-037 · 2026-10-10 · Policy chunks know their headings (`claim.v2`)
- **Decision:** the policy chunker was rebuilt around headings. It amends D-029 and D-033.
  - **Sections:** every chunk has `section_path`, the headings above it (`["Permissions", "CAMERA"]`), and `section`, the last item. The page title (a single level-1 heading that opens the document) is not part of the path; it is stored once as `policy_title`.
  - **Retrieval text:** `PolicyChunk.search_text` is the path joined with `" > "`, then the sentence. Policy retrieval (BM25, §7.11) must index `search_text`, not `text`.
  - **Markdown is the common format:** HTML pages are converted to markdown by the extractor, GitHub policies already are markdown, and one small parser (`chunking.py`, no new dependency) handles both.
  - **Sentences:** the lines of a paragraph are joined first; a sentence ends only at `.`, `!` or `?` followed by a space and a capital letter or digit, with a short abbreviation list. A link keeps its text, never its target or reference label.
  - **Tables:** one chunk per row, written `Header1: cell; Header2: cell`, under the table's section.
  - **Bold headings:** on HTML pages a paragraph that is only bold text, of 8 words or fewer, is treated as a heading below the last real one.
  - **GitHub:** `github.com/<owner>/<repo>/blob/<ref>/<path>.md` is fetched from `raw.githubusercontent.com` under the same guard and limits (D-031), falling back to the page itself. `privacy_policy_url` is the listing's URL and `policy_final_url` the one fetched; `policy_format` says how it was parsed. `text/plain` and `text/markdown` are accepted.
  - **Duplicates:** a chunk is dropped only if its section path and its text both match an earlier one.
  - **Every evidence id resolves inside the claim:** `listing_chunks` (`lst_001` = Play description, `lst_002` = caption) and `flag_chunks` (`claim_*` ids with their explanation) sit beside `policy_chunks`.
  - **Versions:** the claim is `claim.v2` and the per-package cache `claim-cache.v2`. Old cache entries fail validation and are ignored. `PIPELINE_VERSION` is unchanged, because the extraction did not change.
- **Status:** PERMANENT
- **Why:** with body text only, "Required to send a scanned code to a custom URL" no longer said it was about INTERNET, and sentences broke at links and inline code ("…requires using" / "WifiManager.getConfiguredNetworks" / "which requires…"). The full path matters because "Data we collect > Location" and "Data we share > Location" share the nearest heading.
- **Affects:** `worker/src/pipeline/claim/chunking.py` (new), `policy.py`, `models.py`, `claim.py`, `cache.py`; `worker/tests/test_claim_chunking.py` and `worker/tests/fixtures/`.
- **Undo / revisit:**
  - Bump `claim-cache.vN` whenever the chunking or the cached shape changes, so old entries are not reused.
  - The claim cache does expire (3 days, D-029). Keep an expiry when it moves to S3: policies change over time.
  - The combined report is rewritten on every request and never read back (D-034), so it needs no version in its name. If it is ever cached and reused, add the claim version to its key.
  - Known gaps: the extractor drops some very short list items (a one-word "Email" bullet can be lost); only GitHub is rewritten to raw files (not GitLab, Bitbucket or gists); tables without a header row are read as paragraphs.
