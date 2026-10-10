# Plainsight

Read `docs/PROJECT_SPEC.md` first, and follow its §20 (Notes for Claude Code).

The spec is a reference draft, not a fixed specification: verify before relying on it, and say so when it doesn't fit what you find. Its safety rules are firm:

- Never install or execute an APK. Static analysis only.
- Never commit secrets, APKs, malware samples, datasets or model binaries.
- Keep IAM least-privilege.

## Decisions

Before changing code, read `docs/DECISIONS.md`. Anything marked `TEMPORARY-DEV` is a development shortcut, not the final design. Add a new entry whenever you make a design decision or a dev-only shortcut, and mark dev-only code with `# DEV-ONLY (D-0xx)` so `grep -rn "DEV-ONLY" .` finds it.
