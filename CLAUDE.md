# Skill Analyzer — Claude Code

The shared, agent-agnostic project context (architecture, invariants, design decisions, the web
layer, commands, and gotchas) lives in `AGENTS.md`. It is imported below — read it first.

@AGENTS.md

## Claude Code specifics

These add to — and never override — the conventions in `AGENTS.md` and the user's global rules.

- **Commits:** use the `gitmoji-commit` skill. One gitmoji per commit, grouped by user-visible
  behavior (tests in the same commit as the behavior they cover). End each message with
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Run git commands one at a time;
  never `--no-verify`; ask before committing or pushing.
- **Type-check** with the `uvx pyright src tests api` command — the editor/live LSP is pinned to a
  stale interpreter and reports false import errors (see Gotchas in `AGENTS.md`).
- **`.env` is off-limits:** it holds a live `OPENROUTER_API_KEY` for local `JUDGE_LIVE=1` runs and
  is gitignored. The harness blocks reading it; pass it to processes via `uvicorn --env-file .env`
  (the user runs that), never echo or commit it.
- **Browser validation:** the FastAPI app serves the built SPA at `/`, so a quick visual check is
  `uvicorn api.main:app` → open `:8000`. Use `cd web && bun run dev` (proxies to `:8000`) for
  hot-reload work.
- **Keep these docs current:** when you learn something architectural, update `AGENTS.md` (the
  shared source of truth), not this file — leave CLAUDE.md for Claude-Code-only workflow notes.
