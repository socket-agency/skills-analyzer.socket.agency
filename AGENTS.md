# Skill Analyzer — Agent Guide

Canonical project context for any coding agent (Claude Code, Codex, etc.). Humans should
start with `README.md`; this file is the working guide for making changes safely.

Static security analyzer for AI agent instruction artifacts (`SKILL.md`, `AGENTS.md`,
`CLAUDE.md`). Detects prompt injection, command execution, data exfiltration, excessive
permissions, obfuscation and supply-chain risk; returns a `ScanReport` (JSON + SARIF) with a
`CLEAN / CAUTION / DO_NOT_INSTALL` verdict.

## Status

- **Engine `src/analyzer/` — M1–M6 + eval harness.** Pure library, no web imports.
- **M7 web app — DONE.** FastAPI wrapper (`api/`), React + Vite + TS + Tailwind SPA (`web/`, Bun),
  typed `openapi.json → types.ts` contract.
- **M8 deploy — DONE.** Multi-stage `Dockerfile` (Bun builds SPA → FastAPI serves it static), Dokku
  deploy docs + egress allowlist in `README.md`, `.env.example`.

## Working conventions (follow these)

- **TDD.** Write the failing test first; every feature/fix/refactor ships with tests. The whole
  suite must stay green (`uv run pytest`).
- **Keep `src/analyzer/` web-free.** `api/` imports `analyzer`; `analyzer` never imports `api/` or
  any web/HTTP library. This decoupling is what makes the engine unit-testable in isolation.
- **Type-check with `uvx pyright src tests api`** — NOT the editor/live LSP (see Gotchas).
- **re2 only in rule patterns** — no lookahead/lookbehind/backreferences (see Key decisions).
- **Commits:** one gitmoji per commit, grouped by user-visible behavior (tests in the same commit
  as the behavior they cover), git commands run one at a time, never `--no-verify`.
- **Never** read, print, or commit `.env` (it holds a live provider key for local runs); it is
  gitignored. Use `.env.example` for structure.

## Stack

- Python 3.12, `uv`. Pure library — **no web/HTTP imports inside `analyzer/`**.
- Deps: `pydantic`, `pyyaml`, `google-re2` (ReDoS-safe regex), `bashlex`, `httpx`, `litellm`,
  `yara-python`. Dev: `pytest`, `pytest-asyncio`, `pytest-timeout`.
- Web: FastAPI + `uvicorn` (backend), React + Vite + TypeScript + Tailwind v4, package manager Bun.
- Package is `analyzer` (src-layout); configured via `[tool.uv.build-backend] module-name`.

## Architecture

Entry point is a pure function: `analyze(bundle, config) -> ScanReport` (`analyze.py`).
Pipeline: ingest → discover (artifact kind → profile) → static rules → manifest →
AST/dataflow → obfuscation → supply-chain/OSV → judge panel → score/verdict/dedupe → render.

### Non-negotiable invariants (§6 of the spec)
1. **Never executes submitted content.** All layers are static (AST parse, regex, decode).
2. **Channel separation** (`judges/panel.py`): artifact content reaches judges only inside a
   nonce-fenced user-role data block; the hardened instructions live in the system role. Fence
   delimiter chars (`⟦⟧`) are stripped from content so it can't forge a closing fence.
3. **Additive-only judges**: `aggregate()` only emits findings — no path clears a finding or
   lowers a verdict. A jailbroken/abstaining judge can never suppress other findings.
4. **documents-vs-performs** (§7): the tool passes its own scan (`test_self_scan.py`).

## Key design decisions (and why)

- **re2, not Python `re`**: linear-time matching is how we satisfy ReDoS-safety without per-rule
  timeouts. **re2 has no lookahead/lookbehind/backreferences** — corpus patterns must avoid them.
- **Rule corpus is data** (`rules/corpus/*.yaml`), multilingual (en/uk/ru). Each rule declares
  `surfaces` (body/reference/script…), `kinds` (skill/agents/claude_md), `escalate_for_claude_md`
  (always-on weighting), and `negatable` (negation-aware documents-vs-performs downgrade).
- **Profile isolation**: structural skill-manifest vectors (`Bash(*)`, `` !`…` ``, `$ARGUMENTS`,
  `model:`) live in `layers/manifest.py` and only run for skill/agents — they can never fire on a
  CLAUDE.md. CLAUDE.md gets standing-instruction rules (escalated) + `@import` poisoning findings.
- **Instruction-body NL scanning only on markdown artifacts** (`discovery.primary_is_doc()`): a
  code file (e.g. a self-scan of `prompt.py`, which *documents* attack strings) is a script
  surface, never an instruction body — this is what keeps the self-scan CLEAN.
- **Taint = env-source → network-sink only.** Generic file reads were dropped from the trigger;
  they caused false positives on benign read-then-POST code (precision > recall, per the spec).
- **Judges are dependency-injected** and gated behind `JUDGE_LIVE=1`. Tests use `judges/fake.py`
  (deterministic) — security properties are provable without a live LLM. Real dispatch
  (`judges/client.py`, LiteLLM→OpenRouter) abstains on any error, timeout or unparseable output.
  All registry models route through OpenRouter (`openrouter/…`), so one `OPENROUTER_API_KEY`
  drives the whole panel; each call is bounded by `judge_timeout_seconds` so a slow model abstains
  instead of hanging the scan.
- **OSV is injected** into `analyze(..., osv_query=...)` so tests stay offline; offline degrades
  to an Info note.

## Web layer (`api/` + `web/`)

- **One-directional dependency**: `api/` imports `analyzer`; `analyzer` never imports `api/`.
  `api/` is a top-level package (NOT in the `analyzer` wheel) — run via `uvicorn api.main:app`;
  Docker sets `PYTHONPATH=/app` so it's importable.
- **`POST /scan`** (`api/main.py`): one multipart endpoint, three modes (`text`/`zip`/`git`).
  Size caps enforced before ingest (413, bounded chunked reads); `IngestError` → 400 (safe message,
  never a stack trace); blocking ingest+`analyze` run via `anyio.to_thread.run_sync`; `Bundle`
  always cleaned in `finally` (submissions ephemeral); content/secrets never logged. SARIF via
  `?format=sarif` or `Accept: application/sarif+json`. `ingest_git` is called with `allow_local=False`.
- **Scan config is dependency-injected** (`api/deps.py` `get_scan_context`): prod uses
  `DEFAULT_CONFIG` + real OSV; tests override the dependency to disable OSV and stub its query
  (offline). `JUDGE_LIVE=1` flips live judges on with no code change (`DEFAULT_CONFIG` reads it).
- **Typed contract**: `api/dump_openapi.py` writes `web/openapi.json` (committed); `bun run gen:api`
  → `web/src/lib/api/types.ts` (committed); `openapi-fetch` client in `web/src/lib/api/client.ts`.
  Drift guarded by `tests/test_openapi_contract.py` + `scripts/check-openapi-drift.sh`.
- **§6.5 report safety**: the SPA renders ALL untrusted strings (evidence, filenames, import
  targets, artifact name) as inert escaped JSX text — no `dangerouslySetInnerHTML`, no markdown
  execution, no auto-linking. Locked by `web/src/components/ReportView.test.tsx`.

## Commands

```bash
uv run pytest                      # full suite (engine + API + contract)
uvx pyright src tests api          # type check (use this, NOT the editor LSP — see gotcha)
cd web && bun run test             # frontend (Vitest): inert-evidence + smoke
uv run python -m tests.eval.harness  # precision/recall over the §10 corpus + self-scan
docker build -t skill-analyzer .   # multi-stage image (SPA + API)

# Run the app locally (live judges optional):
uv run uvicorn --env-file .env api.main:app --port 8000   # set OPENROUTER_API_KEY + JUDGE_LIVE=1 in .env
cd web && bun run dev                                      # hot-reload SPA, proxies /scan to :8000
```

## Gotchas

- **The editor/live LSP reports false "import could not be resolved" errors** — it is pinned to a
  stale interpreter, not `.venv`. `uvx pyright` (configured via `[tool.pyright]` venv) is the
  source of truth and reports 0 errors.
- macOS `/var` → `/private/var` symlink: don't mix `.resolve()`d paths with unresolved
  `bundle.root` when computing `relative_to` (bit us in an import test).
- Verdict floor: any Critical at confidence ≥ Medium ⇒ `DO_NOT_INSTALL` (`scoring.py`).
- `LiteLLM` needs the `openrouter/` routing prefix on model strings (it strips it and sends the
  bare slug to OpenRouter). Without the prefix LiteLLM routes to the native provider instead.
