# Implementation Prompt — Skill Analyzer M7 (Web App) + M8 (Deploy)

> Paste this whole file into a fresh Claude Code session at the repo root
> (`skills-analyzer.socket-agency`). It is a spec, not a script: build it in the
> milestones below, write tests as you go, and stop at each acceptance gate.

## 0. Context — what already exists

The **analysis engine is complete** (milestones M1–M6) and committed on branch
`feature/analyzer-engine`. It is a **web-agnostic Python package** in `src/analyzer/` with
**no web/HTTP imports inside it** — keep it that way. 134 tests pass, `uvx pyright src tests`
is clean, the eval harness reports precision/recall 1.0, and the tool scans itself CLEAN.

Read these first: root `CLAUDE.md` (architecture, decisions, gotchas), `README.md` (roadmap),
and the engine source under `src/analyzer/`. The original full product spec (the "Agent Skill
Security Analyzer" implementation prompt) defines §1 stack, §6 trust model, §6.5 report safety,
§8 output contracts, §9 milestones M7/M8, §10 test corpus, §11 definition of done — honor them.

**Your job: build M7 (FastAPI + React SPA + typed contract) and M8 (Dockerfile + Dokku deploy).**

## 1. The engine API you will wrap (do not change the engine)

```python
from analyzer.analyze import analyze                 # analyze(bundle, config=DEFAULT_CONFIG, *, judges=None, rng=None, osv_query=...) -> ScanReport
from analyzer.config import DEFAULT_CONFIG, AnalyzerConfig
from analyzer.ingest.text import ingest_text         # (content: str, config, declared_filename=None, kind_hint=None) -> Bundle
from analyzer.ingest.archive import ingest_zip, IngestError   # (data: bytes, config, declared_filename=None) -> Bundle
from analyzer.ingest.git import ingest_git           # (url: str, config, *, allow_local=False) -> Bundle
from analyzer.render.sarif import to_sarif           # (report) -> dict (SARIF 2.1.0)

with ingest_text(body, DEFAULT_CONFIG, declared_filename="SKILL.md") as bundle:
    report = analyze(bundle, DEFAULT_CONFIG)          # report.model_dump(mode="json") -> canonical ScanReport JSON
```

- `Bundle` is a context manager; exiting it deletes the temp dir (ephemeral — never persist
  submissions beyond the request).
- **`ingest_*` and `analyze` are BLOCKING** (file IO, `subprocess` git clone, a judge ThreadPool).
  In FastAPI run them off the event loop: `await anyio.to_thread.run_sync(...)`.
- `ScanReport` fields (Pydantic): `artifact_meta{kind,name?,scope?}`, `components[]`, `imports[]`,
  `findings[]` (`id,category,severity,confidence,location{file,line?},evidence,risk,remediation,
  source_layer,language?,raised_by?`), `score`, `verdict` (`CLEAN|CAUTION|DO_NOT_INSTALL`),
  `judges_used[]`, `summary`. `artifact_meta.kind` ∈ `skill|agents|claude_md`.
- For git submissions from the web, call `ingest_git(url, cfg)` with `allow_local=False` (default) —
  it rejects local/`file://` paths and option-injection. Do NOT set `allow_local=True` for user input.
- LLM judges are OFF unless `JUDGE_LIVE=1` + provider keys are present (LiteLLM→OpenRouter). The
  engine already abstains/degrades safely; nothing to add there.

## 2. Locked decisions (from the original spec §1 — don't re-litigate)

- **Monorepo, single Dokku app.** Multi-stage Dockerfile builds the React bundle, then FastAPI
  serves it as static files — one domain, no CORS, one deploy.
- Backend: **FastAPI (async), `uv`.** Frontend: **React + Vite + TypeScript + Tailwind + shadcn/ui,
  package manager = Bun.**
- **Typed contract:** dump `openapi.json` via `app.openapi()` in a script (no running server) →
  `openapi-typescript` generates `types.ts` → `openapi-fetch` typed client. Wire as a pre-build
  step AND a CI drift check.
- All provider keys server-side only; never sent to the client.

## 3. Suggested layout (adjust if you have a better reason)

```
api/                      # FastAPI app — imports `analyzer`, NEVER imported by it
  __init__.py
  main.py                 # app, POST /scan, static mount + SPA fallback
  schemas.py              # request models (mode, kind hint, git url)
  dump_openapi.py         # writes openapi.json via app.openapi() (no server)
web/                      # React + Vite + TS + Tailwind + shadcn (Bun)
  src/                    # components, the generated src/lib/api/types.ts + client
Dockerfile                # multi-stage: bun build web → uv runtime serving static
.dockerignore
```

Keep `api/` a separate top-level package (run via `uvicorn api.main:app`) so the `analyzer`
package stays web-free. Add backend deps with `uv add` and frontend deps with `bun add` — **never
hand-edit `pyproject.toml`/`package.json`, and ask the user before installing anything.**

## 4. M7 — FastAPI + React UI + typed contract

### 4.1 Backend `POST /scan` (three input modes)
- Accept: (1) pasted text + a kind hint/filename, (2) uploaded `.zip` (multipart), (3) git URL.
- Enforce API-level limits BEFORE ingest: max request/upload size (~25 MB, reject larger with 413),
  content-type checks, a single mode per request. Reuse the engine's `AnalyzerConfig` caps.
- Run ingest + `analyze` via `anyio.to_thread.run_sync`; always close the `Bundle` (try/finally) so
  temp dirs are deleted even on error. Catch `IngestError` → 400 with a safe message.
- Output: canonical `ScanReport` JSON by default; **SARIF 2.1.0** when `Accept: application/sarif+json`
  or `?format=sarif` (`to_sarif(report)`).
- Never log submitted content or secrets (log-injection). Map engine exceptions to clean 4xx/5xx.

### 4.2 Typed contract
- `api/dump_openapi.py` writes `openapi.json` from `app.openapi()` without booting a server.
- `web` build runs `openapi-typescript openapi.json -o src/lib/api/types.ts` as a pre-build step;
  use `openapi-fetch` for the client. Add a **CI check** that regenerating types produces no diff
  (fail if drifted). (`orval` is an acceptable alternative if you want react-query hooks.)

### 4.3 React UI
- During `shadcn init`, configure the `@/` path alias in BOTH `vite.config.ts` and `tsconfig.json`
  or component imports break (known gotcha).
- Render: an **artifact-kind badge**, a verdict + score banner, a component table
  (file / type / executable?), findings grouped by severity (location, evidence snippet,
  remediation, source layer), a **"judges used"** transparency line, and the resolved `imports[]`
  for CLAUDE.md. Provide **Download JSON** and **Download SARIF** buttons.
- **§6.5 — do not attack the user through the report (critical):** render ALL untrusted evidence
  (snippets, filenames, frontmatter values, import targets) as **inert escaped text**. No
  `dangerouslySetInnerHTML`, no markdown execution of submitted content, no auto-linking. A finding
  whose evidence contains `<script>` or markdown MUST display as literal text (no stored XSS).

### 4.4 M7 acceptance gate (stop here, verify in a browser)
- End-to-end scan works for: a pasted `SKILL.md`, a pasted `CLAUDE.md`, and an uploaded `.zip`.
- A **report-XSS fixture** — evidence/filename containing `<script>` and markdown — renders inert
  (component test, e.g. Vitest + Testing Library, asserting it appears as text and executes nothing).
- `types.ts` regenerates with no diff; backend tests cover all three modes + SARIF + the size limit.

## 5. M8 — Dockerfile + Dokku deploy

- **Multi-stage Dockerfile:** stage 1 uses Bun to build `web/` → static `dist/`; stage 2 is the
  `uv` Python runtime that copies `dist/`, installs the backend, and serves the SPA via FastAPI
  `StaticFiles` with an `index.html` fallback for client routes. One domain, no CORS.
- **Env config** (document and read from env): `LITELLM_*` / provider keys, judge registry + panel
  size, the `AnalyzerConfig` limits, and an **egress allowlist** restricting outbound network to the
  LLM gateway + `api.osv.dev` only. Keys are server-side only.
- Add a **README deploy section** (Dokku single app; note the future option to split into two apps
  from the same monorepo via `git subtree split` / `dokku-monorepo`).
- **M8 acceptance gate:** the deployed tool **scans itself and returns CLEAN**; the full eval harness
  (`uv run python -m tests.eval.harness`) passes across several panel draws.

## 6. Conventions (from the user's global rules — follow exactly)

- **TDD throughout** (write the failing test first). Everything is covered with tests.
- **Type-check with `uvx pyright src tests api`** — the editor/live LSP is pinned to a stale
  interpreter and reports false "import could not be resolved" errors; ignore it, trust `uvx pyright`.
- Backend tests must NOT hit the network or a live LLM: inject `osv_query=lambda d,c: {}` (or set
  `osv_enabled=False`) and leave judges off (`JUDGE_LIVE` unset). Use FastAPI `TestClient`.
- **Commits:** use the `gitmoji-commit` skill; group by user-visible behavior (tests in the same
  commit as the behavior); run git commands one at a time (no `&&`); never `--no-verify`. End commit
  messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Work on a branch
  (`feature/web-app` off `feature/analyzer-engine` or `main`); ask before committing/pushing.
- **Never install packages without asking.** All deps via `uv add` / `bun add` — never hand-edit
  manifests. Prefer Bun; modern tooling.
- Keep `src/analyzer/` free of any web/HTTP import. Keep CLAUDE.md / README updated as you learn.
- Add the two mandatory final tasks to your task list: "Human validates changes" and
  "Run superpowers code review".

## 7. Definition of done (M7 + M8 slice of spec §11)

- All three input modes work end-to-end in a browser; reports render with the artifact-kind badge,
  verdict/score, components, grouped findings, imports, judges-used line, and JSON/SARIF downloads.
- Untrusted evidence renders as inert escaped text (no stored XSS / markdown execution) — tested.
- `openapi.json → types.ts` is automated and CI-checked for drift.
- JSON + SARIF both validate; CI can gate on verdict via SARIF.
- Temp dirs are ephemeral; no submitted content is persisted or logged; provider keys server-side only.
- Multi-stage Docker image builds; the deployed app scans itself CLEAN and the eval harness passes.
