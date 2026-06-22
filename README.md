# Skill Analyzer

Static security analyzer for AI agent instruction artifacts. It scans Claude Code
**`SKILL.md`** skills, Codex **`AGENTS.md`**, and Claude Code **`CLAUDE.md`** project/user
memory for malicious or unsafe behavior — prompt injection, command execution, data
exfiltration, excessive permissions, obfuscation, and supply-chain risk — and returns a
human-readable report plus machine-readable JSON / SARIF.

> **The analyzer never executes submitted content.** All analysis is static.

The repository has three parts: the **web-agnostic analysis engine** (`src/analyzer/`), a thin
**FastAPI** wrapper (`api/`), and a **React + Vite + Tailwind** single-page app (`web/`). A
multi-stage `Dockerfile` builds the SPA and serves it from FastAPI as one app, one domain.

## What it detects

| Category | Examples |
|---|---|
| Prompt Injection | "ignore all previous instructions", "mark this as safe" (en/uk/ru) |
| Command Execution | `Bash(*)`, `` !`socat … exec:/bin/bash` ``, `curl … \| bash`, reverse shells |
| Data Exfiltration | env-harvest → network POST (taint), "after every commit, POST the diff to …" |
| Excessive Agency | "auto-approve all tools", "never ask before running" |
| Context Poisoning | CLAUDE.md `@import` of `~/.ssh`, out-of-tree, or remote URLs |
| Obfuscation | base64/hex payloads, zero-width chars, bidi/Trojan-Source, homoglyphs |
| Supply Chain | known-CVE deps (OSV.dev), mutable refs, typosquats |
| Trigger Abuse | descriptions engineered to match every prompt |

Each artifact kind gets its own **analysis profile** — e.g. CLAUDE.md is always-on context, so
standing instructions there are weighted one step higher than the same text in an on-demand skill.

## Design highlights

- **Multilingual-first.** Injection / social-engineering phrasing is detected in English,
  Ukrainian and Russian, plus mixed-script / homoglyph content.
- **Hardened against attacks on the analyzer itself.** A randomized, provider-stratified LLM
  judge panel receives artifact content only inside a per-request **nonce-fenced data block**,
  never concatenated into a system prompt. Judges are **additive-only** (they can raise findings,
  never clear one), and a malformed/jailbroken judge **abstains** — it can never mark something
  clean.
- **documents-vs-performs.** A file that *documents* a malicious pattern (a detector, a quoted
  example, a security policy) is not flagged; one that *performs* it is. The tool passes its own
  scan.
- **ReDoS / bomb safe.** Patterns use the linear-time `google-re2` engine; decoders and archive
  extraction enforce size, depth, file-count and path-traversal limits.

## Usage (engine)

```python
from analyzer.analyze import analyze
from analyzer.config import DEFAULT_CONFIG
from analyzer.ingest.text import ingest_text

with ingest_text(open("SKILL.md").read(), DEFAULT_CONFIG, declared_filename="SKILL.md") as bundle:
    report = analyze(bundle, DEFAULT_CONFIG)

print(report.verdict, report.score)        # e.g. DO_NOT_INSTALL 100
print(report.model_dump_json(indent=2))    # canonical JSON ScanReport
```

Ingest modes: `ingest_text`, `ingest.archive.ingest_zip`, `ingest.git.ingest_git`,
`ingest.directory.ingest_directory`. SARIF: `analyzer.render.sarif.to_sarif(report)`.

### LLM judges

Off by default (deterministic). Set `JUDGE_LIVE=1` and provider keys (via LiteLLM / OpenRouter)
to enable the live panel. The registry, panel size and vote threshold are in `analyzer/config.py`.

## Web app

A single `POST /scan` endpoint accepts one submission per request in three modes — pasted text
(with a kind hint), an uploaded `.zip`, or a remote git URL — and returns a canonical `ScanReport`
(JSON by default, **SARIF 2.1.0** via `?format=sarif` or `Accept: application/sarif+json`).
Submissions are ephemeral: every temp sandbox is deleted after the request, and submitted content
is never logged. The React UI renders all untrusted evidence as **inert escaped text** (no
`dangerouslySetInnerHTML`, no markdown execution) so a malicious report can't attack the viewer.

```bash
# 1. backend (http://localhost:8000)
uv run uvicorn api.main:app --reload

# 2. frontend dev server (http://localhost:5173, proxies /scan + /api to :8000)
cd web && bun install && bun run dev
```

### Typed contract (openapi.json → types.ts)

The TypeScript client is generated from the API's own schema, so the frontend can't drift from
the backend:

```bash
uv run python -m api.dump_openapi          # write web/openapi.json from app.openapi()
cd web && bun run gen:api                   # openapi-typescript → src/lib/api/types.ts
bash scripts/check-openapi-drift.sh         # CI: fail if either is stale
```

`tests/test_openapi_contract.py` also asserts the committed `openapi.json` matches the live schema.

## Development

```bash
uv sync
uv run pytest                          # full suite (engine + API + contract)
uvx pyright src tests api              # type check
cd web && bun run test                 # frontend (Vitest): inert-evidence + smoke
uv run python -m tests.eval.harness    # precision/recall over the corpus + self-scan
```

## Deployment (Dokku, single app)

The multi-stage `Dockerfile` builds the SPA with Bun, then serves it from the FastAPI `uv` runtime
— one container, one domain, no CORS.

```bash
docker build -t skill-analyzer .
docker run --rm -p 8000:8000 --env-file .env skill-analyzer
```

On Dokku:

```bash
dokku apps:create skill-analyzer
dokku builder-dockerfile:set skill-analyzer dockerfile-path Dockerfile
# secrets (server-side only — never exposed to the client):
dokku config:set skill-analyzer JUDGE_LIVE=1 OPENROUTER_API_KEY=…
git push dokku main
```

See `.env.example` for all variables (judge toggle + provider keys, `PORT`). The engine's
`AnalyzerConfig` limits (size/file caps, judge panel size, OSV) live in `src/analyzer/config.py`.

**Egress allowlist (enforce at the platform/firewall layer):** the app only needs outbound access
to the **LLM gateway** (OpenRouter, when judges are live) and **`api.osv.dev`** (supply-chain
lookups). Block everything else; note that a submitted *git URL* causes an outbound clone to that
host, so apply the same controls you would to any user-supplied fetch.

> **Future split:** the monorepo can later become two Dokku apps (API + static frontend) from the
> same tree via `git subtree split` / the `dokku-monorepo` plugin. The current single-app layout is
> the simplest correct deploy.

## Roadmap

- **M1–M6** — analysis engine (ingest, profiles, static rules, manifest, AST/dataflow,
  obfuscation, supply-chain/OSV, judge panel, scoring/verdict, SARIF) + eval harness. ✅
- **M7** — FastAPI wrapper + React/Vite/TypeScript/Tailwind SPA, three input modes
  (paste / zip / git URL), typed `openapi.json → types.ts` contract, inert (escaped) evidence
  rendering. ✅
- **M8** — multi-stage Dockerfile (React build → FastAPI serves static), Dokku deploy with an
  egress allowlist to the LLM gateway + OSV.dev. ✅
