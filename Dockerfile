# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — build the React SPA with Bun.
# Consumes the committed web/openapi.json (the typed contract); no Python needed here.
# ─────────────────────────────────────────────────────────────────────────────
FROM oven/bun:1 AS web-build
WORKDIR /web

# Install deps first (cached unless the lockfile changes).
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile

# Build: gen:api (openapi-typescript) → tsc -b → vite build → /web/dist
COPY web/ ./
RUN bun run build

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Python runtime that serves the SPA + the /scan API via FastAPI.
# One image, one domain, no CORS.
# ─────────────────────────────────────────────────────────────────────────────
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS runtime
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_FROZEN=1 \
    # api/ is a top-level package (not part of the analyzer wheel) — put it on the path.
    PYTHONPATH=/app \
    # Run the synced venv's uvicorn directly at runtime (no `uv run`, which would need a
    # writable cache the non-root user lacks).
    VIRTUAL_ENV=/app/.venv \
    PATH=/app/.venv/bin:$PATH \
    PORT=8000

# Install only runtime dependencies (the analyzer engine + FastAPI stack), no dev tools.
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# Application code + the built SPA.
COPY api/ ./api/
COPY --from=web-build /web/dist ./web/dist

# Run as the non-root user that the base image already provides.
USER 1000:1000
EXPOSE 8000

# JUDGE_LIVE / provider keys / AnalyzerConfig limits are supplied at deploy time (see README).
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT}"]
