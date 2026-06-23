"""Engine configuration — all limits, caps and judge-panel settings in one place.

The defaults are the security-relevant ceilings from the spec (§3, §6.4). The
config is *trusted* input authored by us — never derived from the submission.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class JudgeModel:
    """One entry in the judge registry (§4.7)."""

    model_id: str
    provider: str  # e.g. "anthropic", "openai", "google", "openrouter-open"
    gateway: str = "litellm"
    weight: float = 1.0
    enabled: bool = True
    language_tags: tuple[str, ...] = ()
    open_source: bool = False


# Default registry — distinct providers, with open-source members so a panel can
# always satisfy the "never 3-of-one-lab, >=1 open model" stratification rule.
#
# All five models are routed through OpenRouter (the ``openrouter/`` prefix), so a
# single OPENROUTER_API_KEY drives the whole live panel. The ``provider`` field keeps
# the originating lab for stratified sampling; flip the model strings back to native
# prefixes (e.g. ``anthropic/…``) if you'd rather dispatch to each provider directly.
DEFAULT_JUDGE_REGISTRY: tuple[JudgeModel, ...] = (
    JudgeModel("openrouter/anthropic/claude-sonnet-4.5", "anthropic"),
    JudgeModel("openrouter/openai/gpt-5", "openai"),
    JudgeModel("openrouter/google/gemini-2.5-pro", "google"),
    JudgeModel("openrouter/qwen/qwen-2.5-72b-instruct", "openrouter", open_source=True),
    JudgeModel("openrouter/deepseek/deepseek-chat", "openrouter", open_source=True),
)


@dataclass(frozen=True)
class AnalyzerConfig:
    # --- ingest hardening caps (§3, §6.4) ---
    max_total_bytes: int = 25 * 1024 * 1024  # ~25 MB total submission size
    max_file_count: int = 2000
    max_single_file_bytes: int = 5 * 1024 * 1024

    # --- parser / decoder caps (§6.4) ---
    max_yaml_bytes: int = 256 * 1024
    max_yaml_depth: int = 32
    decode_max_output_bytes: int = 2 * 1024 * 1024
    decode_max_depth: int = 2  # decode + recurse one level
    decode_max_blobs: int = 64  # cap decoded blobs per file (anti finding-explosion DoS)
    regex_timeout_seconds: float = 2.0

    # --- import resolution (§4.1) ---
    import_follow_depth: int = 1  # CLAUDE.md @import: follow one hop in-tree

    # --- git ingest (§3, §6.4) ---
    git_timeout_seconds: float = 60.0

    # --- judge panel (§4.7) ---
    judge_registry: tuple[JudgeModel, ...] = DEFAULT_JUDGE_REGISTRY
    panel_size: int = 3
    judge_min_confidence_votes: int = 1  # >=1 judge at confidence >= Medium to keep a finding
    judge_live: bool = field(default_factory=lambda: os.environ.get("JUDGE_LIVE") == "1")
    # Per-judge LLM call timeout. Bounds a slow/hanging model so it abstains instead of
    # stalling the whole panel (calls run in parallel, so this also caps the panel's wall time).
    judge_timeout_seconds: float = 30.0

    # --- supply chain ---
    osv_enabled: bool = True
    osv_endpoint: str = "https://api.osv.dev/v1/querybatch"
    osv_timeout_seconds: float = 10.0


DEFAULT_CONFIG = AnalyzerConfig()
