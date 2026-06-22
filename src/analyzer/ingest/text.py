"""Pasted-text ingest — writes a single artifact body into a sandbox dir."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from analyzer.bundle import Bundle
from analyzer.config import AnalyzerConfig
from analyzer.ingest.archive import IngestError

_KIND_DEFAULT_NAME = {
    "skill": "SKILL.md",
    "agents": "AGENTS.md",
    "claude_md": "CLAUDE.md",
}


def _safe_basename(name: str | None) -> str | None:
    """Reduce a user-supplied filename to a safe basename, or None if unusable."""
    if not name:
        return None
    base = os.path.basename(name.strip().replace("\\", "/"))
    base = base.strip()
    if not base or set(base) <= {"."}:
        return None
    return base


def ingest_text(
    content: str,
    config: AnalyzerConfig,
    declared_filename: str | None = None,
    kind_hint: str | None = None,
) -> Bundle:
    """Write pasted ``content`` to a named file in a fresh sandbox dir."""
    if len(content.encode("utf-8", errors="ignore")) > config.max_total_bytes:
        raise IngestError("pasted content exceeds total size cap")

    name = _safe_basename(declared_filename) or _KIND_DEFAULT_NAME.get(kind_hint or "", "PASTED.md")

    root = Path(tempfile.mkdtemp(prefix="ssa-text-"))
    bundle = Bundle(
        root=root,
        source_mode="text",
        primary_path=Path(name),
        declared_filename=declared_filename,
    )
    try:
        (root / name).write_text(content, encoding="utf-8")
    except Exception:
        bundle.cleanup()
        raise
    return bundle
