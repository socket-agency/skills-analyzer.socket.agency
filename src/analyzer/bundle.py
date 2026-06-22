"""The :class:`Bundle` — an extracted submission rooted in a sandboxed temp dir.

Every analysis layer reads from a Bundle. The Bundle never executes anything; it
only exposes inert file contents and untrusted metadata (declared filename, git
commit/author/branch) as data to be analyzed.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Bundle:
    """An ingested submission.

    Attributes:
        root: absolute path to the sandbox dir holding the submission.
        source_mode: one of ``text`` / ``zip`` / ``git``.
        primary_path: relative path of the main artifact file, if identified.
        declared_filename: original filename as supplied by the user (untrusted).
        git_metadata: untrusted git facts (commit message, author, branch). Keys
            are stable strings; values are inert data to be analyzed, never trusted.
        owns_root: whether ``root`` is a temp dir this Bundle should delete.
    """

    root: Path
    source_mode: str
    primary_path: Path | None = None
    declared_filename: str | None = None
    git_metadata: dict[str, str] = field(default_factory=dict)
    owns_root: bool = True

    #: directories we never scan (build/VCS/cache noise, not artifact content)
    IGNORED_DIRS = frozenset({"__pycache__", ".git", ".venv", ".pytest_cache", ".ruff_cache", "node_modules", ".mypy_cache"})

    def iter_files(self) -> Iterator[Path]:
        """Yield every regular file under root as a path relative to root.

        Symlinks are skipped: ingest resolves/strips them, and we never follow one
        out of the sandbox. Build/VCS/cache directories are skipped as noise.
        """
        for path in sorted(self.root.rglob("*")):
            if path.is_symlink():
                continue
            rel = path.relative_to(self.root)
            if any(part in self.IGNORED_DIRS for part in rel.parts):
                continue
            if path.is_file():
                yield rel

    def abs_path(self, relpath: Path | str) -> Path:
        """Resolve a relative path inside the sandbox, refusing escapes."""
        candidate = (self.root / relpath).resolve()
        root = self.root.resolve()
        if root != candidate and root not in candidate.parents:
            raise ValueError(f"path escapes sandbox: {relpath!r}")
        return candidate

    def read_text(self, relpath: Path | str, max_bytes: int = 5 * 1024 * 1024) -> str:
        """Read a file as UTF-8 text (lossy), bounded to ``max_bytes``."""
        data = self.abs_path(relpath).read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="replace")

    def read_bytes(self, relpath: Path | str, max_bytes: int = 5 * 1024 * 1024) -> bytes:
        return self.abs_path(relpath).read_bytes()[:max_bytes]

    def cleanup(self) -> None:
        if self.owns_root and self.root.exists():
            shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> Bundle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.cleanup()
