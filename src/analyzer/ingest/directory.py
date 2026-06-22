"""Directory ingest — wrap an existing on-disk directory as a Bundle.

Used for self-scanning the analyzer's own source. The directory is NOT owned, so
cleanup never deletes it.
"""

from __future__ import annotations

from pathlib import Path

from analyzer.bundle import Bundle
from analyzer.ingest.archive import IngestError


def ingest_directory(path: str | Path) -> Bundle:
    root = Path(path).resolve()
    if not root.is_dir():
        raise IngestError(f"not a directory: {path}")
    return Bundle(root=root, source_mode="dir", owns_root=False)
