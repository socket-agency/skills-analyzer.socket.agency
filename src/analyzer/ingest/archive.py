"""Zip ingest with hardening against zip-slip, symlinks and decompression bombs (§6.4)."""

from __future__ import annotations

import io
import stat
import tempfile
import zipfile
from pathlib import Path

from analyzer.bundle import Bundle
from analyzer.config import AnalyzerConfig


class IngestError(Exception):
    """Raised when a submission violates a hardening limit or looks hostile."""


def _is_within(root: Path, target: Path) -> bool:
    return root == target or root in target.parents


def ingest_zip(
    data: bytes,
    config: AnalyzerConfig,
    declared_filename: str | None = None,
) -> Bundle:
    """Extract a zip into a fresh sandbox dir, refusing anything unsafe."""
    root = Path(tempfile.mkdtemp(prefix="ssa-zip-"))
    bundle = Bundle(root=root, source_mode="zip", declared_filename=declared_filename)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = [m for m in zf.infolist() if not m.is_dir()]
            if len(members) > config.max_file_count:
                raise IngestError(
                    f"archive exceeds max file count ({len(members)} > {config.max_file_count})"
                )

            total = 0
            for member in members:
                mode = (member.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    # never materialize a symlink — it could point out of the sandbox
                    continue

                target = (root / member.filename).resolve()
                if not _is_within(root.resolve(), target):
                    raise IngestError(f"zip-slip / traversal entry rejected: {member.filename!r}")

                # bounded read defends against a lying uncompressed-size header (bomb)
                with zf.open(member) as src:
                    chunk = src.read(config.max_single_file_bytes + 1)
                if len(chunk) > config.max_single_file_bytes:
                    raise IngestError(f"file exceeds single-file cap: {member.filename!r}")
                total += len(chunk)
                if total > config.max_total_bytes:
                    raise IngestError("archive exceeds total size cap (possible bomb)")

                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(chunk)
    except zipfile.BadZipFile as exc:
        bundle.cleanup()
        raise IngestError(f"not a valid zip archive: {exc}") from exc
    except Exception:
        bundle.cleanup()
        raise

    return bundle
