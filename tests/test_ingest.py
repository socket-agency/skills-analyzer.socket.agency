"""Ingest hardening tests (M1 gate): zip-slip / symlink / size / file-count.

The analyzer treats every submitted archive as hostile. These tests assert the
extractor refuses traversal and bombs instead of writing outside the sandbox.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import replace

import pytest

from analyzer.config import DEFAULT_CONFIG
from analyzer.ingest.archive import IngestError, ingest_zip
from analyzer.ingest.text import ingest_text


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_clean_zip_extracts_files():
    data = _zip_bytes({"SKILL.md": b"---\nname: x\n---\nhi", "scripts/run.py": b"print(1)"})
    with ingest_zip(data, DEFAULT_CONFIG) as bundle:
        files = {str(p) for p in bundle.iter_files()}
        assert "SKILL.md" in files
        assert "scripts/run.py" in files


def test_zip_slip_traversal_is_rejected(tmp_path):
    """An entry escaping the sandbox via ../ must not be written outside it."""
    sentinel = tmp_path / "escaped.txt"
    data = _zip_bytes({"../escaped.txt": b"pwned", "SKILL.md": b"ok"})
    with pytest.raises(IngestError):
        ingest_zip(data, DEFAULT_CONFIG)
    assert not sentinel.exists()


def test_absolute_path_entry_is_rejected():
    data = _zip_bytes({"/etc/evil": b"pwned"})
    with pytest.raises(IngestError):
        ingest_zip(data, DEFAULT_CONFIG)


def test_symlink_entry_is_skipped():
    """A symlink zip entry must never be materialized as a followable link."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 & 0xFFFF) << 16  # S_IFLNK
        zf.writestr(info, "/etc/passwd")
        zf.writestr("SKILL.md", "ok")
    with ingest_zip(buf.getvalue(), DEFAULT_CONFIG) as bundle:
        files = {str(p) for p in bundle.iter_files()}
        assert "link" not in files
        assert "SKILL.md" in files


def test_file_count_cap_is_enforced():
    cfg = replace(DEFAULT_CONFIG, max_file_count=3)
    data = _zip_bytes({f"f{i}.txt": b"x" for i in range(10)})
    with pytest.raises(IngestError):
        ingest_zip(data, cfg)


def test_total_size_cap_blocks_decompression_bomb():
    cfg = replace(DEFAULT_CONFIG, max_total_bytes=1024)
    data = _zip_bytes({"big.txt": b"A" * 100_000})  # highly compressible bomb
    with pytest.raises(IngestError):
        ingest_zip(data, cfg)


def test_text_ingest_writes_named_file():
    with ingest_text("hello", DEFAULT_CONFIG, declared_filename="CLAUDE.md") as bundle:
        assert bundle.source_mode == "text"
        assert bundle.primary_path is not None
        assert bundle.read_text(bundle.primary_path) == "hello"


def test_text_ingest_sanitizes_traversal_in_filename():
    """A declared filename with traversal must not place a file outside the sandbox."""
    with ingest_text("x", DEFAULT_CONFIG, declared_filename="../../etc/passwd") as bundle:
        # primary file lands inside the sandbox regardless of the hostile name
        assert bundle.primary_path is not None
        bundle.abs_path(bundle.primary_path)  # must not raise
