"""The tool must pass its own scan (§7, §11): scanning analyzer/ returns CLEAN.

This proves documents-vs-performs — the analyzer's rule corpus and detector source
*contain* malicious patterns as data without being flagged for performing them.
"""

from __future__ import annotations

from pathlib import Path

from analyzer.analyze import analyze
from analyzer.config import DEFAULT_CONFIG
from analyzer.ingest.directory import ingest_directory
from analyzer.models import Severity, Verdict

_ANALYZER_SRC = Path(__file__).resolve().parents[1] / "src" / "analyzer"


def _no_osv(deps, config):
    return {}


def test_self_scan_is_clean():
    bundle = ingest_directory(_ANALYZER_SRC)
    report = analyze(bundle, DEFAULT_CONFIG, osv_query=_no_osv)
    offenders = [f for f in report.findings if f.severity is not Severity.INFO]
    assert report.verdict is Verdict.CLEAN, f"self-scan not clean: {[f.id for f in offenders]}"
    assert offenders == []
