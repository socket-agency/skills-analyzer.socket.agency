"""Scoring tests (M6, §4.8): dedupe/merge + verdict floor."""

from __future__ import annotations

from analyzer.findings import make_finding
from analyzer.models import Category, Confidence, Severity, SourceLayer, Verdict
from analyzer.scoring import decide_verdict, dedupe, score_findings


def _f(severity, confidence=Confidence.HIGH, file="a.md", line=1, category=Category.COMMAND_EXECUTION, layer=SourceLayer.STATIC_RULES):
    return make_finding(
        rule_id=f"r.{severity.value}",
        category=category,
        severity=severity,
        confidence=confidence,
        file=file,
        line=line,
        evidence="e",
        risk="r",
        remediation="rem",
        source_layer=layer,
    )


def test_dedupe_merges_same_location_category_keeping_highest():
    findings = [
        _f(Severity.LOW, layer=SourceLayer.STATIC_RULES),
        _f(Severity.CRITICAL, layer=SourceLayer.AST_PYTHON),
    ]
    merged = dedupe(findings)
    assert len(merged) == 1
    assert merged[0].severity is Severity.CRITICAL


def test_dedupe_keeps_distinct_categories():
    findings = [
        _f(Severity.HIGH, category=Category.COMMAND_EXECUTION),
        _f(Severity.HIGH, category=Category.DATA_EXFILTRATION),
    ]
    assert len(dedupe(findings)) == 2


def test_verdict_floor_critical_medium_is_do_not_install():
    assert decide_verdict([_f(Severity.CRITICAL, Confidence.MEDIUM)]) is Verdict.DO_NOT_INSTALL


def test_critical_low_confidence_is_only_caution():
    assert decide_verdict([_f(Severity.CRITICAL, Confidence.LOW)]) is Verdict.CAUTION


def test_high_is_caution():
    assert decide_verdict([_f(Severity.HIGH, Confidence.HIGH)]) is Verdict.CAUTION


def test_only_info_low_is_clean():
    assert decide_verdict([_f(Severity.LOW), _f(Severity.INFO)]) is Verdict.CLEAN


def test_empty_is_clean():
    assert decide_verdict([]) is Verdict.CLEAN


def test_score_increases_with_severity():
    low = score_findings([_f(Severity.LOW)])
    crit = score_findings([_f(Severity.CRITICAL)])
    assert 0 <= low < crit <= 100
