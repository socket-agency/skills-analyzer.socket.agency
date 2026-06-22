"""SARIF 2.1.0 rendering tests (M6, §8)."""

from __future__ import annotations

from analyzer.findings import make_finding
from analyzer.models import (
    ArtifactKind,
    ArtifactMeta,
    Category,
    Confidence,
    ScanReport,
    Severity,
    SourceLayer,
    Verdict,
)
from analyzer.render.sarif import to_sarif


def _report():
    findings = [
        make_finding(
            rule_id="ast.python.os_system",
            category=Category.COMMAND_EXECUTION,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file="scripts/run.py",
            line=3,
            evidence="os.system(...)",
            risk="runs a shell command",
            remediation="don't",
            source_layer=SourceLayer.AST_PYTHON,
        ),
        make_finding(
            rule_id="manifest.model_override",
            category=Category.MANIFEST_VALIDATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            file="SKILL.md",
            line=1,
            evidence="model: x",
            risk="override",
            remediation="avoid",
            source_layer=SourceLayer.MANIFEST,
        ),
    ]
    return ScanReport(
        artifact_meta=ArtifactMeta(kind=ArtifactKind.SKILL, name="x"),
        findings=findings,
        verdict=Verdict.DO_NOT_INSTALL,
    )


def test_sarif_top_level_shape():
    s = to_sarif(_report())
    assert s["version"] == "2.1.0"
    assert "$schema" in s
    assert len(s["runs"]) == 1
    assert s["runs"][0]["tool"]["driver"]["name"] == "skill-analyzer"


def test_sarif_results_have_required_fields():
    s = to_sarif(_report())
    results = s["runs"][0]["results"]
    assert len(results) == 2
    for r in results:
        assert "ruleId" in r
        assert r["level"] in ("error", "warning", "note")
        assert r["message"]["text"]
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1


def test_sarif_level_mapping():
    s = to_sarif(_report())
    by_rule = {r["ruleId"]: r["level"] for r in s["runs"][0]["results"]}
    assert by_rule["ast.python.os_system"] == "error"  # critical -> error
    assert by_rule["manifest.model_override"] == "warning"  # medium -> warning


def test_sarif_declares_rules():
    s = to_sarif(_report())
    rule_ids = {r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]}
    assert "ast.python.os_system" in rule_ids
