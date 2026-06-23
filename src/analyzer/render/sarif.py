"""SARIF 2.1.0 serialization (§8) for GitHub code scanning / CI gating.

Evidence text is carried as inert data; SARIF consumers render it as plain text.
"""

from __future__ import annotations

from analyzer import __version__
from analyzer.models import Finding, ScanReport, Severity

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _rule_id(finding: Finding) -> str:
    return finding.id.split("@", 1)[0]


def _result(finding: Finding) -> dict:
    region: dict[str, int] = {}
    if finding.location.line is not None:
        region["startLine"] = finding.location.line
    return {
        "ruleId": _rule_id(finding),
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{finding.risk} (evidence: {finding.evidence})"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.file},
                    "region": region or {"startLine": 1},
                }
            }
        ],
        "properties": {
            "category": finding.category.value,
            "confidence": finding.confidence.value,
            "severity": finding.severity.value,
            "sourceLayer": finding.source_layer.value,
            "raisedBy": finding.raised_by,
            "language": finding.language,
        },
    }


def _rules(findings: list[Finding]) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in findings:
        rid = _rule_id(f)
        if rid not in seen:
            seen[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.risk},
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
            }
    return list(seen.values())


def to_sarif(report: ScanReport) -> dict:
    findings = report.findings
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "skill-analyzer",
                        "informationUri": "https://github.com/socket-agency/skills-analyzer.socket.agency",
                        "version": __version__,
                        "rules": _rules(findings),
                    }
                },
                "results": [_result(f) for f in findings],
                "properties": {
                    "verdict": report.verdict.value,
                    "score": report.score,
                    "artifactKind": report.artifact_meta.kind.value,
                    "judgesUsed": report.judges_used,
                },
            }
        ],
    }
