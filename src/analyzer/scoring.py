"""Finding dedupe/merge, numeric score, and verdict decision (§4.8).

Verdict floor (non-negotiable): any Critical at confidence >= Medium ⇒ DO_NOT_INSTALL.
"""

from __future__ import annotations

from analyzer.models import (
    Confidence,
    Finding,
    Severity,
    Verdict,
    confidence_rank,
    severity_rank,
)

_SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
_CONFIDENCE_FACTOR: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings sharing (file, line, category); keep the strongest one."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.location.file, f.location.line, f.category)
        current = best.get(key)
        if current is None or _rank(f) > _rank(current):
            best[key] = f
    return list(best.values())


def _rank(f: Finding) -> tuple[int, int]:
    return severity_rank(f.severity), confidence_rank(f.confidence)


def score_findings(findings: list[Finding]) -> int:
    total = 0.0
    for f in findings:
        total += _SEVERITY_WEIGHT[f.severity] * _CONFIDENCE_FACTOR[f.confidence]
    return min(100, int(total))


def decide_verdict(findings: list[Finding]) -> Verdict:
    medium = confidence_rank(Confidence.MEDIUM)
    for f in findings:
        if f.severity is Severity.CRITICAL and confidence_rank(f.confidence) >= medium:
            return Verdict.DO_NOT_INSTALL  # verdict floor
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            return Verdict.CAUTION
    return Verdict.CLEAN
