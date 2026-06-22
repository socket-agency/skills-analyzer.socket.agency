"""Helpers for constructing :class:`Finding` objects with stable ids.

A finding id is deterministic for a given (rule, location) so the dedupe step in
scoring can merge the same issue surfaced by multiple layers.
"""

from __future__ import annotations

from analyzer.models import (
    Category,
    Confidence,
    Finding,
    Location,
    Severity,
    SourceLayer,
)

_EVIDENCE_MAX = 240


def clip_evidence(text: str) -> str:
    """Bound evidence length. Rendering layer is responsible for escaping it."""
    snippet = text.strip()
    if len(snippet) > _EVIDENCE_MAX:
        snippet = snippet[:_EVIDENCE_MAX] + "…"
    return snippet


def make_finding(
    *,
    rule_id: str,
    category: Category,
    severity: Severity,
    confidence: Confidence,
    file: str,
    line: int | None,
    evidence: str,
    risk: str,
    remediation: str,
    source_layer: SourceLayer,
    language: str | None = None,
    raised_by: str | None = None,
) -> Finding:
    loc = f"{file}:{line}" if line is not None else file
    return Finding(
        id=f"{rule_id}@{loc}",
        category=category,
        severity=severity,
        confidence=confidence,
        location=Location(file=file, line=line),
        evidence=clip_evidence(evidence),
        risk=risk,
        remediation=remediation,
        source_layer=source_layer,
        language=language,
        raised_by=raised_by,
    )
