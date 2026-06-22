"""Obfuscation / evasion detection (§4.5).

Catches hidden-instruction tricks (zero-width chars, bidi / Trojan-Source
overrides, homoglyph script-mixing) and encoded payloads, which are decoded with
bounded recursion and re-scanned by the rule + shell layers so a base64-wrapped
reverse shell still surfaces.
"""

from __future__ import annotations

import unicodedata

from analyzer.bundle import Bundle
from analyzer.config import AnalyzerConfig
from analyzer.decode import find_and_decode
from analyzer.discovery import Discovery
from analyzer.findings import make_finding
from analyzer.layers.ast_shell import scan_shell_text
from analyzer.models import (
    Category,
    ComponentType,
    Confidence,
    Finding,
    Severity,
    SourceLayer,
)
from analyzer.rules.engine import RuleEngine, load_default_engine

_ZERO_WIDTH = set("​‌‍﻿⁠")
_BIDI = set("‪‫‬‭‮⁦⁧⁨⁩")


def _line_of_char(text: str, predicate_chars: set[str]) -> int:
    for i, ch in enumerate(text):
        if ch in predicate_chars:
            return text.count("\n", 0, i) + 1
    return 1


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    if name.startswith("CYRILLIC"):
        return "cyrillic"
    if name.startswith("LATIN"):
        return "latin"
    if name.startswith("GREEK"):
        return "greek"
    return "other"


def _has_mixed_script(token: str) -> bool:
    scripts = {s for ch in token if (s := _script_of(ch)) in ("latin", "cyrillic", "greek")}
    return len(scripts) > 1


def scan_obfuscation_text(
    text: str,
    file: str,
    kind: str,
    engine: RuleEngine,
    config: AnalyzerConfig,
    surface: str = "body",
) -> list[Finding]:
    findings: list[Finding] = []

    # Text-anomaly checks apply to instruction surfaces only. On a reference/doc they
    # are downgraded to Info (documents-vs-performs); on source code they're skipped —
    # a multilingual detector's own source legitimately contains these characters.
    if surface in ("body", "reference"):
        findings += _char_anomalies(text, file, surface)

    findings.extend(_decode_and_rescan(text, file, kind, engine, config))
    return findings


def _char_anomalies(text: str, file: str, surface: str) -> list[Finding]:
    findings: list[Finding] = []
    anomaly_sev = Severity.INFO if surface == "reference" else None  # None => native severity

    if any(ch in _ZERO_WIDTH for ch in text):
        findings.append(
            make_finding(
                rule_id="obfuscation.zero_width",
                category=Category.OBFUSCATION,
                severity=anomaly_sev or Severity.MEDIUM,
                confidence=Confidence.HIGH,
                file=file,
                line=_line_of_char(text, _ZERO_WIDTH),
                evidence="zero-width / invisible characters present",
                risk="Zero-width characters can hide instructions from human reviewers.",
                remediation="Remove invisible characters; keep instruction text plain.",
                source_layer=SourceLayer.OBFUSCATION,
            )
        )

    if any(ch in _BIDI for ch in text):
        findings.append(
            make_finding(
                rule_id="obfuscation.bidi_override",
                category=Category.OBFUSCATION,
                severity=anomaly_sev or Severity.HIGH,
                confidence=Confidence.HIGH,
                file=file,
                line=_line_of_char(text, _BIDI),
                evidence="bidirectional control characters present",
                risk="Bidi/Trojan-Source overrides make displayed text differ from what is parsed.",
                remediation="Remove bidirectional control characters.",
                source_layer=SourceLayer.OBFUSCATION,
            )
        )

    for token in text.split():
        if _has_mixed_script(token):
            findings.append(
                make_finding(
                    rule_id="obfuscation.script_mixing",
                    category=Category.OBFUSCATION,
                    severity=anomaly_sev or Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    file=file,
                    line=1,
                    evidence=f"mixed-script token: {token}",
                    risk="Mixed Latin/Cyrillic homoglyphs can spoof trusted words.",
                    remediation="Use a single script per token; avoid homoglyph spoofing.",
                    source_layer=SourceLayer.OBFUSCATION,
                )
            )
            break  # one finding per surface is enough

    return findings


def _decode_and_rescan(
    text: str, file: str, kind: str, engine: RuleEngine, config: AnalyzerConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for blob in find_and_decode(text, config):
        findings.append(
            make_finding(
                rule_id="obfuscation.encoded_payload",
                category=Category.OBFUSCATION,
                severity=Severity.INFO,  # presence only; dangerous decoded content is flagged by the rescan
                confidence=Confidence.MEDIUM,
                file=file,
                line=1,
                evidence=f"{blob.encoding} payload: {blob.source_snippet}",
                risk="An encoded payload hides its content from static review.",
                remediation="Do not ship encoded executable payloads in an artifact.",
                source_layer=SourceLayer.OBFUSCATION,
            )
        )
        # re-scan the decoded content so a wrapped reverse shell / injection still fires
        for f in scan_shell_text(blob.text, file, config):
            findings.append(_retag_decoded(f, blob.encoding))
        for m in engine.scan(blob.text, file, "body", kind):
            findings.append(
                make_finding(
                    rule_id=f"{m.rule.id}.decoded",
                    category=m.rule.category,
                    severity=m.rule.severity,
                    confidence=m.rule.confidence,
                    file=file,
                    line=1,
                    evidence=f"({blob.encoding}-decoded) {m.evidence}",
                    risk=m.rule.description,
                    remediation=m.rule.remediation,
                    source_layer=SourceLayer.OBFUSCATION,
                    language=m.rule.language,
                )
            )
    return findings


def _retag_decoded(finding: Finding, encoding: str) -> Finding:
    return finding.model_copy(
        update={
            "id": f"{finding.id}.decoded",
            "evidence": f"({encoding}-decoded) {finding.evidence}",
            "source_layer": SourceLayer.OBFUSCATION,
        }
    )


def analyze_obfuscation(
    bundle: Bundle,
    discovery: Discovery,
    config: AnalyzerConfig,
    engine: RuleEngine | None = None,
) -> list[Finding]:
    engine = engine or load_default_engine()
    kind = discovery.kind.value
    findings: list[Finding] = []

    primary = str(discovery.primary_path)
    primary_surface = "body" if discovery.primary_is_doc() else "script"
    try:
        findings += scan_obfuscation_text(
            bundle.read_text(discovery.primary_path), primary, kind, engine, config, primary_surface
        )
    except (OSError, ValueError):
        pass

    for comp in discovery.components:
        if comp.path == primary or comp.type is ComponentType.ASSET:
            continue
        surface = "script" if comp.type is ComponentType.SCRIPT else "reference"
        try:
            text = bundle.read_text(comp.path)
        except (OSError, ValueError):
            continue
        findings += scan_obfuscation_text(text, comp.path, kind, engine, config, surface)

    return findings
