"""Static-rule scanning layer (§4.2).

Runs the YAML rule corpus over the relevant *surfaces* of a submission:
  - the primary artifact's full text -> ``body`` (instruction surface, full severity)
  - reference / other text files     -> ``reference`` (documentation, downgraded to Info)
  - script files                     -> ``script`` (secrets only; code is AST's job)
  - filenames + git metadata         -> ``body`` (sneaky injection vectors, treated as data)

Severity adjustment encodes two spec rules:
  - documents-vs-performs (§7): a pattern that merely appears in a reference/doc is Info.
  - always-on weighting (§4.3): a CLAUDE.md instruction is escalated one step.
"""

from __future__ import annotations

from analyzer.bundle import Bundle
from analyzer.config import AnalyzerConfig
from analyzer.discovery import Discovery
from analyzer.findings import make_finding
from analyzer.models import (
    ArtifactKind,
    ComponentType,
    Finding,
    Severity,
    SourceLayer,
    escalate,
)
from analyzer.parsing.frontmatter import Frontmatter
from analyzer.rules.engine import RuleEngine, RuleMatch, load_default_engine

# binary / non-text components we don't scan as text
_SKIP_SCAN = {ComponentType.ASSET}


def analyze_static(
    bundle: Bundle,
    discovery: Discovery,
    frontmatter: Frontmatter,
    config: AnalyzerConfig,
    engine: RuleEngine | None = None,
) -> list[Finding]:
    engine = engine or load_default_engine()
    kind = discovery.kind.value
    findings: list[Finding] = []
    primary = str(discovery.primary_path)

    # 1. primary artifact full text — instruction surface only if it's a markdown/text
    # artifact; if the "primary" is source code (e.g. a self-scan of the analyzer), it
    # is a script surface, so injection prose inside code (like our judge prompt) is not
    # mistaken for a performed instruction (documents-vs-performs).
    try:
        primary_text = bundle.read_text(discovery.primary_path)
    except (OSError, ValueError):
        primary_text = frontmatter.body
    primary_surface = "body" if discovery.primary_is_doc() else "script"
    findings += _scan(engine, primary_text, primary, primary_surface, kind, discovery.kind)

    # 2. other components
    for comp in discovery.components:
        if comp.path == primary or comp.type in _SKIP_SCAN:
            continue
        surface = _surface_for(comp.type)
        if surface is None:
            continue
        try:
            text = bundle.read_text(comp.path)
        except (OSError, ValueError):
            continue
        findings += _scan(engine, text, comp.path, surface, kind, discovery.kind)

    # 3. filenames — injection hidden in a path is still data to be flagged
    for comp in discovery.components:
        findings += _scan(engine, comp.path, comp.path, "body", kind, discovery.kind)

    # 4. git metadata (commit message / author / branch) — untrusted data
    for key, value in bundle.git_metadata.items():
        if value:
            findings += _scan(engine, value, f"git:{key}", "body", kind, discovery.kind)

    return findings


def _surface_for(ctype: ComponentType) -> str | None:
    if ctype is ComponentType.SCRIPT:
        return "script"
    if ctype in (ComponentType.REFERENCE, ComponentType.OTHER):
        return "reference"
    return None


def _scan(
    engine: RuleEngine,
    text: str,
    file: str,
    surface: str,
    kind: str,
    artifact_kind: ArtifactKind,
) -> list[Finding]:
    return [_to_finding(m, surface, artifact_kind) for m in engine.scan(text, file, surface, kind)]


def _to_finding(match: RuleMatch, surface: str, artifact_kind: ArtifactKind) -> Finding:
    rule = match.rule
    severity = rule.severity
    if surface == "reference" or match.negated:
        severity = Severity.INFO  # documents-vs-performs: reference doc or negated/forbidden statement
    elif artifact_kind is ArtifactKind.CLAUDE_MD and rule.escalate_for_claude_md:
        severity = escalate(severity)  # always-on context weighting

    return make_finding(
        rule_id=rule.id,
        category=rule.category,
        severity=severity,
        confidence=rule.confidence,
        file=match.file,
        line=match.line,
        evidence=match.evidence,
        risk=rule.description,
        remediation=rule.remediation,
        source_layer=SourceLayer.STATIC_RULES,
        language=rule.language,
    )
