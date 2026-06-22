"""The engine entry point: ``analyze(bundle, config) -> ScanReport``.

A pure function that runs every analysis layer over an ingested bundle, merges
findings, and scores a verdict. The judge panel is **additive-only** — its findings
are appended, never used to clear deterministic findings or lower the verdict.

The analyzer NEVER executes submitted content; all layers are static.
"""

from __future__ import annotations

import random
from collections.abc import Sequence

from analyzer.bundle import Bundle
from analyzer.config import DEFAULT_CONFIG, AnalyzerConfig
from analyzer.discovery import discover
from analyzer.judges.panel import Judge, run_panel
from analyzer.layers import ast_python, ast_shell, manifest, obfuscation, static_rules, supply_chain
from analyzer.models import ArtifactKind, ArtifactMeta, Finding, ScanReport, Severity
from analyzer.parsing.frontmatter import parse_frontmatter
from analyzer.parsing.imports import resolve_imports
from analyzer.scoring import decide_verdict, dedupe, score_findings


def analyze(
    bundle: Bundle,
    config: AnalyzerConfig = DEFAULT_CONFIG,
    *,
    judges: Sequence[Judge] | None = None,
    rng: random.Random | None = None,
    osv_query: supply_chain.OsvQuery = supply_chain.query_osv,
) -> ScanReport:
    discovery = discover(bundle, config)
    primary = discovery.primary_path

    try:
        primary_text = bundle.read_text(primary)
    except (OSError, ValueError):
        primary_text = ""
    frontmatter = parse_frontmatter(primary_text, config)

    imports = (
        resolve_imports(bundle, primary, config)
        if discovery.kind is ArtifactKind.CLAUDE_MD
        else []
    )

    findings: list[Finding] = []
    findings += static_rules.analyze_static(bundle, discovery, frontmatter, config)
    findings += manifest.analyze_manifest(discovery, frontmatter, frontmatter.body, imports, config)
    findings += _scan_scripts(bundle, discovery, config)
    findings += obfuscation.analyze_obfuscation(bundle, discovery, config)
    findings += supply_chain.analyze_supply_chain(bundle, discovery, config, osv_query=osv_query)

    # judge panel — additive only
    panel = run_panel(primary_text, config, judges=judges, rng=rng, default_file=str(primary))
    findings += panel.findings

    findings = dedupe(findings)
    score = score_findings(findings)
    verdict = decide_verdict(findings)

    meta = ArtifactMeta(
        kind=discovery.kind,
        name=_artifact_name(frontmatter, primary),
        scope=discovery.scope,
    )
    return ScanReport(
        artifact_meta=meta,
        components=discovery.components,
        imports=imports,
        findings=findings,
        score=score,
        verdict=verdict,
        judges_used=panel.judges_used,
        summary=_summarize(verdict, findings),
    )


def _scan_scripts(bundle: Bundle, discovery, config: AnalyzerConfig) -> list[Finding]:
    findings: list[Finding] = []
    for comp in discovery.components:
        if not comp.executable:
            continue
        try:
            text = bundle.read_text(comp.path)
        except (OSError, ValueError):
            continue
        if comp.language == "python":
            findings += ast_python.scan_python_text(text, comp.path, config)
        elif comp.language == "shell":
            findings += ast_shell.scan_shell_text(text, comp.path, config)
    return findings


def _artifact_name(frontmatter, primary) -> str:
    if frontmatter.data and frontmatter.data.get("name"):
        return str(frontmatter.data["name"])
    return primary.name if hasattr(primary, "name") else str(primary)


def _summarize(verdict, findings: list[Finding]) -> str:
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] += 1
    return (
        f"{verdict.value}: {len(findings)} findings "
        f"({counts[Severity.CRITICAL]} critical, {counts[Severity.HIGH]} high, "
        f"{counts[Severity.MEDIUM]} medium)"
    )
