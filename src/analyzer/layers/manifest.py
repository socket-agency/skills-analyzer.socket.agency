"""Per-profile manifest & standing-instruction analysis (§4.3).

This layer handles the *structural* vectors that aren't natural-language patterns:
  - skill / agents: frontmatter manifest vectors (broad tools, dynamic ``!`…```
    command injection, ``$ARGUMENTS`` in shell, ``model:`` / ``context:`` overrides,
    description hygiene & trigger hijacking, malformed frontmatter).
  - claude_md: ``@import`` poisoning (sensitive / out-of-tree / remote targets).

Profile isolation is structural: skill vectors only run for skill/agents kinds, so
they can never fire on a CLAUDE.md (which has no frontmatter manifest).
"""

from __future__ import annotations

import re2

from analyzer.config import AnalyzerConfig
from analyzer.discovery import Discovery
from analyzer.findings import make_finding
from analyzer.models import (
    ArtifactKind,
    Category,
    Confidence,
    Finding,
    ImportKind,
    ImportRef,
    Severity,
    SourceLayer,
)
from analyzer.parsing.frontmatter import Frontmatter

_DYNAMIC_CMD = re2.compile(r"!`[^`]+`")
_ARGUMENTS = re2.compile(r"\$(ARGUMENTS|\{ARGUMENTS\}|[1-9])")
_SHELL_INDICATOR = re2.compile(r"(?i)(```\s*(ba)?sh|!`|\bcurl\b|\bwget\b|\bbash\b|\bsh -c\b|\beval\b|\bsubprocess\b|\bos\.system\b)")
_BROAD_BASH = re2.compile(r"(?i)bash\s*\(\s*\*\s*\)")
_UNSCOPED_BASH = re2.compile(r"(?i)(^|[,\[\s])bash($|[,\]\s])")
_TRIGGER_HIJACK = re2.compile(
    r"(?i)(for (all|every|any) (task|request|prompt|query|conversation)|"
    r"always use this|use this (skill )?(for )?(everything|all|any))"
)
_SENSITIVE_IMPORT = re2.compile(r"(?i)(\.ssh|\.aws|\.config|\.netrc|\.npmrc|/etc/|id_rsa|\.env|credentials)")


def _loc(text: str, pattern_match_start: int) -> int:
    return text.count("\n", 0, pattern_match_start) + 1


def analyze_manifest(
    discovery: Discovery,
    frontmatter: Frontmatter,
    body: str,
    imports: list[ImportRef],
    config: AnalyzerConfig,
) -> list[Finding]:
    kind = discovery.kind
    primary = str(discovery.primary_path)

    if kind in (ArtifactKind.SKILL, ArtifactKind.AGENTS):
        if not discovery.primary_is_doc():
            return []  # a code file misrouted as primary (e.g. self-scan) — no manifest
        return _skill_manifest(primary, frontmatter, body)
    if kind is ArtifactKind.CLAUDE_MD:
        return _claude_md_imports(primary, imports)
    return []


def _skill_manifest(primary: str, fm: Frontmatter, body: str) -> list[Finding]:
    findings: list[Finding] = []
    raw_fm = fm.raw or ""

    # malformed / missing frontmatter is itself a finding for skills
    if fm.malformed:
        findings.append(
            make_finding(
                rule_id="manifest.malformed_frontmatter",
                category=Category.MANIFEST_VALIDATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                file=primary,
                line=1,
                evidence=raw_fm[:120] or "malformed frontmatter",
                risk="Frontmatter could not be parsed safely; the skill's declared scope is unknown.",
                remediation="Fix the YAML frontmatter so its tool grants and metadata are explicit.",
                source_layer=SourceLayer.MANIFEST,
            )
        )
    elif not fm.present:
        findings.append(
            make_finding(
                rule_id="manifest.missing_frontmatter",
                category=Category.MANIFEST_VALIDATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=primary,
                line=1,
                evidence="no frontmatter block",
                risk="A skill without frontmatter has no declared tool scope or description.",
                remediation="Add frontmatter with name, description and a scoped allowed-tools list.",
                source_layer=SourceLayer.MANIFEST,
            )
        )

    data = fm.data or {}

    findings.extend(_check_allowed_tools(primary, data))
    findings.extend(_check_dynamic_command(primary, raw_fm, body))
    findings.extend(_check_arguments(primary, raw_fm, body))
    findings.extend(_check_model_context(primary, data))
    findings.extend(_check_description(primary, data, fm))

    return findings


def _stringify_tools(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _check_allowed_tools(primary: str, data: dict) -> list[Finding]:
    if "allowed-tools" not in data:
        return []
    tools = _stringify_tools(data["allowed-tools"])
    broad = _BROAD_BASH.search(tools)
    unscoped = _UNSCOPED_BASH.search(tools)
    star = tools.strip() == "*" or ", *" in tools or tools.strip().startswith("*")
    if broad or unscoped or star:
        return [
            make_finding(
                rule_id="manifest.allowed_tools_broad",
                category=Category.EXCESSIVE_AGENCY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                file=primary,
                line=1,
                evidence=f"allowed-tools: {tools}",
                risk="A broad/unscoped Bash grant lets the skill run arbitrary shell commands silently.",
                remediation="Scope tool grants narrowly, e.g. Bash(git status:*) instead of Bash(*).",
                source_layer=SourceLayer.MANIFEST,
            )
        ]
    return []


def _check_dynamic_command(primary: str, raw_fm: str, body: str) -> list[Finding]:
    findings: list[Finding] = []
    for surface in (raw_fm, body):
        for m in _DYNAMIC_CMD.finditer(surface):
            findings.append(
                make_finding(
                    rule_id="manifest.dynamic_command",
                    category=Category.COMMAND_EXECUTION,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    file=primary,
                    line=_loc(surface, m.start()),
                    evidence=str(m.group(0)),
                    risk="A !`…` directive runs a shell command before/while the skill loads — silent code execution.",
                    remediation="Remove dynamic command injection; never execute shell from frontmatter or body.",
                    source_layer=SourceLayer.MANIFEST,
                )
            )
    return findings


def _check_arguments(primary: str, raw_fm: str, body: str) -> list[Finding]:
    combined = raw_fm + "\n" + body
    if not _ARGUMENTS.search(combined) or not _SHELL_INDICATOR.search(combined):
        return []
    m = _ARGUMENTS.search(combined)
    assert m is not None
    return [
        make_finding(
            rule_id="manifest.arguments_in_shell",
            category=Category.COMMAND_EXECUTION,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            file=primary,
            line=_loc(combined, m.start()),
            evidence=_line_of(combined, m.start()),
            risk="User-controlled $ARGUMENTS/$1 substituted into a shell command enables command injection.",
            remediation="Never interpolate $ARGUMENTS into shell; validate and pass arguments safely.",
            source_layer=SourceLayer.MANIFEST,
        )
    ]


def _check_model_context(primary: str, data: dict) -> list[Finding]:
    findings: list[Finding] = []
    if "model" in data:
        findings.append(
            make_finding(
                rule_id="manifest.model_override",
                category=Category.MANIFEST_VALIDATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=primary,
                line=1,
                evidence=f"model: {data['model']}",
                risk="A model override may downgrade execution to a weaker / less-aligned model.",
                remediation="Avoid pinning model; if required, justify and use an aligned model.",
                source_layer=SourceLayer.MANIFEST,
            )
        )
    if str(data.get("context", "")).strip().lower() == "fork":
        findings.append(
            make_finding(
                rule_id="manifest.context_fork",
                category=Category.EXCESSIVE_AGENCY,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=primary,
                line=1,
                evidence=f"context/agent: {data.get('context') or data.get('agent')}",
                risk="Forking a subagent can escape the user's review scope for spawned actions.",
                remediation="Review forked/subagent execution; ensure it remains within the user's oversight.",
                source_layer=SourceLayer.MANIFEST,
            )
        )
    if data.get("disable-model-invocation") and data.get("user-invocable") is False:
        findings.append(
            make_finding(
                rule_id="manifest.hidden_invocation",
                category=Category.MANIFEST_VALIDATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                file=primary,
                line=1,
                evidence="disable-model-invocation + user-invocable: false",
                risk="This combination can hide skill execution from the user.",
                remediation="Make invocation visible to the user.",
                source_layer=SourceLayer.MANIFEST,
            )
        )
    return findings


def _check_description(primary: str, data: dict, fm: Frontmatter) -> list[Finding]:
    findings: list[Finding] = []
    if fm.present and not fm.malformed and "description" not in data:
        findings.append(
            make_finding(
                rule_id="manifest.missing_description",
                category=Category.MANIFEST_VALIDATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=primary,
                line=1,
                evidence="no description",
                risk="A missing description hides what the skill does and when it triggers.",
                remediation="Add a clear, narrow description of the skill's purpose.",
                source_layer=SourceLayer.MANIFEST,
            )
        )
    desc = str(data.get("description", ""))
    if _TRIGGER_HIJACK.search(desc):
        findings.append(
            make_finding(
                rule_id="manifest.trigger_hijack",
                category=Category.TRIGGER_ABUSE,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                file=primary,
                line=1,
                evidence=f"description: {desc}",
                risk="An over-broad description engineered to match every prompt hijacks skill selection.",
                remediation="Scope the description to the specific task the skill handles.",
                source_layer=SourceLayer.MANIFEST,
            )
        )
    return findings


def _claude_md_imports(primary: str, imports: list[ImportRef]) -> list[Finding]:
    findings: list[Finding] = []
    for imp in imports:
        if imp.kind is ImportKind.IN_TREE:
            continue  # resolved in-tree imports are followed, not flagged here
        sensitive = bool(_SENSITIVE_IMPORT.search(imp.target))
        kind_word = "remote" if imp.kind is ImportKind.REMOTE else "out-of-tree"
        findings.append(
            make_finding(
                rule_id=f"manifest.import_{imp.kind.value}",
                category=Category.CONTEXT_POISONING,
                severity=Severity.HIGH,  # base medium escalated for always-on CLAUDE.md context
                confidence=Confidence.HIGH if sensitive else Confidence.MEDIUM,
                file=primary,
                line=1,
                evidence=imp.raw,
                risk=(
                    f"A {kind_word} @import pulls external content into always-on context "
                    "(indirect prompt injection / context poisoning)."
                    + (" The target is a sensitive path." if sensitive else "")
                ),
                remediation="Only import vetted in-tree files; never import sensitive paths or remote URLs.",
                source_layer=SourceLayer.MANIFEST,
            )
        )
    return findings


def _line_of(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    if end == -1:
        end = len(text)
    return text[start:end]
