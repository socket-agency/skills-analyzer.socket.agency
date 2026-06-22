"""Canonical report data model for the analyzer.

Everything the engine produces flows into a :class:`ScanReport`. All untrusted
evidence stored on findings is treated as inert data — the rendering layer is
responsible for escaping it (the engine never interprets it).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ArtifactKind(str, Enum):
    """The three artifact kinds v1 recognizes, each with its own analysis profile."""

    SKILL = "skill"
    AGENTS = "agents"
    CLAUDE_MD = "claude_md"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    CAUTION = "CAUTION"
    DO_NOT_INSTALL = "DO_NOT_INSTALL"


class Category(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_EXECUTION = "command_execution"
    DATA_EXFILTRATION = "data_exfiltration"
    EXCESSIVE_AGENCY = "excessive_agency"
    SECRET_EXPOSURE = "secret_exposure"
    SUPPLY_CHAIN = "supply_chain"
    CONTEXT_POISONING = "context_poisoning"
    OBFUSCATION = "obfuscation"
    TRIGGER_ABUSE = "trigger_abuse"
    TOOL_POISONING = "tool_poisoning"
    MANIFEST_VALIDATION = "manifest_validation"


class SourceLayer(str, Enum):
    STATIC_RULES = "static_rules"
    MANIFEST = "manifest"
    AST_PYTHON = "ast_python"
    AST_SHELL = "ast_shell"
    TAINT = "taint"
    OBFUSCATION = "obfuscation"
    SUPPLY_CHAIN = "supply_chain"
    JUDGE = "judge"


class ImportKind(str, Enum):
    """Classification of a CLAUDE.md ``@import`` target."""

    IN_TREE = "in_tree"
    OUT_OF_TREE = "out_of_tree"
    REMOTE = "remote"


class ComponentType(str, Enum):
    MANIFEST = "manifest"
    SCRIPT = "script"
    REFERENCE = "reference"
    ASSET = "asset"
    OTHER = "other"


# --- severity / confidence ranking helpers -------------------------------------------------

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


def severity_rank(severity: Severity) -> int:
    return _SEVERITY_RANK[severity]


def confidence_rank(confidence: Confidence) -> int:
    return _CONFIDENCE_RANK[confidence]


def escalate(severity: Severity) -> Severity:
    """Bump a severity one step (capped at Critical).

    Used by the CLAUDE.md profile: a standing instruction is always-on context,
    so the same text weighs one step higher than in an on-demand skill body.
    """
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = order.index(severity)
    return order[min(idx + 1, len(order) - 1)]


# --- report structures ---------------------------------------------------------------------


class Location(BaseModel):
    file: str
    line: int | None = None


class Finding(BaseModel):
    id: str
    category: Category
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: str
    risk: str
    remediation: str
    source_layer: SourceLayer
    language: str | None = None
    raised_by: str | None = None  # judge model id, for judge-layer findings


class Component(BaseModel):
    path: str
    type: ComponentType
    language: str | None = None
    executable: bool = False


class ImportRef(BaseModel):
    raw: str  # the literal @import token as written (untrusted)
    target: str  # normalized target path/url (untrusted)
    kind: ImportKind
    resolved: bool = False  # whether an in-tree target was found and followed


class ArtifactMeta(BaseModel):
    kind: ArtifactKind
    name: str | None = None
    scope: str | None = None  # e.g. project / user / nested, for CLAUDE.md


class ScanReport(BaseModel):
    artifact_meta: ArtifactMeta
    components: list[Component] = Field(default_factory=list)
    imports: list[ImportRef] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    score: int = 0
    verdict: Verdict = Verdict.CLEAN
    judges_used: list[str] = Field(default_factory=list)
    summary: str = ""
