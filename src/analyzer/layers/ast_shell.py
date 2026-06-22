"""Shell analysis (§4.4).

Combines ReDoS-safe re2 signature patterns with a best-effort ``bashlex`` parse to
catch download-pipe-to-shell, reverse shells, and rc-file / ssh / git-hook
persistence writes. Shell is never executed — only parsed and pattern-matched.
"""

from __future__ import annotations

from dataclasses import dataclass

import bashlex
import re2

from analyzer.config import AnalyzerConfig
from analyzer.findings import make_finding
from analyzer.models import Category, Confidence, Finding, Severity, SourceLayer

_DOWNLOADERS = {"curl", "wget", "fetch"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}


@dataclass
class _Sig:
    rule_id: str
    pattern: object
    severity: Severity
    risk: str


_SIGNATURES: list[_Sig] = [
    _Sig(
        "shell.reverse_socat",
        re2.compile(r"(?i)socat\b.{0,80}(tcp|tcp4|tcp6):.{0,80}exec"),
        Severity.CRITICAL,
        "socat reverse shell connecting out and exec'ing a shell.",
    ),
    _Sig(
        "shell.reverse_nc",
        re2.compile(r"(?i)\bnc\b.{0,30}\s-e\b"),
        Severity.CRITICAL,
        "netcat reverse shell (-e executes a program on connect).",
    ),
    _Sig(
        "shell.reverse_devtcp",
        re2.compile(r"(?i)(ba)?sh\b.{0,40}/dev/tcp/"),
        Severity.CRITICAL,
        "Bash /dev/tcp reverse shell.",
    ),
    _Sig(
        "shell.interactive_reverse",
        re2.compile(r"(?i)(ba|z)?sh\s+-i\b.{0,40}(>&|/dev/tcp|\|)"),
        Severity.CRITICAL,
        "Interactive shell redirected over a network connection.",
    ),
    _Sig(
        "shell.download_pipe_shell",
        re2.compile(r"(?i)(curl|wget|fetch)\b.{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b"),
        Severity.HIGH,
        "Remote payload piped directly into a shell (curl|bash).",
    ),
    _Sig(
        "shell.persistence_write",
        re2.compile(
            r"(?i)>>?\s*[~/]?[^\s]*(\.bashrc|\.zshrc|\.bash_profile|\.profile|\.ssh/|/\.git/hooks/)"
        ),
        Severity.HIGH,
        "Writes to a shell rc / ssh / git-hook file — establishes persistence.",
    ),
    _Sig(
        "shell.xattr_clear",
        re2.compile(r"(?i)xattr\s+-c\b"),
        Severity.MEDIUM,
        "Clears extended attributes (e.g. macOS quarantine) to evade gatekeeping.",
    ),
]


def _line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_shell_text(text: str, file: str, config: AnalyzerConfig) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for sig in _SIGNATURES:
        for m in sig.pattern.finditer(text):  # type: ignore[attr-defined]
            if sig.rule_id in seen:
                break
            seen.add(sig.rule_id)
            findings.append(
                make_finding(
                    rule_id=sig.rule_id,
                    category=Category.COMMAND_EXECUTION,
                    severity=sig.severity,
                    confidence=Confidence.HIGH,
                    file=file,
                    line=_line_at(text, m.start()),
                    evidence=str(m.group(0)),
                    risk=sig.risk,
                    remediation="Remove the command; never download-and-run or open reverse shells.",
                    source_layer=SourceLayer.AST_SHELL,
                )
            )

    if not any(s.rule_id == "shell.download_pipe_shell" for s in _SIGNATURES if s.rule_id in seen):
        findings.extend(_bashlex_pipe_to_shell(text, file))

    return findings


def _bashlex_pipe_to_shell(text: str, file: str) -> list[Finding]:
    """Best-effort: detect a downloader piped into a shell via the parse tree."""
    try:
        trees = bashlex.parse(text)
    except Exception:  # noqa: BLE001 — bashlex faces hostile/partial input; any parse failure is non-fatal
        return []

    findings: list[Finding] = []
    for tree in trees:
        commands = _pipeline_command_names(tree)
        for names in commands:
            if names and names[0] in _DOWNLOADERS and any(n in _SHELLS for n in names[1:]):
                findings.append(
                    make_finding(
                        rule_id="shell.download_pipe_shell",
                        category=Category.COMMAND_EXECUTION,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        file=file,
                        line=1,
                        evidence=" | ".join(names),
                        risk="Remote payload piped directly into a shell (curl|bash).",
                        remediation="Download to a file, review it, then run explicitly.",
                        source_layer=SourceLayer.AST_SHELL,
                    )
                )
                return findings
    return findings


def _pipeline_command_names(node: object) -> list[list[str]]:
    """Return, for each pipeline, the list of leading command words."""
    pipelines: list[list[str]] = []

    def first_word(cmd: object) -> str | None:
        parts = getattr(cmd, "parts", [])
        for part in parts:
            if getattr(part, "kind", None) == "word":
                return getattr(part, "word", None)
        return None

    def walk(n: object) -> None:
        kind = getattr(n, "kind", None)
        if kind == "pipeline":
            names: list[str] = []
            for part in getattr(n, "parts", []):
                if getattr(part, "kind", None) == "command":
                    w = first_word(part)
                    if w:
                        names.append(w)
            if names:
                pipelines.append(names)
        for part in getattr(n, "parts", []):
            walk(part)
        for part in getattr(n, "list", []) or []:
            walk(part)

    walk(node)
    return pipelines
