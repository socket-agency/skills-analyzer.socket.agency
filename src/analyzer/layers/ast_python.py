"""Python AST analysis + simple taint tracking (§4.4).

We parse with :mod:`ast` and inspect the tree — the analyzer **never executes**
submitted code. We flag dangerous sinks (command execution, dynamic eval) and
detect the env/secret/file -> network taint flow that signals data exfiltration.
"""

from __future__ import annotations

import ast

from analyzer.config import AnalyzerConfig
from analyzer.findings import make_finding
from analyzer.models import Category, Confidence, Finding, Severity, SourceLayer

# Module-qualified network calls (requests.post, httpx.get, urllib.request.urlopen…).
_NETWORK_PREFIXES = ("requests.", "httpx.", "aiohttp.", "urllib.")
# Unambiguous network attrs — generic verbs like get/post are NOT here because they
# collide with dict.get etc.; those are only sinks when on a network module prefix.
_NETWORK_ATTRS = {"urlopen", "sendall"}


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _has_shell_true(call: ast.Call) -> bool:
    return any(
        kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
        for kw in call.keywords
    )


def scan_python_text(source: str, file: str, config: AnalyzerConfig) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []  # unparseable input must never crash the scanner

    findings: list[Finding] = []
    has_env_source = False
    has_network_sink = False
    network_line = 1

    for node in ast.walk(tree):
        # env-harvest source: os.environ / os.getenv. We intentionally do NOT treat
        # generic file reads as taint sources — that yields false positives on benign
        # read-then-network code (false positives are the main risk per the spec).
        if isinstance(node, ast.Attribute) and node.attr == "environ":
            has_env_source = True
        if isinstance(node, ast.Call):
            name = _dotted(node.func) or ""
            attr = name.rsplit(".", 1)[-1]

            if name in ("os.getenv", "os.environ.get"):
                has_env_source = True

            if name.startswith(_NETWORK_PREFIXES) or attr in _NETWORK_ATTRS or "socket" in name:
                has_network_sink = True
                network_line = node.lineno

            findings.extend(_check_dangerous_call(node, name, file))

    if has_env_source and has_network_sink:
        findings.append(
            make_finding(
                rule_id="taint.source_to_network",
                category=Category.DATA_EXFILTRATION,
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                file=file,
                line=network_line,
                evidence="environment data flows to a network sink",
                risk="Environment variables are read and sent to a network endpoint — data exfiltration.",
                remediation="Do not transmit environment/secret data to external endpoints.",
                source_layer=SourceLayer.TAINT,
            )
        )

    return findings


def _check_dangerous_call(call: ast.Call, name: str, file: str) -> list[Finding]:
    line = call.lineno

    if name == "os.system" or name == "os.popen":
        return [_cmd(name, file, line, Severity.HIGH, "runs an arbitrary shell command")]
    if name.startswith("subprocess.") and _has_shell_true(call):
        return [_cmd(name, file, line, Severity.HIGH, "spawns a shell (shell=True) — command injection risk")]
    if name in ("eval", "exec"):
        return [_cmd(name, file, line, Severity.HIGH, "dynamically executes code from a string")]
    if name in ("compile", "__import__"):
        return [_cmd(name, file, line, Severity.MEDIUM, "performs dynamic code import/compilation")]
    return []


def _cmd(name: str, file: str, line: int, severity: Severity, why: str) -> Finding:
    return make_finding(
        rule_id=f"ast.python.{name.replace('.', '_')}",
        category=Category.COMMAND_EXECUTION,
        severity=severity,
        confidence=Confidence.HIGH,
        file=file,
        line=line,
        evidence=f"{name}(...)",
        risk=f"`{name}` {why}.",
        remediation="Avoid dynamic execution; use safe, argument-list APIs without a shell.",
        source_layer=SourceLayer.AST_PYTHON,
    )
