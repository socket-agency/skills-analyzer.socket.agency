"""Web-agnostic static security analyzer for AI agent instruction artifacts.

Analyzes ``SKILL.md``, ``AGENTS.md`` and ``CLAUDE.md`` for prompt injection,
command execution, data exfiltration, excessive permissions, obfuscation and
supply-chain risk.

Hard invariant: this package **never executes** submitted content. All analysis
is static. The public entry point is :func:`analyzer.analyze.analyze`.
"""

__version__ = "0.1.0"
